/**
 * EDGE LICENSE CENTER by AMIRBTC (@EDGE_LicenceBot)
 * Cloudflare Worker — Path B-1 Primary Backend (D1 + R2 + Cron + Android Keystore PoP)
 *
 * Dual-mode compatibility:
 * - When `env.DB` (Cloudflare D1) is bound: runs full Path B-1 serverless backend (Mini App API,
 *   @EDGE_LicenceBot webhook, RBAC Admin API, Android ECDSA/RSA validation, Polygon verifier, R2 backups, Cron).
 * - When `env.DB` is unbound: preserves Phase 1 stateless HMAC-signed Android proxy behavior (`ORIGIN_API_URL`).
 */

import {
  activateDeviceWithProofD1,
  issueDeviceChallengeD1,
  updateLicenseStatusD1,
  validateAndroidLicenseD1,
} from './androidLicense';
import {
  canonicalizeJson,
  randomHex,
  sha256Hex,
  verifyTelegramInitDataWebCrypto,
} from './crypto';
import { runDailyAuditD1, checkAndRunMissedCronCatchUp } from './cronJobs';
import { DOMAIN_CONSTANTS, type D1Database, type WorkerEnv } from './d1Types';
import {
  claimSingleUseKey,
  createOrderD1,
  DomainError,
  ensureSuperAdminBootstrap,
  formatMicroUsdc,
  recordAuditLog,
  recordSecurityEvent,
  submitTransactionHashD1,
  upsertUserFromTelegram,
  verifyPaymentOnChainD1,
  type D1AdminRow,
  type D1OrderRow,
  type D1PaymentRow,
  type D1PlanRow,
  type D1UserRow,
} from './ordersAndPayments';
import {
  deriveWorkerSessionSigningKey,
  getEffectivePermissions,
  hasAdminPermission,
  signWorkerSessionToken,
  verifyWorkerSessionToken,
  type AdminPermission,
  type AdminRole,
} from './rbac';
import { handleTelegramWebhookWorker } from './telegramBot';

const SECURITY_HEADERS: Record<string, string> = {
  'Content-Type': 'application/json; charset=utf-8',
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
};

const ipRateBuckets = new Map<string, number[]>();

export function resetWorkerRateLimiterForTests(): void {
  ipRateBuckets.clear();
}

function checkEdgeRateLimit(
  ip: string,
  maxPerMinute: number,
  nowMs = Date.now()
): { allowed: boolean; retryAfterSec: number } {
  const windowMs = 60_000;
  const cutoff = nowMs - windowMs;
  let stamps = ipRateBuckets.get(ip);
  if (!stamps) {
    stamps = [];
    ipRateBuckets.set(ip, stamps);
  }
  while (stamps.length > 0 && stamps[0] <= cutoff) {
    stamps.shift();
  }
  if (stamps.length >= maxPerMinute) {
    const oldest = stamps[0] ?? nowMs;
    return {
      allowed: false,
      retryAfterSec: Math.max(1, Math.ceil((oldest + windowMs - nowMs) / 1000)),
    };
  }
  stamps.push(nowMs);
  return { allowed: true, retryAfterSec: 0 };
}

async function computeHmacHex(secret: string, message: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sigBuf = await crypto.subtle.sign('HMAC', key, enc.encode(message));
  return Array.from(new Uint8Array(sigBuf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function jsonResponse(body: unknown, status = 200, extraHeaders: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...SECURITY_HEADERS, ...extraHeaders },
  });
}

function getClientIp(request: Request): string {
  return (
    request.headers.get('CF-Connecting-IP') ??
    request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() ??
    'unknown'
  );
}

function parseExtraPermissions(admin: D1AdminRow | null | undefined): string[] {
  if (!admin?.permissions_json) return [];
  try {
    const parsed = JSON.parse(admin.permissions_json);
    return Array.isArray(parsed) ? parsed.filter((x): x is string => typeof x === 'string') : [];
  } catch {
    return [];
  }
}

async function handleLegacyProxyFetch(
  request: Request,
  env: WorkerEnv,
  fetchImpl: typeof fetch
): Promise<Response> {
  const url = new URL(request.url);

  if (request.method === 'GET' && url.pathname === '/v1/health') {
    return jsonResponse({
      ok: true,
      service: 'edge-license-android-gateway',
      phase: env.GATEWAY_PHASE ?? 'PHASE_1_HARDENED',
      role: 'stateless_android_proxy_only',
    });
  }

  if (request.method === 'POST' && url.pathname === '/v1/license/validate') {
    if (!env.ORIGIN_API_URL || !env.GATEWAY_SHARED_SECRET) {
      return jsonResponse({ valid: false, error: 'GATEWAY_ORIGIN_NOT_CONFIGURED' }, 503);
    }

    const clientIp = getClientIp(request);
    const maxPerMin = Number(env.RATE_LIMIT_MAX_PER_MIN ?? 60);
    const rate = checkEdgeRateLimit(clientIp, Number.isFinite(maxPerMin) ? maxPerMin : 60);
    if (!rate.allowed) {
      return jsonResponse(
        { error: 'RATE_LIMIT_EXCEEDED', retryAfterSeconds: rate.retryAfterSec },
        429,
        { 'Retry-After': String(rate.retryAfterSec) }
      );
    }

    const rawBody = await request.text();
    if (rawBody.length > 4096) {
      return jsonResponse({ error: 'PAYLOAD_TOO_LARGE' }, 413);
    }

    const timestamp = String(Math.floor(Date.now() / 1000));
    const signature = await computeHmacHex(env.GATEWAY_SHARED_SECRET, `${timestamp}.${rawBody}`);
    const originEndpoint = `${env.ORIGIN_API_URL.replace(/\/$/, '')}/api/v1/gateway/validate`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8000);

    try {
      const upstreamResponse = await fetchImpl(originEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Edge-Gateway-Secret': env.GATEWAY_SHARED_SECRET,
          'X-Edge-Timestamp': timestamp,
          'X-Edge-Signature': signature,
          'X-Forwarded-Client-IP': clientIp,
        },
        body: rawBody,
        signal: controller.signal,
      });

      const responseBody = await upstreamResponse.text();
      return new Response(responseBody, {
        status: upstreamResponse.status,
        headers: SECURITY_HEADERS,
      });
    } catch {
      return jsonResponse({ valid: false, error: 'UPSTREAM_GATEWAY_UNAVAILABLE' }, 502);
    } finally {
      clearTimeout(timer);
    }
  }

  return jsonResponse({ error: 'ROUTE_NOT_FOUND' }, 404);
}

interface AuthContext {
  user: D1UserRow;
  admin: D1AdminRow | null;
  authMode: 'bearer_session' | 'telegram_init_data' | 'phase0_preview';
}

async function authenticateWorkerRequest(
  request: Request,
  db: D1Database,
  env: WorkerEnv,
  clientIp: string
): Promise<{ ok: true; ctx: AuthContext } | { ok: false; response: Response }> {
  const authHeader = request.headers.get('Authorization');
  if (authHeader && authHeader.startsWith('Bearer ')) {
    try {
      const signingKey = await deriveWorkerSessionSigningKey(env.SESSION_SECRET, env.TELEGRAM_BOT_TOKEN);
      const tokenPayload = await verifyWorkerSessionToken(authHeader.slice(7), signingKey);
      const user = await db
        .prepare(`SELECT * FROM users WHERE telegram_id = ?`)
        .bind(tokenPayload.sub)
        .first<D1UserRow>();
      if (!user || user.id !== tokenPayload.uid) {
        return { ok: false, response: jsonResponse({ error: 'SESSION_USER_NOT_FOUND' }, 401) };
      }
      if (user.status !== 'active') {
        return {
          ok: false,
          response: jsonResponse({ error: 'ACCOUNT_RESTRICTED', status: user.status }, 403),
        };
      }
      const admin = await db
        .prepare(`SELECT * FROM admins WHERE telegram_id = ? AND is_active = 1`)
        .bind(user.telegram_id)
        .first<D1AdminRow>();
      return {
        ok: true,
        ctx: { user, admin: admin ?? null, authMode: 'bearer_session' },
      };
    } catch (err) {
      await recordAuditLog(db, {
        actorType: 'system',
        actorId: 'auth_guard',
        action: 'SESSION_TOKEN_INVALID',
        entityType: 'session',
        severity: 'warning',
        metadata: { reason: err instanceof Error ? err.message : 'INVALID_TOKEN' },
        ipAddress: clientIp,
      });
      return { ok: false, response: jsonResponse({ error: 'INVALID_SESSION_TOKEN' }, 401) };
    }
  }

  const initData = request.headers.get('X-Telegram-Init-Data');
  if (initData) {
    try {
      const verified = await verifyTelegramInitDataWebCrypto(initData, env.TELEGRAM_BOT_TOKEN ?? '', {
        maxAgeSeconds: Number(env.TELEGRAM_INIT_DATA_MAX_AGE_SECONDS ?? 300),
      });
      const user = await upsertUserFromTelegram(db, {
        telegramId: String(verified.user.id),
        username: verified.user.username ?? null,
        firstName: verified.user.first_name,
        lastName: verified.user.last_name ?? null,
        languageCode: verified.user.language_code ?? 'fa',
      });
      if (user.status !== 'active') {
        return {
          ok: false,
          response: jsonResponse({ error: 'ACCOUNT_RESTRICTED', status: user.status }, 403),
        };
      }
      const admin = await db
        .prepare(`SELECT * FROM admins WHERE telegram_id = ? AND is_active = 1`)
        .bind(user.telegram_id)
        .first<D1AdminRow>();
      return {
        ok: true,
        ctx: { user, admin: admin ?? null, authMode: 'telegram_init_data' },
      };
    } catch (err) {
      await recordAuditLog(db, {
        actorType: 'system',
        actorId: 'auth_guard',
        action: 'TELEGRAM_AUTH_FAILED',
        entityType: 'session',
        severity: 'warning',
        metadata: { reason: err instanceof Error ? err.message : 'AUTH_ERROR' },
        ipAddress: clientIp,
      });
      return { ok: false, response: jsonResponse({ error: 'INVALID_TELEGRAM_INIT_DATA' }, 401) };
    }
  }

  if (env.ENVIRONMENT !== 'production' && env.ALLOW_PHASE0_PREVIEW_SESSION === 'true') {
    const previewUser = await upsertUserFromTelegram(db, {
      telegramId: '900000001',
      username: 'edge_preview_customer',
      firstName: 'EDGE Preview Customer',
      languageCode: 'fa',
    });
    return {
      ok: true,
      ctx: { user: previewUser, admin: null, authMode: 'phase0_preview' },
    };
  }

  return { ok: false, response: jsonResponse({ error: 'TELEGRAM_AUTH_REQUIRED' }, 401) };
}

async function requireAdminPermission(
  db: D1Database,
  ctx: AuthContext,
  permission: AdminPermission,
  clientIp: string
): Promise<Response | null> {
  const admin = ctx.admin;
  const extra = parseExtraPermissions(admin);
  if (!admin || admin.is_active !== 1 || !hasAdminPermission(admin.role as AdminRole, permission, extra)) {
    await recordAuditLog(db, {
      actorType: 'user',
      actorId: ctx.user.telegram_id,
      action: 'ADMIN_ACCESS_DENIED',
      entityType: 'permission',
      entityId: permission,
      severity: 'warning',
      ipAddress: clientIp,
    });
    await recordSecurityEvent(db, {
      eventType: 'UNAUTHORIZED_ADMIN',
      severity: 'medium',
      userId: ctx.user.id,
      ipAddress: clientIp,
      details: { permission },
    });
    return jsonResponse({ error: 'FORBIDDEN_ADMIN_PERMISSION', required: permission }, 403);
  }
  return null;
}

async function runWithIdempotency(
  request: Request,
  db: D1Database,
  scope: string,
  actorId: string,
  bodyObj: unknown,
  handler: () => Promise<Response>
): Promise<Response> {
  const key = request.headers.get('Idempotency-Key')?.trim();
  if (!key) {
    return handler();
  }
  if (key.length < 8 || key.length > 128) {
    return jsonResponse({ error: 'INVALID_IDEMPOTENCY_KEY' }, 400);
  }

  const reqHash = await sha256Hex(canonicalizeJson(bodyObj ?? {}));
  const nowIso = new Date().toISOString();

  await db
    .prepare(`DELETE FROM idempotency_records WHERE scope = ? AND idempotency_key = ? AND expires_at <= ?`)
    .bind(scope, key, nowIso)
    .run();

  const existing = await db
    .prepare(
      `SELECT actor_id, request_hash, response_status, response_body_json
       FROM idempotency_records
       WHERE scope = ? AND idempotency_key = ?`
    )
    .bind(scope, key)
    .first<{
      actor_id: string;
      request_hash: string;
      response_status: number;
      response_body_json: string;
    }>();

  if (existing) {
    if (existing.actor_id !== actorId || existing.request_hash !== reqHash) {
      return jsonResponse(
        {
          error: 'IDEMPOTENCY_KEY_CONFLICT',
          message: 'Idempotency-Key was already used with a different payload or actor.',
        },
        409
      );
    }
    return new Response(existing.response_body_json, {
      status: existing.response_status,
      headers: { ...SECURITY_HEADERS, 'X-Idempotent-Replayed': 'true' },
    });
  }

  const res = await handler();
  if (res.status >= 200 && res.status < 300) {
    const resText = await res.clone().text();
    const expiresAt = new Date(Date.now() + 24 * 3600_000).toISOString();
    await db
      .prepare(
        `INSERT OR IGNORE INTO idempotency_records (
           scope, idempotency_key, actor_id, request_hash, response_status, response_body_json, expires_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(scope, key, actorId, reqHash, res.status, resText, expiresAt)
      .run();
  }
  return res;
}

export default {
  async fetch(
    request: Request,
    env: WorkerEnv,
    fetchImpl: typeof fetch = fetch
  ): Promise<Response> {
    const runtimeEnv: WorkerEnv = env.FETCH_IMPL ? env : { ...env, FETCH_IMPL: fetchImpl };
    if (!runtimeEnv.DB) {
      return handleLegacyProxyFetch(request, runtimeEnv, fetchImpl);
    }

    const db = runtimeEnv.DB;
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method.toUpperCase();
    const clientIp = getClientIp(request);

    try {
      await ensureSuperAdminBootstrap(db, runtimeEnv);

      // 1. Health & Public Config & Public RSA Key
      if (method === 'GET' && (path === '/v1/health' || path === '/api/v1/health')) {
        const dbCheck = await db.prepare('SELECT 1 AS ok').first<{ ok: number }>();
        const phaseRow = await db
          .prepare(`SELECT value FROM system_settings WHERE key = 'system_phase'`)
          .first<{ value: string }>();
        return jsonResponse({
          ok: dbCheck?.ok === 1,
          architecture: 'PATH_B1_CLOUDFLARE_WORKER_D1',
          brand: `${DOMAIN_CONSTANTS.brandName} by ${DOMAIN_CONSTANTS.brandOwner}`,
          phase: phaseRow?.value ?? runtimeEnv.GATEWAY_PHASE ?? 'PHASE_1_6_PATH_B1_STAGING',
          paymentMode: runtimeEnv.PAYMENT_VERIFICATION_MODE ?? 'DRY_RUN',
          licenseMode: runtimeEnv.LICENSE_ISSUANCE_MODE ?? 'DRY_RUN',
          botHandle: DOMAIN_CONSTANTS.botHandle,
          timestamp: new Date().toISOString(),
        });
      }

      if (method === 'GET' && path === '/api/v1/public/config') {
        const phaseRow = await db
          .prepare(`SELECT value FROM system_settings WHERE key = 'system_phase'`)
          .first<{ value: string }>();
        const plansRes = await db
          .prepare(`SELECT * FROM plans WHERE is_active = 1 ORDER BY sort_order ASC`)
          .all<D1PlanRow>();
        return jsonResponse({
          brandName: DOMAIN_CONSTANTS.brandName,
          brandOwner: DOMAIN_CONSTANTS.brandOwner,
          botHandle: DOMAIN_CONSTANTS.botHandle,
          phase: phaseRow?.value ?? runtimeEnv.GATEWAY_PHASE ?? 'PHASE_1_6_PATH_B1_STAGING',
          paymentMode: runtimeEnv.PAYMENT_VERIFICATION_MODE ?? 'DRY_RUN',
          licenseMode: runtimeEnv.LICENSE_ISSUANCE_MODE ?? 'DRY_RUN',
          network: {
            name: DOMAIN_CONSTANTS.networkName,
            chainId: DOMAIN_CONSTANTS.chainId,
            currencySymbol: 'USDC',
            tokenStandard: 'ERC-20 (Polygon PoS Native USDC)',
            usdcContractAddress: DOMAIN_CONSTANTS.usdcContractAddress,
            destinationWalletAddress: DOMAIN_CONSTANTS.destinationWalletAddress,
            minConfirmations: Number(runtimeEnv.POLYGON_MIN_CONFIRMATIONS ?? DOMAIN_CONSTANTS.minConfirmations),
          },
          plans: plansRes.results ?? [],
        });
      }

      if (method === 'GET' && (path === '/v1/license/public-key' || path === '/api/v1/license/public-key')) {
        if (!runtimeEnv.RSA_PUBLIC_KEY_PEM) {
          return jsonResponse({ error: 'RSA_PUBLIC_KEY_NOT_CONFIGURED' }, 503);
        }
        return jsonResponse({
          keyId: runtimeEnv.RSA_KEY_ID ?? 'edge-rsa-v1',
          algorithm: 'RSASSA-PKCS1-v1_5-SHA256',
          publicKeyPem: runtimeEnv.RSA_PUBLIC_KEY_PEM,
        });
      }

      // 2. Android Keystore PoP & Zero-APK-Secret License Endpoints
      if (method === 'POST' && (path === '/v1/license/challenge' || path === '/api/v1/license/challenge')) {
        const maxPerMin = Number(runtimeEnv.RATE_LIMIT_MAX_PER_MIN ?? 60);
        const rate = checkEdgeRateLimit(`chg:${clientIp}`, Number.isFinite(maxPerMin) ? maxPerMin : 60);
        if (!rate.allowed) {
          return jsonResponse({ error: 'RATE_LIMIT_EXCEEDED', retryAfterSeconds: rate.retryAfterSec }, 429);
        }
        const body = (await request.json().catch(() => null)) as {
          licenseKey?: string;
          deviceKeyId?: string;
          deviceFingerprint?: string;
        } | null;
        if (!body?.licenseKey || !body?.deviceKeyId || !body?.deviceFingerprint) {
          return jsonResponse({ error: 'MISSING_CHALLENGE_FIELDS' }, 400);
        }
        const challenge = await issueDeviceChallengeD1(db, {
          licenseKey: body.licenseKey.trim(),
          deviceKeyId: body.deviceKeyId.trim(),
          deviceFingerprint: body.deviceFingerprint.trim(),
        });
        return jsonResponse(challenge, 200);
      }

      if (method === 'POST' && (path === '/v1/license/activate' || path === '/api/v1/license/activate')) {
        const maxPerMin = Number(runtimeEnv.RATE_LIMIT_MAX_PER_MIN ?? 60);
        const rate = checkEdgeRateLimit(`act:${clientIp}`, Number.isFinite(maxPerMin) ? maxPerMin : 60);
        if (!rate.allowed) {
          return jsonResponse({ error: 'RATE_LIMIT_EXCEEDED', retryAfterSeconds: rate.retryAfterSec }, 429);
        }
        const body = (await request.json().catch(() => null)) as {
          challengeId?: string;
          licenseKey?: string;
          deviceKeyId?: string;
          deviceFingerprint?: string;
          devicePublicKeySpkiBase64?: string;
          proofSignatureBase64?: string;
          attestationLevel?: 'strongbox' | 'tee' | 'software';
          deviceModel?: string;
          androidVersion?: string;
          appVersion?: string;
        } | null;
        if (
          !body?.challengeId ||
          !body?.licenseKey ||
          !body?.deviceKeyId ||
          !body?.deviceFingerprint ||
          !body?.devicePublicKeySpkiBase64 ||
          !body?.proofSignatureBase64
        ) {
          return jsonResponse({ error: 'MISSING_ACTIVATION_FIELDS' }, 400);
        }
        const activated = await activateDeviceWithProofD1(db, runtimeEnv, {
          challengeId: body.challengeId,
          licenseKey: body.licenseKey,
          deviceKeyId: body.deviceKeyId,
          deviceFingerprint: body.deviceFingerprint,
          devicePublicKeySpkiBase64: body.devicePublicKeySpkiBase64,
          proofSignatureBase64: body.proofSignatureBase64,
          attestationLevel: body.attestationLevel,
          deviceModel: body.deviceModel,
          androidVersion: body.androidVersion,
          appVersion: body.appVersion,
          ipAddress: clientIp,
        });
        return jsonResponse(activated, 200);
      }

      if (method === 'POST' && (path === '/v1/license/validate' || path === '/api/v1/license/validate')) {
        const maxPerMin = Number(runtimeEnv.RATE_LIMIT_MAX_PER_MIN ?? 60);
        const rate = checkEdgeRateLimit(clientIp, Number.isFinite(maxPerMin) ? maxPerMin : 60);
        if (!rate.allowed) {
          return jsonResponse(
            { error: 'RATE_LIMIT_EXCEEDED', retryAfterSeconds: rate.retryAfterSec },
            429,
            { 'Retry-After': String(rate.retryAfterSec) }
          );
        }
        const rawBody = await request.text();
        if (rawBody.length > 4096) {
          return jsonResponse({ error: 'PAYLOAD_TOO_LARGE' }, 413);
        }
        const body = JSON.parse(rawBody || '{}') as {
          licenseKey?: string;
          deviceKeyId?: string;
          appVersion?: string;
        };
        if (!body.licenseKey || !body.deviceKeyId) {
          return jsonResponse({ valid: false, reason: 'MISSING_LICENSE_OR_DEVICE_KEY' }, 400);
        }
        const outcome = await validateAndroidLicenseD1(db, runtimeEnv, {
          licenseKey: body.licenseKey.trim(),
          deviceKeyId: body.deviceKeyId.trim(),
          rawBody,
          timestampHeader: request.headers.get('X-Device-Timestamp'),
          nonceHeader: request.headers.get('X-Device-Nonce'),
          deviceSignatureHeader: request.headers.get('X-Device-Signature'),
          appVersion: body.appVersion,
          ipAddress: clientIp,
        });
        return jsonResponse(outcome.body, outcome.status);
      }

      // 3. Telegram Bot Webhook (Fail-Closed + Deduplicated)
      if (method === 'POST' && (path === '/api/v1/bot/webhook' || path === '/v1/bot/webhook')) {
        const wh = await handleTelegramWebhookWorker(request, db, runtimeEnv, clientIp);
        return jsonResponse(wh.body, wh.status);
      }

      // 4. Mini App Single-Use Telegram initData -> Bearer Session Exchange
      if (method === 'POST' && path === '/api/v1/auth/telegram') {
        const body = (await request.json().catch(() => ({}))) as { initData?: string };
        const initData = request.headers.get('X-Telegram-Init-Data') ?? body.initData ?? '';
        try {
          const maxAge = Number(runtimeEnv.TELEGRAM_INIT_DATA_MAX_AGE_SECONDS ?? 300);
          const verified = await verifyTelegramInitDataWebCrypto(
            initData,
            runtimeEnv.TELEGRAM_BOT_TOKEN ?? '',
            { maxAgeSeconds: maxAge }
          );
          const fresh = await claimSingleUseKey(db, {
            scope: 'telegram_init_data_exchange',
            key: verified.hash,
            actorId: String(verified.user.id),
            ttlSeconds: maxAge + 60,
          });
          if (!fresh) {
            await recordSecurityEvent(db, {
              eventType: 'INIT_DATA_REPLAY',
              severity: 'medium',
              ipAddress: clientIp,
              details: { telegramId: verified.user.id },
            });
            return jsonResponse({ error: 'TELEGRAM_INIT_DATA_REPLAYED' }, 401);
          }
          const user = await upsertUserFromTelegram(db, {
            telegramId: String(verified.user.id),
            username: verified.user.username ?? null,
            firstName: verified.user.first_name,
            lastName: verified.user.last_name ?? null,
            languageCode: verified.user.language_code ?? 'fa',
          });
          if (user.status !== 'active') {
            return jsonResponse({ error: 'ACCOUNT_RESTRICTED', status: user.status }, 403);
          }
          const signingKey = await deriveWorkerSessionSigningKey(
            runtimeEnv.SESSION_SECRET,
            runtimeEnv.TELEGRAM_BOT_TOKEN
          );
          const { token, expiresAt } = await signWorkerSessionToken(
            {
              telegramId: user.telegram_id,
              userId: user.id,
              ttlSeconds: Number(runtimeEnv.SESSION_TTL_SECONDS ?? 900),
            },
            signingKey
          );
          const admin = await db
            .prepare(`SELECT * FROM admins WHERE telegram_id = ? AND is_active = 1`)
            .bind(user.telegram_id)
            .first<D1AdminRow>();
          return jsonResponse({
            token,
            expiresAt,
            user,
            adminRole: admin?.role ?? null,
            permissions: getEffectivePermissions(
              (admin?.role as AdminRole | undefined) ?? null,
              parseExtraPermissions(admin)
            ),
          });
        } catch (err) {
          await recordAuditLog(db, {
            actorType: 'system',
            actorId: 'auth_exchange',
            action: 'TELEGRAM_AUTH_EXCHANGE_FAILED',
            entityType: 'session',
            severity: 'warning',
            metadata: { reason: err instanceof Error ? err.message : 'AUTH_ERROR' },
            ipAddress: clientIp,
          });
          return jsonResponse({ error: 'INVALID_TELEGRAM_INIT_DATA' }, 401);
        }
      }

      // 5. Authenticated Mini App Routes
      if (path.startsWith('/api/v1/')) {
        const auth = await authenticateWorkerRequest(request, db, runtimeEnv, clientIp);
        if (!auth.ok) return auth.response;
        const { ctx } = auth;

        if (method === 'GET' && path === '/api/v1/me') {
          const phaseRow = await db
            .prepare(`SELECT value FROM system_settings WHERE key = 'system_phase'`)
            .first<{ value: string }>();
          return jsonResponse({
            authenticated: true,
            authMode: ctx.authMode,
            phase: phaseRow?.value ?? runtimeEnv.GATEWAY_PHASE ?? 'PHASE_1_6_PATH_B1_STAGING',
            paymentMode: runtimeEnv.PAYMENT_VERIFICATION_MODE ?? 'DRY_RUN',
            licenseMode: runtimeEnv.LICENSE_ISSUANCE_MODE ?? 'DRY_RUN',
            user: ctx.user,
            adminRole: ctx.admin?.role ?? null,
            permissions: getEffectivePermissions(
              (ctx.admin?.role as AdminRole | undefined) ?? null,
              parseExtraPermissions(ctx.admin)
            ),
          });
        }

        if (method === 'GET' && path === '/api/v1/orders') {
          const rows = await db
            .prepare(
              `SELECT o.*, p.code AS plan_code, p.name_en AS plan_name_en, p.name_fa AS plan_name_fa
               FROM orders o JOIN plans p ON p.id = o.plan_id
               WHERE o.user_id = ? ORDER BY o.id DESC`
            )
            .bind(ctx.user.id)
            .all<D1OrderRow>();
          return jsonResponse({ orders: rows.results ?? [] });
        }

        if (method === 'POST' && path === '/api/v1/orders') {
          const body = (await request.json().catch(() => null)) as {
            planCode?: string;
            orderType?: 'new' | 'renew' | 'upgrade';
            targetSubscriptionId?: number;
            expectedSenderWallet?: string;
          } | null;
          if (!body?.planCode) return jsonResponse({ error: 'PLAN_CODE_REQUIRED' }, 400);
          return await runWithIdempotency(request, db, 'create_order', ctx.user.telegram_id, body, async () => {
            const order = await createOrderD1(db, runtimeEnv, {
              userId: ctx.user.id,
              planCode: body.planCode!,
              orderType: body.orderType,
              targetSubscriptionId: body.targetSubscriptionId,
              expectedSenderWallet: body.expectedSenderWallet,
              ipAddress: clientIp,
            });
            return jsonResponse({ order }, 201);
          });
        }

        if (method === 'GET' && path === '/api/v1/payments') {
          const rows = await db
            .prepare(
              `SELECT pay.*, o.order_code
               FROM payments pay JOIN orders o ON o.id = pay.order_id
               WHERE pay.user_id = ? ORDER BY pay.id DESC`
            )
            .bind(ctx.user.id)
            .all<D1PaymentRow>();
          return jsonResponse({ payments: rows.results ?? [] });
        }

        if (method === 'POST' && path === '/api/v1/payments/submit-tx') {
          const body = (await request.json().catch(() => null)) as {
            orderCode?: string;
            txHash?: string;
          } | null;
          if (!body?.orderCode || !body?.txHash) {
            return jsonResponse({ error: 'ORDER_CODE_AND_TX_HASH_REQUIRED' }, 400);
          }
          return await runWithIdempotency(request, db, 'submit_tx', ctx.user.telegram_id, body, async () => {
            const result = await submitTransactionHashD1(db, runtimeEnv, {
              userId: ctx.user.id,
              orderCode: body.orderCode!,
              txHash: body.txHash!,
              ipAddress: clientIp,
            });
            return jsonResponse(result, 201);
          });
        }

        if (method === 'GET' && path === '/api/v1/licenses') {
          const licRows = await db
            .prepare(`SELECT * FROM licenses WHERE user_id = ? ORDER BY id DESC`)
            .bind(ctx.user.id)
            .all<Record<string, unknown>>();
          const subRows = await db
            .prepare(
              `SELECT s.*, p.code AS plan_code, p.name_en AS plan_name_en, p.name_fa AS plan_name_fa
               FROM subscriptions s JOIN plans p ON p.id = s.plan_id
               WHERE s.user_id = ? ORDER BY s.id DESC`
            )
            .bind(ctx.user.id)
            .all<Record<string, unknown>>();
          const licenses = await Promise.all(
            (licRows.results ?? []).map(async (lic) => {
              const devRows = await db
                .prepare(`SELECT * FROM devices WHERE license_id = ? ORDER BY id DESC`)
                .bind(lic.id)
                .all<Record<string, unknown>>();
              return { ...lic, devices: devRows.results ?? [] };
            })
          );
          return jsonResponse({ licenses, subscriptions: subRows.results ?? [] });
        }

        const userUnbindMatch = path.match(/^\/api\/v1\/licenses\/([^/]+)\/devices\/([^/]+)$/);
        if (method === 'DELETE' && userUnbindMatch) {
          const licenseKey = decodeURIComponent(userUnbindMatch[1]);
          const fingerprint = decodeURIComponent(userUnbindMatch[2]);
          const lic = await db
            .prepare(`SELECT id, user_id FROM licenses WHERE license_key = ?`)
            .bind(licenseKey)
            .first<{ id: number; user_id: number }>();
          if (!lic || lic.user_id !== ctx.user.id) {
            return jsonResponse({ error: 'LICENSE_NOT_FOUND' }, 404);
          }
          const res = await db
            .prepare(`DELETE FROM devices WHERE license_id = ? AND device_fingerprint = ?`)
            .bind(lic.id, fingerprint)
            .run();
          if ((res.meta?.changes ?? 0) === 0) {
            return jsonResponse({ error: 'DEVICE_NOT_FOUND' }, 404);
          }
          await recordAuditLog(db, {
            actorType: 'user',
            actorId: ctx.user.telegram_id,
            action: 'DEVICE_UNBOUND',
            entityType: 'device',
            entityId: fingerprint,
            metadata: { licenseKey },
          });
          return jsonResponse({ unbound: true });
        }

        if (method === 'GET' && path === '/api/v1/support/tickets') {
          const tickets = await db
            .prepare(`SELECT * FROM support_tickets WHERE user_id = ? ORDER BY id DESC`)
            .bind(ctx.user.id)
            .all<Record<string, unknown>>();
          return jsonResponse({ tickets: tickets.results ?? [] });
        }

        if (method === 'POST' && path === '/api/v1/support/tickets') {
          const body = (await request.json().catch(() => null)) as {
            subject?: string;
            message?: string;
            orderId?: number;
            priority?: 'low' | 'normal' | 'high' | 'urgent';
          } | null;
          if (!body?.subject || body.subject.trim().length < 3 || !body?.message || body.message.trim().length < 5) {
            return jsonResponse({ error: 'INVALID_TICKET_PAYLOAD' }, 400);
          }
          return await runWithIdempotency(request, db, 'create_ticket', ctx.user.telegram_id, body, async () => {
            const ticketCode = `TKT-${Date.now().toString(36).toUpperCase()}-${randomHex(2).toUpperCase()}`;
            await db
              .prepare(
                `INSERT INTO support_tickets (ticket_code, user_id, order_id, subject, message, status, priority)
                 VALUES (?, ?, ?, ?, ?, 'open', ?)`
              )
              .bind(
                ticketCode,
                ctx.user.id,
                body.orderId ?? null,
                body.subject!.trim().slice(0, 120),
                body.message!.trim().slice(0, 2000),
                body.priority ?? 'normal'
              )
              .run();
            const ticket = await db
              .prepare(`SELECT * FROM support_tickets WHERE ticket_code = ?`)
              .bind(ticketCode)
              .first<Record<string, unknown>>();
            return jsonResponse({ ticket }, 201);
          });
        }

        if (method === 'GET' && path === '/api/v1/notifications') {
          const rows = await db
            .prepare(`SELECT * FROM notifications WHERE user_id = ? ORDER BY id DESC LIMIT 50`)
            .bind(ctx.user.id)
            .all<Record<string, unknown>>();
          return jsonResponse({ notifications: rows.results ?? [] });
        }

        // ==================== Restricted RBAC Admin Routes ====================
        if (path.startsWith('/api/v1/admin/')) {
          if (method === 'GET' && path === '/api/v1/admin/dashboard') {
            const deny = await requireAdminPermission(db, ctx, 'dashboard:read', clientIp);
            if (deny) return deny;
            const [usersC, ordersC, pendingPayC, activeSubC, activeLicC, openTicketsC, revRow] =
              await Promise.all([
                db.prepare(`SELECT COUNT(*) AS cnt FROM users`).first<{ cnt: number }>(),
                db.prepare(`SELECT COUNT(*) AS cnt FROM orders`).first<{ cnt: number }>(),
                db
                  .prepare(`SELECT COUNT(*) AS cnt FROM payments WHERE status IN ('submitted', 'dry_run_recorded', 'verifying')`)
                  .first<{ cnt: number }>(),
                db.prepare(`SELECT COUNT(*) AS cnt FROM subscriptions WHERE status = 'active'`).first<{ cnt: number }>(),
                db.prepare(`SELECT COUNT(*) AS cnt FROM licenses WHERE status = 'active'`).first<{ cnt: number }>(),
                db
                  .prepare(`SELECT COUNT(*) AS cnt FROM support_tickets WHERE status IN ('open', 'in_progress')`)
                  .first<{ cnt: number }>(),
                db
                  .prepare(`SELECT COALESCE(SUM(amount_usdc_micro), 0) AS total FROM payments WHERE status = 'confirmed'`)
                  .first<{ total: number }>(),
              ]);
            return jsonResponse({
              summary: {
                totalUsers: usersC?.cnt ?? 0,
                totalOrders: ordersC?.cnt ?? 0,
                pendingPayments: pendingPayC?.cnt ?? 0,
                activeSubscriptions: activeSubC?.cnt ?? 0,
                activeLicenses: activeLicC?.cnt ?? 0,
                openTickets: openTicketsC?.cnt ?? 0,
                confirmedRevenueUsd: formatMicroUsdc(revRow?.total ?? 0),
              },
            });
          }

          if (method === 'GET' && path === '/api/v1/admin/users') {
            const deny = await requireAdminPermission(db, ctx, 'users:read', clientIp);
            if (deny) return deny;
            const limit = Math.min(200, Math.max(1, Number(url.searchParams.get('limit') ?? 100)));
            const offset = Math.max(0, Number(url.searchParams.get('offset') ?? 0));
            const rows = await db
              .prepare(`SELECT * FROM users ORDER BY id DESC LIMIT ? OFFSET ?`)
              .bind(limit, offset)
              .all<D1UserRow>();
            return jsonResponse({ users: rows.results ?? [] });
          }

          const userStatusMatch = path.match(/^\/api\/v1\/admin\/users\/(\d+)\/status$/);
          if (method === 'PATCH' && userStatusMatch) {
            const deny = await requireAdminPermission(db, ctx, 'users:write', clientIp);
            if (deny) return deny;
            const userId = Number(userStatusMatch[1]);
            const body = (await request.json().catch(() => null)) as {
              status?: 'active' | 'suspended' | 'banned';
            } | null;
            if (!body?.status || !['active', 'suspended', 'banned'].includes(body.status)) {
              return jsonResponse({ error: 'INVALID_USER_STATUS' }, 400);
            }
            const nowIso = new Date().toISOString();
            await db
              .prepare(`UPDATE users SET status = ?, updated_at = ? WHERE id = ?`)
              .bind(body.status, nowIso, userId)
              .run();
            const user = await db.prepare(`SELECT * FROM users WHERE id = ?`).bind(userId).first<D1UserRow>();
            if (!user) return jsonResponse({ error: 'USER_NOT_FOUND' }, 404);
            await recordAuditLog(db, {
              actorType: 'admin',
              actorId: ctx.user.telegram_id,
              action: 'USER_STATUS_UPDATED',
              entityType: 'user',
              entityId: String(userId),
              metadata: { status: body.status },
            });
            return jsonResponse({ user });
          }

          if (method === 'GET' && path === '/api/v1/admin/orders') {
            const deny = await requireAdminPermission(db, ctx, 'orders:read', clientIp);
            if (deny) return deny;
            const rows = await db
              .prepare(
                `SELECT o.*, p.code AS plan_code, p.name_en AS plan_name_en, p.name_fa AS plan_name_fa
                 FROM orders o JOIN plans p ON p.id = o.plan_id ORDER BY o.id DESC LIMIT 100`
              )
              .all<D1OrderRow>();
            return jsonResponse({ orders: rows.results ?? [] });
          }

          const orderStatusMatch = path.match(/^\/api\/v1\/admin\/orders\/([^/]+)\/status$/);
          if (method === 'PATCH' && orderStatusMatch) {
            const deny = await requireAdminPermission(db, ctx, 'orders:write', clientIp);
            if (deny) return deny;
            const orderCode = decodeURIComponent(orderStatusMatch[1]);
            const body = (await request.json().catch(() => null)) as {
              status?: 'cancelled' | 'rejected' | 'expired';
              reason?: string;
            } | null;
            if (!body?.status || !['cancelled', 'rejected', 'expired'].includes(body.status) || !body?.reason) {
              return jsonResponse({ error: 'INVALID_ORDER_STATUS_PATCH' }, 400);
            }
            const nowIso = new Date().toISOString();
            await db
              .prepare(`UPDATE orders SET status = ?, updated_at = ? WHERE order_code = ?`)
              .bind(body.status, nowIso, orderCode)
              .run();
            const order = await db
              .prepare(`SELECT * FROM orders WHERE order_code = ?`)
              .bind(orderCode)
              .first<D1OrderRow>();
            if (!order) return jsonResponse({ error: 'ORDER_NOT_FOUND' }, 404);
            await recordAuditLog(db, {
              actorType: 'admin',
              actorId: ctx.user.telegram_id,
              action: 'ORDER_STATUS_UPDATED',
              entityType: 'order',
              entityId: orderCode,
              metadata: { status: body.status, reason: body.reason },
            });
            return jsonResponse({ order });
          }

          if (method === 'GET' && path === '/api/v1/admin/payments') {
            const deny = await requireAdminPermission(db, ctx, 'payments:read', clientIp);
            if (deny) return deny;
            const rows = await db
              .prepare(
                `SELECT pay.*, o.order_code FROM payments pay JOIN orders o ON o.id = pay.order_id ORDER BY pay.id DESC LIMIT 100`
              )
              .all<D1PaymentRow>();
            return jsonResponse({ payments: rows.results ?? [] });
          }

          const payVerifyMatch = path.match(/^\/api\/v1\/admin\/payments\/(\d+)\/verify$/);
          if (method === 'POST' && payVerifyMatch) {
            const deny = await requireAdminPermission(db, ctx, 'payments:verify', clientIp);
            if (deny) return deny;
            const paymentId = Number(payVerifyMatch[1]);
            const result = await verifyPaymentOnChainD1(db, runtimeEnv, paymentId, {
              actorId: ctx.user.telegram_id,
            });
            return jsonResponse(result);
          }

          if (method === 'GET' && path === '/api/v1/admin/subscriptions') {
            const deny = await requireAdminPermission(db, ctx, 'subscriptions:read', clientIp);
            if (deny) return deny;
            const rows = await db
              .prepare(
                `SELECT s.*, p.code AS plan_code, p.name_en AS plan_name_en, p.name_fa AS plan_name_fa
                 FROM subscriptions s JOIN plans p ON p.id = s.plan_id ORDER BY s.id DESC LIMIT 100`
              )
              .all<Record<string, unknown>>();
            return jsonResponse({ subscriptions: rows.results ?? [] });
          }

          if (method === 'GET' && path === '/api/v1/admin/licenses') {
            const deny = await requireAdminPermission(db, ctx, 'licenses:read', clientIp);
            if (deny) return deny;
            const rows = await db
              .prepare(`SELECT * FROM licenses ORDER BY id DESC LIMIT 100`)
              .all<Record<string, unknown>>();
            return jsonResponse({ licenses: rows.results ?? [] });
          }

          const licHistoryMatch = path.match(/^\/api\/v1\/admin\/licenses\/([^/]+)\/history$/);
          if (method === 'GET' && licHistoryMatch) {
            const deny = await requireAdminPermission(db, ctx, 'licenses:read', clientIp);
            if (deny) return deny;
            const licenseKey = decodeURIComponent(licHistoryMatch[1]);
            const lic = await db
              .prepare(`SELECT id FROM licenses WHERE license_key = ?`)
              .bind(licenseKey)
              .first<{ id: number }>();
            if (!lic) return jsonResponse({ error: 'LICENSE_NOT_FOUND' }, 404);
            const rows = await db
              .prepare(`SELECT * FROM license_history WHERE license_id = ? ORDER BY id DESC`)
              .bind(lic.id)
              .all<Record<string, unknown>>();
            return jsonResponse({ history: rows.results ?? [] });
          }

          const licStatusMatch = path.match(/^\/api\/v1\/admin\/licenses\/([^/]+)\/status$/);
          if (method === 'PATCH' && licStatusMatch) {
            const deny = await requireAdminPermission(db, ctx, 'licenses:write', clientIp);
            if (deny) return deny;
            const licenseKey = decodeURIComponent(licStatusMatch[1]);
            const body = (await request.json().catch(() => null)) as {
              status?: 'active' | 'revoked' | 'blocked';
              reason?: string;
            } | null;
            if (!body?.status || !['active', 'revoked', 'blocked'].includes(body.status) || !body?.reason) {
              return jsonResponse({ error: 'INVALID_LICENSE_STATUS_PATCH' }, 400);
            }
            await updateLicenseStatusD1(db, {
              licenseKey,
              status: body.status,
              reason: body.reason,
              adminActorId: ctx.user.telegram_id,
            });
            const license = await db
              .prepare(`SELECT * FROM licenses WHERE license_key = ?`)
              .bind(licenseKey)
              .first<Record<string, unknown>>();
            return jsonResponse({ license });
          }

          const adminUnbindMatch = path.match(/^\/api\/v1\/admin\/licenses\/([^/]+)\/devices\/([^/]+)$/);
          if (method === 'DELETE' && adminUnbindMatch) {
            const deny = await requireAdminPermission(db, ctx, 'licenses:write', clientIp);
            if (deny) return deny;
            const licenseKey = decodeURIComponent(adminUnbindMatch[1]);
            const fingerprint = decodeURIComponent(adminUnbindMatch[2]);
            const lic = await db
              .prepare(`SELECT id FROM licenses WHERE license_key = ?`)
              .bind(licenseKey)
              .first<{ id: number }>();
            if (!lic) return jsonResponse({ error: 'LICENSE_NOT_FOUND' }, 404);
            const res = await db
              .prepare(`DELETE FROM devices WHERE license_id = ? AND device_fingerprint = ?`)
              .bind(lic.id, fingerprint)
              .run();
            if ((res.meta?.changes ?? 0) === 0) return jsonResponse({ error: 'DEVICE_NOT_FOUND' }, 404);
            await recordAuditLog(db, {
              actorType: 'admin',
              actorId: ctx.user.telegram_id,
              action: 'ADMIN_DEVICE_UNBOUND',
              entityType: 'device',
              entityId: fingerprint,
              metadata: { licenseKey },
            });
            return jsonResponse({ unbound: true });
          }

          if (method === 'GET' && path === '/api/v1/admin/plans') {
            const deny = await requireAdminPermission(db, ctx, 'plans:read', clientIp);
            if (deny) return deny;
            const rows = await db.prepare(`SELECT * FROM plans ORDER BY sort_order ASC`).all<D1PlanRow>();
            return jsonResponse({ plans: rows.results ?? [] });
          }

          const planMatch = path.match(/^\/api\/v1\/admin\/plans\/([^/]+)$/);
          if (method === 'PATCH' && planMatch) {
            const deny = await requireAdminPermission(db, ctx, 'plans:write', clientIp);
            if (deny) return deny;
            const code = decodeURIComponent(planMatch[1]);
            const body = (await request.json().catch(() => null)) as {
              isActive?: boolean;
              maxDevices?: number;
            } | null;
            const existing = await db.prepare(`SELECT * FROM plans WHERE code = ?`).bind(code).first<D1PlanRow>();
            if (!existing) return jsonResponse({ error: 'PLAN_NOT_FOUND' }, 404);
            const nextActive = body?.isActive === undefined ? existing.is_active : body.isActive ? 1 : 0;
            const nextMaxDev = body?.maxDevices ?? existing.max_devices;
            await db
              .prepare(`UPDATE plans SET is_active = ?, max_devices = ?, updated_at = ? WHERE code = ?`)
              .bind(nextActive, nextMaxDev, new Date().toISOString(), code)
              .run();
            const plan = await db.prepare(`SELECT * FROM plans WHERE code = ?`).bind(code).first<D1PlanRow>();
            return jsonResponse({ plan });
          }

          if (method === 'GET' && path === '/api/v1/admin/reports/finance') {
            const deny = await requireAdminPermission(db, ctx, 'reports:finance', clientIp);
            if (deny) return deny;
            const byPlanRes = await db
              .prepare(
                `SELECT p.code AS plan_code, p.name_en, p.price_usd_display,
                        COUNT(DISTINCT o.id) AS orders_count,
                        COUNT(DISTINCT CASE WHEN pay.status = 'confirmed' THEN pay.id END) AS confirmed_payments_count,
                        COALESCE(SUM(CASE WHEN pay.status = 'confirmed' THEN pay.amount_usdc_micro ELSE 0 END), 0) AS confirmed_usdc_micro
                 FROM plans p
                 LEFT JOIN orders o ON o.plan_id = p.id
                 LEFT JOIN payments pay ON pay.order_id = o.id
                 GROUP BY p.id
                 ORDER BY p.sort_order ASC`
              )
              .all<Record<string, unknown>>();
            const totals = await db
              .prepare(
                `SELECT (SELECT COUNT(*) FROM orders) AS total_orders,
                        (SELECT COUNT(*) FROM payments WHERE status = 'confirmed') AS confirmed_payments,
                        (SELECT COALESCE(SUM(amount_usdc_micro), 0) FROM payments WHERE status = 'confirmed') AS confirmed_micro,
                        (SELECT COUNT(*) FROM payments WHERE status = 'dry_run_recorded') AS dry_run_submissions`
              )
              .first<{
                total_orders: number;
                confirmed_payments: number;
                confirmed_micro: number;
                dry_run_submissions: number;
              }>();
            return jsonResponse({
              byPlan: byPlanRes.results ?? [],
              totals: {
                totalOrders: totals?.total_orders ?? 0,
                confirmedPayments: totals?.confirmed_payments ?? 0,
                confirmedRevenueUsd: formatMicroUsdc(totals?.confirmed_micro ?? 0),
                dryRunSubmissions: totals?.dry_run_submissions ?? 0,
              },
            });
          }

          if (method === 'GET' && path === '/api/v1/admin/reports/security') {
            const deny = await requireAdminPermission(db, ctx, 'reports:security', clientIp);
            if (deny) return deny;
            const severity = url.searchParams.get('severity');
            const rows = severity
              ? await db
                  .prepare(`SELECT * FROM audit_logs WHERE severity = ? ORDER BY id DESC LIMIT 100`)
                  .bind(severity)
                  .all<Record<string, unknown>>()
              : await db
                  .prepare(`SELECT * FROM audit_logs ORDER BY id DESC LIMIT 100`)
                  .all<Record<string, unknown>>();
            return jsonResponse({ auditLogs: rows.results ?? [] });
          }

          if (method === 'GET' && path === '/api/v1/admin/tickets') {
            const deny = await requireAdminPermission(db, ctx, 'users:read', clientIp);
            if (deny) return deny;
            const rows = await db
              .prepare(`SELECT * FROM support_tickets ORDER BY id DESC LIMIT 100`)
              .all<Record<string, unknown>>();
            return jsonResponse({ tickets: rows.results ?? [] });
          }

          const ticketMatch = path.match(/^\/api\/v1\/admin\/tickets\/(\d+)$/);
          if (method === 'PATCH' && ticketMatch) {
            const deny = await requireAdminPermission(db, ctx, 'users:write', clientIp);
            if (deny) return deny;
            const ticketId = Number(ticketMatch[1]);
            const body = (await request.json().catch(() => null)) as {
              status?: 'open' | 'in_progress' | 'resolved' | 'closed';
              adminReply?: string;
            } | null;
            if (!body?.status) return jsonResponse({ error: 'TICKET_STATUS_REQUIRED' }, 400);
            const nowIso = new Date().toISOString();
            const closedAt = body.status === 'closed' || body.status === 'resolved' ? nowIso : null;
            await db
              .prepare(
                `UPDATE support_tickets
                 SET status = ?, admin_reply = COALESCE(?, admin_reply), assigned_admin_id = ?, updated_at = ?, closed_at = COALESCE(?, closed_at)
                 WHERE id = ?`
              )
              .bind(body.status, body.adminReply ?? null, ctx.admin!.id, nowIso, closedAt, ticketId)
              .run();
            const ticket = await db
              .prepare(`SELECT * FROM support_tickets WHERE id = ?`)
              .bind(ticketId)
              .first<Record<string, unknown>>();
            if (!ticket) return jsonResponse({ error: 'TICKET_NOT_FOUND' }, 404);
            return jsonResponse({ ticket });
          }

          if (method === 'GET' && path === '/api/v1/admin/admins') {
            const deny = await requireAdminPermission(db, ctx, 'admins:read', clientIp);
            if (deny) return deny;
            const [adminsRes, settingsRes] = await Promise.all([
              db
                .prepare(
                  `SELECT a.*, u.username, u.first_name FROM admins a JOIN users u ON u.id = a.user_id ORDER BY a.id ASC`
                )
                .all<Record<string, unknown>>(),
              db.prepare(`SELECT * FROM system_settings ORDER BY key ASC`).all<Record<string, unknown>>(),
            ]);
            return jsonResponse({ admins: adminsRes.results ?? [], settings: settingsRes.results ?? [] });
          }

          if (method === 'POST' && path === '/api/v1/admin/admins') {
            const deny = await requireAdminPermission(db, ctx, 'admins:write', clientIp);
            if (deny) return deny;
            const body = (await request.json().catch(() => null)) as {
              telegramId?: string;
              role?: AdminRole;
            } | null;
            if (!body?.telegramId || !/^\d{5,20}$/.test(body.telegramId) || !body?.role) {
              return jsonResponse({ error: 'INVALID_ADMIN_PAYLOAD' }, 400);
            }
            return await runWithIdempotency(request, db, 'assign_admin', ctx.user.telegram_id, body, async () => {
              const targetUser = await upsertUserFromTelegram(db, {
                telegramId: body.telegramId!,
                firstName: `Admin ${body.telegramId}`,
              });
              await db
                .prepare(
                  `INSERT INTO admins (user_id, telegram_id, role, is_active, granted_by)
                   VALUES (?, ?, ?, 1, ?)
                   ON CONFLICT(user_id) DO UPDATE SET role = excluded.role, is_active = 1, granted_by = excluded.granted_by, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')`
                )
                .bind(targetUser.id, targetUser.telegram_id, body.role!, ctx.admin!.id)
                .run();
              const admin = await db
                .prepare(`SELECT * FROM admins WHERE telegram_id = ?`)
                .bind(targetUser.telegram_id)
                .first<D1AdminRow>();
              return jsonResponse({ admin }, 201);
            });
          }

          const deactAdminMatch = path.match(/^\/api\/v1\/admin\/admins\/(\d+)\/deactivate$/);
          if (method === 'PATCH' && deactAdminMatch) {
            const deny = await requireAdminPermission(db, ctx, 'admins:write', clientIp);
            if (deny) return deny;
            const adminId = Number(deactAdminMatch[1]);
            const target = await db.prepare(`SELECT * FROM admins WHERE id = ?`).bind(adminId).first<D1AdminRow>();
            if (!target) return jsonResponse({ error: 'ADMIN_NOT_FOUND' }, 404);
            if (target.role === 'super_admin') {
              const cnt = await db
                .prepare(`SELECT COUNT(*) AS cnt FROM admins WHERE role = 'super_admin' AND is_active = 1`)
                .first<{ cnt: number }>();
              if ((cnt?.cnt ?? 0) <= 1) {
                return jsonResponse({ error: 'LAST_SUPER_ADMIN_PROTECTED' }, 409);
              }
            }
            await db
              .prepare(`UPDATE admins SET is_active = 0, updated_at = ? WHERE id = ?`)
              .bind(new Date().toISOString(), adminId)
              .run();
            const updated = await db.prepare(`SELECT * FROM admins WHERE id = ?`).bind(adminId).first<D1AdminRow>();
            return jsonResponse({ admin: updated });
          }

          const settingMatch = path.match(/^\/api\/v1\/admin\/settings\/([^/]+)$/);
          if (method === 'PATCH' && settingMatch) {
            const deny = await requireAdminPermission(db, ctx, 'settings:write', clientIp);
            if (deny) return deny;
            const key = decodeURIComponent(settingMatch[1]);
            const body = (await request.json().catch(() => null)) as { value?: string } | null;
            if (!body?.value) return jsonResponse({ error: 'SETTING_VALUE_REQUIRED' }, 400);
            const existing = await db
              .prepare(`SELECT * FROM system_settings WHERE key = ?`)
              .bind(key)
              .first<{ key: string; is_immutable: number }>();
            if (!existing) return jsonResponse({ error: 'SETTING_NOT_FOUND' }, 404);
            if (existing.is_immutable === 1) {
              return jsonResponse({ error: 'IMMUTABLE_SYSTEM_SETTING' }, 403);
            }
            await db
              .prepare(`UPDATE system_settings SET value = ?, updated_by = ?, updated_at = ? WHERE key = ?`)
              .bind(body.value, ctx.user.telegram_id, new Date().toISOString(), key)
              .run();
            const setting = await db
              .prepare(`SELECT * FROM system_settings WHERE key = ?`)
              .bind(key)
              .first<Record<string, unknown>>();
            return jsonResponse({ setting });
          }

          if (method === 'POST' && path === '/api/v1/admin/cron/run') {
            const deny = await requireAdminPermission(db, ctx, 'settings:write', clientIp);
            if (deny) return deny;
            const result = await runDailyAuditD1(db, runtimeEnv, { force: true });
            return jsonResponse({ cron: result });
          }

          if (method === 'GET' && path === '/api/v1/admin/backups') {
            const deny = await requireAdminPermission(db, ctx, 'reports:security', clientIp);
            if (deny) return deny;
            const runs = await db
              .prepare(`SELECT * FROM cron_runs ORDER BY run_date_utc DESC LIMIT 30`)
              .all<Record<string, unknown>>();
            const r2Objects = runtimeEnv.BACKUP_BUCKET
              ? (await runtimeEnv.BACKUP_BUCKET.list({ prefix: 'backups/d1/', limit: 30 })).objects
              : [];
            return jsonResponse({ cronRuns: runs.results ?? [], r2Backups: r2Objects });
          }
        }
      }

      return jsonResponse({ error: 'ROUTE_NOT_FOUND' }, 404);
    } catch (err) {
      if (err instanceof DomainError) {
        return jsonResponse({ error: err.code, message: err.message }, err.statusCode);
      }
      const requestId = randomHex(6);
      await recordAuditLog(db, {
        actorType: 'system',
        actorId: 'worker_error_handler',
        action: 'UNHANDLED_WORKER_ERROR',
        entityType: 'http_request',
        entityId: requestId,
        severity: 'critical',
        metadata: { path, method, errorName: err instanceof Error ? err.name : 'UnknownError' },
        ipAddress: clientIp,
      }).catch(() => undefined);
      return jsonResponse({ error: 'INTERNAL_SERVER_ERROR', requestId }, 500);
    }
  },

  async scheduled(
    _controller: { scheduledTime?: number; cron?: string },
    env: WorkerEnv,
    ctx?: { waitUntil(promise: Promise<unknown>): void }
  ): Promise<void> {
    if (!env.DB) return;
    const task = (async () => {
      await checkAndRunMissedCronCatchUp(env.DB!, env);
      await runDailyAuditD1(env.DB!, env);
    })();
    if (ctx && typeof ctx.waitUntil === 'function') {
      ctx.waitUntil(task);
    } else {
      await task;
    }
  },
};
