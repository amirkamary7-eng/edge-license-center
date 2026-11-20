import crypto from 'crypto';
import express, { type NextFunction, type Request, type Response } from 'express';
import { z } from 'zod';
import {
  BRAND_NAME,
  BRAND_OWNER,
  PAYMENT_NETWORK,
  TELEGRAM_BOT_HANDLE,
} from '../shared/constants';
import type { AdminRecord, AdminRole, UserRecord } from '../shared/types';
import { EdgeBotRouter } from './bot/commands';
import { TelegramBotApiClient, type TelegramBotTransport } from './bot/telegramClient';
import { createTelegramWebhookHandler } from './bot/webhookHandler';
import type { ServerEnv } from './config/env';
import type { SqliteDb } from './db/connection';
import { AdminOperationError, AdminService } from './modules/admin/adminService';
import { AuditService } from './modules/audit/auditService';
import { LicenseError, LicenseService } from './modules/license/licenseService';
import { PaymentError, PaymentService } from './modules/payment/paymentService';
import { PolygonRpcClient, type PolygonRpcProvider } from './modules/payment/polygonVerifier';
import { PlanRepository } from './modules/plans/planRepository';
import { SupportService } from './modules/support/supportService';
import { UserRepository } from './modules/users/userRepository';
import {
  hashRequestPayload,
  IdempotencyError,
  IdempotencyStore,
} from './security/idempotency';
import { createRateLimiter } from './security/rateLimiter';
import {
  getEffectivePermissions,
  hasAdminPermission,
  type AdminPermission,
} from './security/rbac';
import {
  deriveSessionSigningKey,
  signSessionToken,
  verifySessionToken,
} from './security/sessionToken';
import { verifyTelegramInitData } from './security/telegramAuth';

declare module 'express-serve-static-core' {
  interface Request {
    authUser?: UserRecord;
    authAdmin?: AdminRecord | null;
    authMode?: 'telegram_init_data' | 'bearer_session' | 'phase0_preview';
    rawBody?: string;
  }
}

export interface CreateApiAppOptions {
  db: SqliteDb;
  env: ServerEnv;
  botClient?: TelegramBotTransport;
  rpcProvider?: PolygonRpcProvider;
}

function parseExtraPermissions(admin: AdminRecord | null | undefined): string[] {
  if (!admin?.permissions_json) return [];
  try {
    const parsed = JSON.parse(admin.permissions_json);
    return Array.isArray(parsed) ? parsed.filter((x): x is string => typeof x === 'string') : [];
  } catch {
    return [];
  }
}

export function createApiApp({
  db,
  env,
  botClient: injectedBotClient,
  rpcProvider: injectedRpcProvider,
}: CreateApiAppOptions): express.Express {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', 1);

  // Strict security headers
  app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    res.setHeader(
      'Content-Security-Policy',
      "default-src 'self' https://telegram.org https://fonts.googleapis.com https://fonts.gstatic.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; script-src 'self' 'unsafe-inline' https://telegram.org; img-src 'self' data:; connect-src 'self'"
    );
    if (env.NODE_ENV === 'production') {
      res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    }
    next();
  });

  app.use(
    express.json({
      limit: '256kb',
      verify: (req, _res, buf) => {
        (req as Request).rawBody = buf.toString('utf8');
      },
    })
  );

  const users = new UserRepository(db);
  const plans = new PlanRepository(db);
  const audit = new AuditService(db);
  const idempotency = new IdempotencyStore(db);
  const supportService = new SupportService(db);

  const licenseService = new LicenseService(db, {
    issuanceMode: env.LICENSE_ISSUANCE_MODE,
    rsaPrivateKeyPem: env.RSA_PRIVATE_KEY_PEM,
    rsaPublicKeyPem: env.RSA_PUBLIC_KEY_PEM,
    rsaKeyId: env.RSA_KEY_ID,
  });

  const rpcProvider: PolygonRpcProvider =
    injectedRpcProvider ??
    new PolygonRpcClient(env.POLYGON_RPC_URL, {
      timeoutMs: env.POLYGON_RPC_TIMEOUT_MS,
    });

  const paymentService = new PaymentService(db, {
    verificationMode: env.PAYMENT_VERIFICATION_MODE,
    minConfirmations: env.POLYGON_MIN_CONFIRMATIONS,
    requireSenderWalletInLive: env.REQUIRE_SENDER_WALLET_IN_LIVE,
    rpcProvider,
    licenseService,
  });

  const adminService = new AdminService(db);
  const botRouter = new EdgeBotRouter(db, paymentService, licenseService, env.APP_URL);
  const botClient: TelegramBotTransport | undefined =
    injectedBotClient ??
    (env.TELEGRAM_BOT_TOKEN ? new TelegramBotApiClient(env.TELEGRAM_BOT_TOKEN) : undefined);

  // Bootstrap explicitly configured Super Admin Telegram ID (never a hardcoded default)
  if (env.BOOTSTRAP_SUPER_ADMIN_TELEGRAM_ID) {
    const superUser = users.upsertFromTelegram({
      telegramId: env.BOOTSTRAP_SUPER_ADMIN_TELEGRAM_ID,
      username: 'amirbtc_owner',
      firstName: 'AMIRBTC',
      languageCode: 'fa',
    });
    users.ensureAdminRole(superUser.id, superUser.telegram_id, 'super_admin');
  }

  // Sliding-window rate limiters
  const globalLimiter = createRateLimiter({
    windowMs: 60_000,
    maxRequests: 120,
    bucketName: 'api_global',
    enabled: env.RATE_LIMIT_ENABLED,
    audit,
  });
  const sensitiveWriteLimiter = createRateLimiter({
    windowMs: 60_000,
    maxRequests: 15,
    bucketName: 'api_sensitive_write',
    enabled: env.RATE_LIMIT_ENABLED,
    audit,
  });
  const gatewayLimiter = createRateLimiter({
    windowMs: 60_000,
    maxRequests: 60,
    bucketName: 'android_gateway',
    enabled: env.RATE_LIMIT_ENABLED,
    keyGenerator: (req) =>
      req.header('x-forwarded-client-ip') ?? req.ip ?? 'gateway_unknown',
    audit,
  });
  const webhookLimiter = createRateLimiter({
    windowMs: 60_000,
    maxRequests: 120,
    bucketName: 'bot_webhook',
    enabled: env.RATE_LIMIT_ENABLED,
    audit,
  });

  app.use('/api/v1', globalLimiter);

  /**
   * Idempotency Middleware backed by SQLite `idempotency_records`.
   * Activates whenever `Idempotency-Key` header is supplied on POST/PATCH routes.
   */
  const withIdempotency = (scope: string) => {
    return (req: Request, res: Response, next: NextFunction) => {
      const key = req.header('idempotency-key')?.trim();
      if (!key) {
        next();
        return;
      }
      if (key.length < 8 || key.length > 128) {
        res.status(400).json({ error: 'INVALID_IDEMPOTENCY_KEY' });
        return;
      }

      const actorId = req.authUser?.telegram_id ?? req.ip ?? 'anonymous';
      const requestHash = hashRequestPayload(req.body);

      try {
        const cached = idempotency.findResponse({ scope, key, actorId, requestHash });
        if (cached) {
          res.setHeader('X-Idempotent-Replayed', 'true');
          res.status(cached.status).json(cached.body);
          return;
        }
      } catch (err) {
        next(err);
        return;
      }

      const origJson = res.json.bind(res);
      res.json = ((body: unknown) => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          try {
            idempotency.saveResponse({
              scope,
              key,
              actorId,
              requestHash,
              status: res.statusCode,
              body,
            });
          } catch {
            // Non-fatal if response was already cached in race
          }
        }
        return origJson(body);
      }) as typeof res.json;

      next();
    };
  };

  /**
   * Authentication Middleware:
   * 1. Validates HMAC-signed short-lived Bearer Session Token (`Authorization: Bearer edge1...`).
   * 2. Validates authentic Telegram WebApp `X-Telegram-Init-Data` HMAC-SHA256.
   * 3. Preview session fallback ONLY when `NODE_ENV !== 'production'` AND `ALLOW_PHASE0_PREVIEW_SESSION=true`,
   *    and NEVER grants admin privileges (`authAdmin = null`).
   */
  const requireAuth = (req: Request, res: Response, next: NextFunction) => {
    const authHeader = req.header('authorization');
    if (authHeader && authHeader.startsWith('Bearer ')) {
      try {
        const signingKey = deriveSessionSigningKey(env.SESSION_SECRET, env.TELEGRAM_BOT_TOKEN);
        const tokenPayload = verifySessionToken(authHeader.slice(7), signingKey);
        const user = users.findByTelegramId(tokenPayload.sub);
        if (!user || user.id !== tokenPayload.uid) {
          res.status(401).json({ error: 'SESSION_USER_NOT_FOUND' });
          return;
        }
        if (user.status !== 'active') {
          res.status(403).json({ error: 'ACCOUNT_RESTRICTED', status: user.status });
          return;
        }
        req.authUser = user;
        req.authAdmin = users.findActiveAdminByTelegramId(user.telegram_id) ?? null;
        req.authMode = 'bearer_session';
        next();
        return;
      } catch (err) {
        audit.record({
          actorType: 'system',
          actorId: 'auth_guard',
          action: 'SESSION_TOKEN_INVALID',
          entityType: 'session',
          severity: 'warning',
          metadata: { reason: err instanceof Error ? err.message : 'INVALID_TOKEN' },
          ipAddress: req.ip,
        });
        res.status(401).json({ error: 'INVALID_SESSION_TOKEN' });
        return;
      }
    }

    const initData = req.header('x-telegram-init-data');
    if (initData) {
      try {
        const verified = verifyTelegramInitData(initData, env.TELEGRAM_BOT_TOKEN, {
          maxAgeSeconds: env.TELEGRAM_INIT_DATA_MAX_AGE_SECONDS,
        });
        const user = users.upsertFromTelegram({
          telegramId: String(verified.user.id),
          username: verified.user.username ?? null,
          firstName: verified.user.first_name,
          lastName: verified.user.last_name ?? null,
          languageCode: verified.user.language_code ?? 'fa',
        });

        if (user.status !== 'active') {
          res.status(403).json({ error: 'ACCOUNT_RESTRICTED', status: user.status });
          return;
        }

        req.authUser = user;
        req.authAdmin = users.findActiveAdminByTelegramId(user.telegram_id) ?? null;
        req.authMode = 'telegram_init_data';
        next();
        return;
      } catch (err) {
        audit.record({
          actorType: 'system',
          actorId: 'auth_guard',
          action: 'TELEGRAM_AUTH_FAILED',
          entityType: 'session',
          severity: 'warning',
          metadata: { reason: err instanceof Error ? err.message : 'AUTH_ERROR' },
          ipAddress: req.ip,
        });
        res.status(401).json({ error: 'INVALID_TELEGRAM_INIT_DATA' });
        return;
      }
    }

    if (env.NODE_ENV !== 'production' && env.ALLOW_PHASE0_PREVIEW_SESSION) {
      const previewUser = users.upsertFromTelegram({
        telegramId: '900000001',
        username: 'edge_preview_customer',
        firstName: 'EDGE Preview Customer',
        languageCode: 'fa',
      });
      req.authUser = previewUser;
      // SECURITY RULE: Preview session NEVER grants admin or super_admin privileges.
      req.authAdmin = null;
      req.authMode = 'phase0_preview';
      next();
      return;
    }

    res.status(401).json({ error: 'TELEGRAM_AUTH_REQUIRED' });
  };

  const requireAdminPermission = (permission: AdminPermission) => {
    return (req: Request, res: Response, next: NextFunction) => {
      const admin = req.authAdmin;
      const extra = parseExtraPermissions(admin);
      if (!admin || admin.is_active !== 1 || !hasAdminPermission(admin.role, permission, extra)) {
        audit.record({
          actorType: 'user',
          actorId: req.authUser?.telegram_id ?? 'anonymous',
          action: 'ADMIN_ACCESS_DENIED',
          entityType: 'permission',
          entityId: permission,
          severity: 'warning',
          ipAddress: req.ip,
        });
        res.status(403).json({ error: 'FORBIDDEN_ADMIN_PERMISSION', required: permission });
        return;
      }
      next();
    };
  };

  // ==================== Public System & Catalog Routes ====================
  app.get('/api/v1/health', (_req, res) => {
    const dbCheck = db.prepare('SELECT 1 AS ok').get() as { ok: number };
    const phaseRow = db
      .prepare(`SELECT value FROM system_settings WHERE key = 'system_phase'`)
      .get() as { value: string } | undefined;

    res.json({
      ok: dbCheck?.ok === 1,
      brand: `${BRAND_NAME} by ${BRAND_OWNER}`,
      phase: phaseRow?.value ?? 'PHASE_1_HARDENED',
      paymentMode: env.PAYMENT_VERIFICATION_MODE,
      licenseMode: env.LICENSE_ISSUANCE_MODE,
      botHandle: TELEGRAM_BOT_HANDLE,
      timestamp: new Date().toISOString(),
    });
  });

  app.get('/api/v1/public/config', (_req, res) => {
    const phaseRow = db
      .prepare(`SELECT value FROM system_settings WHERE key = 'system_phase'`)
      .get() as { value: string } | undefined;

    res.json({
      brandName: BRAND_NAME,
      brandOwner: BRAND_OWNER,
      botHandle: TELEGRAM_BOT_HANDLE,
      phase: phaseRow?.value ?? 'PHASE_1_HARDENED',
      paymentMode: env.PAYMENT_VERIFICATION_MODE,
      licenseMode: env.LICENSE_ISSUANCE_MODE,
      network: {
        name: PAYMENT_NETWORK.name,
        chainId: PAYMENT_NETWORK.chainId,
        currencySymbol: PAYMENT_NETWORK.currencySymbol,
        tokenStandard: PAYMENT_NETWORK.tokenStandard,
        usdcContractAddress: PAYMENT_NETWORK.usdcContractAddress,
        destinationWalletAddress: PAYMENT_NETWORK.destinationWalletAddress,
        minConfirmations: env.POLYGON_MIN_CONFIRMATIONS,
      },
      plans: plans.listActive(),
    });
  });

  // ==================== Single-Use Telegram initData -> Bearer Session Exchange ====================
  app.post('/api/v1/auth/telegram', sensitiveWriteLimiter, (req, res) => {
    const initData =
      req.header('x-telegram-init-data') ??
      (typeof (req.body as { initData?: unknown })?.initData === 'string'
        ? (req.body as { initData: string }).initData
        : '');

    try {
      const verified = verifyTelegramInitData(initData, env.TELEGRAM_BOT_TOKEN, {
        maxAgeSeconds: env.TELEGRAM_INIT_DATA_MAX_AGE_SECONDS,
      });

      // Strictly enforce single-use anti-replay on Telegram initData exchange
      const claimed = idempotency.claimOnce({
        scope: 'telegram_init_data_exchange',
        key: verified.hash,
        actorId: String(verified.user.id),
        ttlSeconds: env.TELEGRAM_INIT_DATA_MAX_AGE_SECONDS + 60,
      });

      if (!claimed) {
        audit.record({
          actorType: 'system',
          actorId: String(verified.user.id),
          action: 'TELEGRAM_INIT_DATA_REPLAY_BLOCKED',
          entityType: 'session',
          entityId: verified.hash.slice(0, 16),
          severity: 'warning',
          ipAddress: req.ip,
        });
        res.status(401).json({ error: 'TELEGRAM_INIT_DATA_REPLAYED' });
        return;
      }

      const user = users.upsertFromTelegram({
        telegramId: String(verified.user.id),
        username: verified.user.username ?? null,
        firstName: verified.user.first_name,
        lastName: verified.user.last_name ?? null,
        languageCode: verified.user.language_code ?? 'fa',
      });

      if (user.status !== 'active') {
        res.status(403).json({ error: 'ACCOUNT_RESTRICTED', status: user.status });
        return;
      }

      const signingKey = deriveSessionSigningKey(env.SESSION_SECRET, env.TELEGRAM_BOT_TOKEN);
      const { token, expiresAt } = signSessionToken(
        { telegramId: user.telegram_id, userId: user.id, ttlSeconds: env.SESSION_TTL_SECONDS },
        signingKey
      );
      const admin = users.findActiveAdminByTelegramId(user.telegram_id) ?? null;

      res.status(200).json({
        token,
        expiresAt,
        user,
        adminRole: admin?.role ?? null,
        permissions: getEffectivePermissions(admin?.role ?? null, parseExtraPermissions(admin)),
      });
    } catch (err) {
      audit.record({
        actorType: 'system',
        actorId: 'auth_exchange',
        action: 'TELEGRAM_AUTH_EXCHANGE_FAILED',
        entityType: 'session',
        severity: 'warning',
        metadata: { reason: err instanceof Error ? err.message : 'AUTH_ERROR' },
        ipAddress: req.ip,
      });
      res.status(401).json({ error: 'INVALID_TELEGRAM_INIT_DATA' });
    }
  });

  // ==================== Mini App Authenticated Routes ====================
  app.get('/api/v1/me', requireAuth, (req, res) => {
    const admin = req.authAdmin ?? null;
    const phaseRow = db
      .prepare(`SELECT value FROM system_settings WHERE key = 'system_phase'`)
      .get() as { value: string } | undefined;

    res.json({
      authenticated: true,
      authMode: req.authMode,
      phase: phaseRow?.value ?? 'PHASE_1_HARDENED',
      paymentMode: env.PAYMENT_VERIFICATION_MODE,
      licenseMode: env.LICENSE_ISSUANCE_MODE,
      user: req.authUser,
      adminRole: admin?.role ?? null,
      permissions: getEffectivePermissions(admin?.role ?? null, parseExtraPermissions(admin)),
    });
  });

  app.get('/api/v1/orders', requireAuth, (req, res) => {
    res.json({ orders: paymentService.listUserOrders(req.authUser!.id) });
  });

  const CreateOrderBody = z.object({
    planCode: z.enum(['EDGE_1M', 'EDGE_3M', 'EDGE_6M', 'EDGE_12M']),
    orderType: z.enum(['new', 'renew', 'upgrade']).optional(),
    targetSubscriptionId: z.number().int().positive().optional(),
    expectedSenderWallet: z.string().regex(/^0x[a-fA-F0-9]{40}$/).optional(),
  });

  app.post(
    '/api/v1/orders',
    requireAuth,
    sensitiveWriteLimiter,
    withIdempotency('create_order'),
    (req, res, next) => {
      try {
        const parsed = CreateOrderBody.parse(req.body);
        const order = paymentService.createOrder(req.authUser!.id, parsed.planCode, req.ip, {
          orderType: parsed.orderType,
          targetSubscriptionId: parsed.targetSubscriptionId,
          expectedSenderWallet: parsed.expectedSenderWallet,
        });
        res.status(201).json({ order });
      } catch (err) {
        next(err);
      }
    }
  );

  const SubmitTxBody = z.object({
    orderCode: z.string().min(6).max(64),
    txHash: z.string().min(66).max(66),
  });

  app.post(
    '/api/v1/payments/submit-tx',
    requireAuth,
    sensitiveWriteLimiter,
    withIdempotency('submit_tx'),
    (req, res, next) => {
      try {
        const parsed = SubmitTxBody.parse(req.body);
        const result = paymentService.submitTransactionHash({
          userId: req.authUser!.id,
          orderCode: parsed.orderCode,
          txHash: parsed.txHash,
          ipAddress: req.ip,
        });
        res.status(201).json(result);
      } catch (err) {
        next(err);
      }
    }
  );

  app.get('/api/v1/payments', requireAuth, (req, res) => {
    res.json({ payments: paymentService.listUserPayments(req.authUser!.id) });
  });

  app.get('/api/v1/licenses', requireAuth, (req, res) => {
    res.json({
      licenses: licenseService.listUserLicenses(req.authUser!.id),
      subscriptions: licenseService.listUserSubscriptions(req.authUser!.id),
    });
  });

  app.delete(
    '/api/v1/licenses/:licenseKey/devices/:fingerprint',
    requireAuth,
    sensitiveWriteLimiter,
    (req, res, next) => {
      try {
        const result = licenseService.unbindDevice({
          licenseKey: String(req.params.licenseKey),
          deviceFingerprint: String(req.params.fingerprint),
          actorType: 'user',
          actorId: req.authUser!.telegram_id,
          requesterUserId: req.authUser!.id,
        });
        res.json(result);
      } catch (err) {
        next(err);
      }
    }
  );

  // User Support Tickets & Notifications
  app.get('/api/v1/support/tickets', requireAuth, (req, res) => {
    res.json({ tickets: supportService.listUserTickets(req.authUser!.id) });
  });

  app.post(
    '/api/v1/support/tickets',
    requireAuth,
    sensitiveWriteLimiter,
    withIdempotency('create_ticket'),
    (req, res, next) => {
      try {
        const body = z
          .object({
            subject: z.string().min(3).max(120),
            message: z.string().min(5).max(2000),
            orderId: z.number().int().positive().optional(),
            priority: z.enum(['low', 'normal', 'high', 'urgent']).optional(),
          })
          .parse(req.body);
        const ticket = supportService.createTicket({
          userId: req.authUser!.id,
          actorId: req.authUser!.telegram_id,
          subject: body.subject,
          message: body.message,
          orderId: body.orderId,
          priority: body.priority,
        });
        res.status(201).json({ ticket });
      } catch (err) {
        next(err);
      }
    }
  );

  app.get('/api/v1/notifications', requireAuth, (req, res) => {
    res.json({ notifications: supportService.listUserNotifications(req.authUser!.id) });
  });

  // ==================== Telegram Bot Webhook (Fail-Closed + Deduplicated) ====================
  app.post(
    '/api/v1/bot/webhook',
    webhookLimiter,
    createTelegramWebhookHandler({
      botRouter,
      webhookSecret: env.TELEGRAM_WEBHOOK_SECRET,
      idempotency,
      audit,
      botClient,
      sendRepliesViaApi: env.TELEGRAM_BOT_SEND_ENABLED || Boolean(injectedBotClient),
    })
  );

  // ==================== Cloudflare Worker -> Backend Android Gateway (Fail-Closed) ====================
  const GatewayValidateBody = z.object({
    licenseKey: z.string().min(10).max(64),
    deviceFingerprint: z.string().min(8).max(128),
    deviceModel: z.string().max(120).optional(),
    androidVersion: z.string().max(32).optional(),
    appVersion: z.string().max(32).optional(),
  });

  app.post('/api/v1/gateway/validate', gatewayLimiter, (req, res, next) => {
    try {
      // Fail-closed: refuse requests if GATEWAY_SHARED_SECRET is unset
      if (!env.GATEWAY_SHARED_SECRET || !env.GATEWAY_SHARED_SECRET.trim()) {
        audit.record({
          actorType: 'system',
          actorId: 'android_gateway',
          action: 'GATEWAY_SECRET_MISSING_BLOCKED',
          entityType: 'security',
          severity: 'critical',
          ipAddress: req.ip,
        });
        res.status(503).json({ error: 'GATEWAY_SECRET_NOT_CONFIGURED' });
        return;
      }

      const provided = req.header('x-edge-gateway-secret') ?? '';
      const a = Buffer.from(provided, 'utf8');
      const b = Buffer.from(env.GATEWAY_SHARED_SECRET, 'utf8');
      if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
        audit.record({
          actorType: 'gateway',
          actorId: req.ip ?? 'unknown',
          action: 'GATEWAY_INVALID_SECRET',
          entityType: 'security',
          severity: 'warning',
          ipAddress: req.ip,
        });
        res.status(401).json({ error: 'INVALID_GATEWAY_SECRET' });
        return;
      }

      // If timestamped HMAC headers are sent by Cloudflare Worker, verify strictly
      const edgeTs = req.header('x-edge-timestamp');
      const edgeSig = req.header('x-edge-signature');
      if (edgeTs || edgeSig) {
        const tsNum = Number(edgeTs);
        const nowSec = Math.floor(Date.now() / 1000);
        if (!Number.isInteger(tsNum) || Math.abs(nowSec - tsNum) > 60 || !edgeSig) {
          res.status(401).json({ error: 'INVALID_GATEWAY_TIMESTAMP' });
          return;
        }
        const expectedSig = crypto
          .createHmac('sha256', env.GATEWAY_SHARED_SECRET)
          .update(`${edgeTs}.${req.rawBody ?? JSON.stringify(req.body)}`)
          .digest('hex');
        const sigA = Buffer.from(edgeSig.toLowerCase(), 'utf8');
        const sigB = Buffer.from(expectedSig.toLowerCase(), 'utf8');
        if (sigA.length !== sigB.length || !crypto.timingSafeEqual(sigA, sigB)) {
          res.status(401).json({ error: 'INVALID_GATEWAY_SIGNATURE' });
          return;
        }
      }

      const parsed = GatewayValidateBody.parse(req.body);
      const outcome = licenseService.validateForAndroid({
        ...parsed,
        ipAddress: req.header('x-forwarded-client-ip') ?? req.ip,
      });
      res.json(outcome);
    } catch (err) {
      next(err);
    }
  });

  // ==================== Restricted RBAC Admin Panel Routes ====================
  app.get('/api/v1/admin/dashboard', requireAuth, requireAdminPermission('dashboard:read'), (_req, res) => {
    res.json({ summary: adminService.getDashboardSummary() });
  });

  app.get('/api/v1/admin/users', requireAuth, requireAdminPermission('users:read'), (req, res) => {
    const limit = Math.min(200, Math.max(1, Number(req.query.limit ?? 100)));
    const offset = Math.max(0, Number(req.query.offset ?? 0));
    res.json({ users: adminService.listUsers(limit, offset) });
  });

  app.patch(
    '/api/v1/admin/users/:id/status',
    requireAuth,
    requireAdminPermission('users:write'),
    (req, res, next) => {
      try {
        const userId = Number(req.params.id);
        const body = z.object({ status: z.enum(['active', 'suspended', 'banned']) }).parse(req.body);
        const updated = adminService.updateUserStatus(
          userId,
          body.status,
          req.authUser!.telegram_id
        );
        res.json({ user: updated });
      } catch (err) {
        next(err);
      }
    }
  );

  app.get('/api/v1/admin/orders', requireAuth, requireAdminPermission('orders:read'), (req, res) => {
    const limit = Math.min(200, Math.max(1, Number(req.query.limit ?? 100)));
    const offset = Math.max(0, Number(req.query.offset ?? 0));
    res.json({ orders: adminService.listOrders(limit, offset) });
  });

  app.patch(
    '/api/v1/admin/orders/:orderCode/status',
    requireAuth,
    requireAdminPermission('orders:write'),
    (req, res, next) => {
      try {
        const body = z
          .object({
            status: z.enum(['cancelled', 'rejected', 'expired']),
            reason: z.string().min(3).max(240),
          })
          .parse(req.body);
        const order = adminService.updateOrderStatus({
          orderCode: String(req.params.orderCode),
          status: body.status,
          reason: body.reason,
          adminActorId: req.authUser!.telegram_id,
        });
        res.json({ order });
      } catch (err) {
        next(err);
      }
    }
  );

  app.get('/api/v1/admin/payments', requireAuth, requireAdminPermission('payments:read'), (req, res) => {
    const limit = Math.min(200, Math.max(1, Number(req.query.limit ?? 100)));
    const offset = Math.max(0, Number(req.query.offset ?? 0));
    res.json({ payments: adminService.listPayments(limit, offset) });
  });

  app.post(
    '/api/v1/admin/payments/:paymentId/verify',
    requireAuth,
    requireAdminPermission('payments:verify'),
    async (req, res, next) => {
      try {
        const paymentId = Number(req.params.paymentId);
        const result = await paymentService.verifyPaymentOnChain(paymentId, {
          actorId: req.authUser!.telegram_id,
        });
        res.json(result);
      } catch (err) {
        next(err);
      }
    }
  );

  app.get(
    '/api/v1/admin/subscriptions',
    requireAuth,
    requireAdminPermission('subscriptions:read'),
    (_req, res) => {
      res.json({ subscriptions: adminService.listSubscriptions() });
    }
  );

  app.get('/api/v1/admin/licenses', requireAuth, requireAdminPermission('licenses:read'), (_req, res) => {
    res.json({ licenses: adminService.listLicenses() });
  });

  app.get(
    '/api/v1/admin/licenses/:licenseKey/history',
    requireAuth,
    requireAdminPermission('licenses:read'),
    (req, res, next) => {
      try {
        res.json({ history: licenseService.listLicenseHistory(String(req.params.licenseKey)) });
      } catch (err) {
        next(err);
      }
    }
  );

  app.patch(
    '/api/v1/admin/licenses/:licenseKey/status',
    requireAuth,
    requireAdminPermission('licenses:write'),
    (req, res, next) => {
      try {
        const body = z
          .object({
            status: z.enum(['active', 'revoked', 'blocked']),
            reason: z.string().min(3).max(240),
          })
          .parse(req.body);
        const updated = licenseService.updateLicenseStatus({
          licenseKey: String(req.params.licenseKey),
          status: body.status,
          reason: body.reason,
          adminActorId: req.authUser!.telegram_id,
        });
        res.json({ license: updated });
      } catch (err) {
        next(err);
      }
    }
  );

  app.delete(
    '/api/v1/admin/licenses/:licenseKey/devices/:fingerprint',
    requireAuth,
    requireAdminPermission('licenses:write'),
    (req, res, next) => {
      try {
        const result = licenseService.unbindDevice({
          licenseKey: String(req.params.licenseKey),
          deviceFingerprint: String(req.params.fingerprint),
          actorType: 'admin',
          actorId: req.authUser!.telegram_id,
        });
        res.json(result);
      } catch (err) {
        next(err);
      }
    }
  );

  app.get('/api/v1/admin/plans', requireAuth, requireAdminPermission('plans:read'), (_req, res) => {
    res.json({ plans: adminService.listPlans() });
  });

  app.patch(
    '/api/v1/admin/plans/:code',
    requireAuth,
    requireAdminPermission('plans:write'),
    (req, res, next) => {
      try {
        const body = z
          .object({
            isActive: z.boolean().optional(),
            maxDevices: z.number().int().min(1).max(10).optional(),
          })
          .parse(req.body);
        const plan = adminService.updatePlanControls({
          code: String(req.params.code),
          isActive: body.isActive,
          maxDevices: body.maxDevices,
          adminActorId: req.authUser!.telegram_id,
        });
        res.json({ plan });
      } catch (err) {
        next(err);
      }
    }
  );

  app.get(
    '/api/v1/admin/reports/finance',
    requireAuth,
    requireAdminPermission('reports:finance'),
    (req, res) => {
      const fromIso = typeof req.query.from === 'string' ? req.query.from : undefined;
      const toIso = typeof req.query.to === 'string' ? req.query.to : undefined;
      res.json(adminService.getFinancialReport({ fromIso, toIso }));
    }
  );

  app.get(
    '/api/v1/admin/reports/security',
    requireAuth,
    requireAdminPermission('reports:security'),
    (req, res) => {
      const severity =
        req.query.severity === 'info' ||
        req.query.severity === 'warning' ||
        req.query.severity === 'critical'
          ? req.query.severity
          : undefined;
      res.json({ auditLogs: adminService.listAuditLogs(100, severity) });
    }
  );

  app.get('/api/v1/admin/tickets', requireAuth, requireAdminPermission('users:read'), (_req, res) => {
    res.json({ tickets: supportService.listAllTickets(100) });
  });

  app.patch(
    '/api/v1/admin/tickets/:id',
    requireAuth,
    requireAdminPermission('users:write'),
    (req, res, next) => {
      try {
        const body = z
          .object({
            status: z.enum(['open', 'in_progress', 'resolved', 'closed']),
            adminReply: z.string().min(1).max(2000).optional(),
          })
          .parse(req.body);
        const ticket = supportService.replyAndUpdateTicket({
          ticketId: Number(req.params.id),
          status: body.status,
          adminReply: body.adminReply,
          adminId: req.authAdmin!.id,
          adminActorId: req.authUser!.telegram_id,
        });
        res.json({ ticket });
      } catch (err) {
        next(err);
      }
    }
  );

  app.get('/api/v1/admin/admins', requireAuth, requireAdminPermission('admins:read'), (_req, res) => {
    res.json({ admins: adminService.listAdmins(), settings: adminService.listSettings() });
  });

  app.post(
    '/api/v1/admin/admins',
    requireAuth,
    requireAdminPermission('admins:write'),
    withIdempotency('assign_admin'),
    (req, res, next) => {
      try {
        const body = z
          .object({
            telegramId: z.string().regex(/^\d{5,20}$/),
            role: z.enum(['super_admin', 'admin', 'finance', 'support', 'auditor']),
          })
          .parse(req.body);

        const assigned = adminService.assignAdminRole({
          telegramId: body.telegramId,
          role: body.role as AdminRole,
          grantedByAdminId: req.authAdmin!.id,
          actorId: req.authUser!.telegram_id,
        });
        res.status(201).json({ admin: assigned });
      } catch (err) {
        next(err);
      }
    }
  );

  app.patch(
    '/api/v1/admin/admins/:id/deactivate',
    requireAuth,
    requireAdminPermission('admins:write'),
    (req, res, next) => {
      try {
        const admin = adminService.deactivateAdmin({
          adminId: Number(req.params.id),
          actorId: req.authUser!.telegram_id,
        });
        res.json({ admin });
      } catch (err) {
        next(err);
      }
    }
  );

  app.patch(
    '/api/v1/admin/settings/:key',
    requireAuth,
    requireAdminPermission('settings:write'),
    (req, res, next) => {
      try {
        const body = z.object({ value: z.string().min(1).max(500) }).parse(req.body);
        const setting = adminService.updateSetting({
          key: String(req.params.key),
          value: body.value,
          adminActorId: req.authUser!.telegram_id,
        });
        res.json({ setting });
      } catch (err) {
        next(err);
      }
    }
  );

  // ==================== Centralized Sanitized Error Handler ====================
  app.use((err: unknown, req: Request, res: Response, _next: NextFunction) => {
    if (err instanceof z.ZodError) {
      res.status(400).json({ error: 'VALIDATION_ERROR', issues: err.issues });
      return;
    }
    if (
      err instanceof PaymentError ||
      err instanceof LicenseError ||
      err instanceof AdminOperationError ||
      err instanceof IdempotencyError
    ) {
      res.status(err.statusCode).json({ error: err.code, message: err.message });
      return;
    }

    if (err instanceof Error && err.message === 'TICKET_NOT_FOUND') {
      res.status(404).json({ error: 'TICKET_NOT_FOUND' });
      return;
    }

    // Never leak internal Error messages, SQLite details, or stack traces to API clients
    const requestId = crypto.randomBytes(6).toString('hex');
    audit.record({
      actorType: 'system',
      actorId: 'error_handler',
      action: 'UNHANDLED_SERVER_ERROR',
      entityType: 'http_request',
      entityId: requestId,
      severity: 'critical',
      metadata: {
        path: req.path,
        method: req.method,
        errorName: err instanceof Error ? err.name : 'UnknownError',
      },
      ipAddress: req.ip,
    });
    res.status(500).json({ error: 'INTERNAL_SERVER_ERROR', requestId });
  });

  return app;
}
