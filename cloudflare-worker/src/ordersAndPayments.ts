/**
 * Path B-1 Authoritative D1 Order, Payment & License Lifecycle Engine
 * Enforces:
 * - Atomic D1 `DB.batch()` financial/license commits
 * - Unique micro-offset anti-front-running
 * - DB-level TxHash anti-replay & TxID squatting cleanup
 * - Strict DRY_RUN settlement & issuance guards
 * - Renewal never reactivates revoked/blocked licenses or suspended/banned users
 */

import { randomHex, sha256Hex, signRsaSha256 } from './crypto';
import { DOMAIN_CONSTANTS, type D1Database, type WorkerEnv } from './d1Types';
import {
  isValidEvmAddress,
  isValidPolygonTxHash,
  normalizeEvmAddress,
  normalizeTxHash,
  verifyPolygonUsdcReceipt,
  WorkerPolygonRpcClient,
  type PolygonRpcProvider,
  type PolygonVerificationResult,
} from './polygon';

export class DomainError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly statusCode = 400
  ) {
    super(message);
    this.name = 'DomainError';
  }
}

export interface D1UserRow {
  id: number;
  telegram_id: string;
  username: string | null;
  first_name: string;
  last_name: string | null;
  language_code: string;
  status: 'active' | 'suspended' | 'banned';
  created_at: string;
  updated_at: string;
  last_seen_at: string | null;
}

export interface D1AdminRow {
  id: number;
  user_id: number;
  telegram_id: string;
  role: 'super_admin' | 'admin' | 'finance' | 'support' | 'auditor';
  permissions_json: string;
  is_active: number;
  granted_by: number | null;
  created_at: string;
  updated_at: string;
}

export interface D1PlanRow {
  id: number;
  code: string;
  name_en: string;
  name_fa: string;
  duration_months: number;
  duration_days: number;
  price_usdc_micro: number;
  price_usd_display: string;
  max_devices: number;
  is_active: number;
  sort_order: number;
}

export interface D1OrderRow {
  id: number;
  order_code: string;
  user_id: number;
  plan_id: number;
  order_type: 'new' | 'renew' | 'upgrade';
  target_subscription_id: number | null;
  expected_amount_usdc_micro: number;
  unique_offset_micro: number;
  payable_amount_usdc_micro: number;
  expected_amount_usd: string;
  expected_sender_wallet: string | null;
  network: string;
  token_contract: string;
  destination_wallet: string;
  status: string;
  expires_at: string;
  created_at: string;
  updated_at: string;
  plan_code?: string;
  plan_name_en?: string;
  plan_name_fa?: string;
}

export interface D1PaymentRow {
  id: number;
  order_id: number;
  user_id: number;
  tx_hash: string;
  network: string;
  token_contract: string;
  sender_address: string | null;
  receiver_address: string;
  amount_usdc_micro: number;
  block_number: number | null;
  confirmations: number;
  status: string;
  verification_note: string | null;
  verified_at: string | null;
  created_at: string;
  updated_at: string;
  order_code?: string;
}

export function formatMicroUsdc(micro: number): string {
  const whole = Math.floor(micro / 1_000_000);
  const frac = String(micro % 1_000_000).padStart(6, '0');
  return `${whole}.${frac}`;
}

export async function recordAuditLog(
  db: D1Database,
  entry: {
    actorType: 'user' | 'admin' | 'system' | 'bot' | 'gateway' | 'cron';
    actorId: string;
    action: string;
    entityType: string;
    entityId?: string | null;
    severity?: 'info' | 'warning' | 'critical';
    metadata?: Record<string, unknown>;
    ipAddress?: string | null;
  }
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO audit_logs (actor_type, actor_id, action, entity_type, entity_id, severity, metadata_json, ip_address)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      entry.actorType,
      entry.actorId,
      entry.action,
      entry.entityType,
      entry.entityId ?? null,
      entry.severity ?? 'info',
      JSON.stringify(entry.metadata ?? {}),
      entry.ipAddress ?? null
    )
    .run();
}

export async function recordSecurityEvent(
  db: D1Database,
  event: {
    eventType:
      | 'ECDSA_INVALID'
      | 'REPLAY_NONCE'
      | 'TIMESTAMP_SKEW'
      | 'CLOCK_ROLLBACK'
      | 'LOCAL_TAMPER'
      | 'SIGNATURE_MISMATCH'
      | 'DEVICE_LIMIT_ABUSE'
      | 'DEVICE_CHURN'
      | 'RATE_LIMITED'
      | 'UNAUTHORIZED_ADMIN'
      | 'WEBHOOK_AUTH_FAILED'
      | 'INIT_DATA_REPLAY'
      | 'INVALID_TX_ATTEMPT';
    severity?: 'low' | 'medium' | 'high' | 'critical';
    userId?: number | null;
    licenseKey?: string | null;
    deviceKeyId?: string | null;
    ipAddress?: string | null;
    details?: Record<string, unknown>;
    source?: string;
  }
): Promise<void> {
  const ipHash = event.ipAddress ? (await sha256Hex(event.ipAddress)).slice(0, 16) : null;
  await db
    .prepare(
      `INSERT INTO security_events (event_type, severity, user_id, license_key, device_key_id, ip_hash, details_json, source)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      event.eventType,
      event.severity ?? 'medium',
      event.userId ?? null,
      event.licenseKey ?? null,
      event.deviceKeyId ?? null,
      ipHash,
      JSON.stringify(event.details ?? {}),
      event.source ?? 'worker_gateway'
    )
    .run();
}

export async function claimSingleUseKey(
  db: D1Database,
  params: { scope: string; key: string; actorId: string; ttlSeconds: number }
): Promise<boolean> {
  const nowIso = new Date().toISOString();
  const expiresIso = new Date(Date.now() + params.ttlSeconds * 1000).toISOString();

  await db
    .prepare(`DELETE FROM idempotency_records WHERE scope = ? AND idempotency_key = ? AND expires_at <= ?`)
    .bind(params.scope, params.key, nowIso)
    .run();

  const res = await db
    .prepare(
      `INSERT OR IGNORE INTO idempotency_records (
         scope, idempotency_key, actor_id, request_hash, response_status, response_body_json, expires_at
       ) VALUES (?, ?, ?, 'once', 200, '{}', ?)`
    )
    .bind(params.scope, params.key, params.actorId, expiresIso)
    .run();

  return (res.meta?.changes ?? 0) === 1;
}

export async function upsertUserFromTelegram(
  db: D1Database,
  tgUser: {
    telegramId: string;
    username?: string | null;
    firstName: string;
    lastName?: string | null;
    languageCode?: string;
  }
): Promise<D1UserRow> {
  const nowIso = new Date().toISOString();
  await db
    .prepare(
      `INSERT INTO users (telegram_id, username, first_name, last_name, language_code, last_seen_at)
       VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT(telegram_id) DO UPDATE SET
         username = COALESCE(excluded.username, users.username),
         first_name = excluded.first_name,
         last_name = COALESCE(excluded.last_name, users.last_name),
         language_code = COALESCE(excluded.language_code, users.language_code),
         last_seen_at = excluded.last_seen_at,
         updated_at = excluded.last_seen_at`
    )
    .bind(
      tgUser.telegramId,
      tgUser.username ?? null,
      tgUser.firstName,
      tgUser.lastName ?? null,
      tgUser.languageCode ?? 'fa',
      nowIso
    )
    .run();

  const user = await db
    .prepare(`SELECT * FROM users WHERE telegram_id = ?`)
    .bind(tgUser.telegramId)
    .first<D1UserRow>();
  if (!user) throw new DomainError('USER_UPSERT_FAILED', 'Failed to persist user.', 500);
  return user;
}

export async function ensureSuperAdminBootstrap(db: D1Database, env: WorkerEnv): Promise<void> {
  const id = env.BOOTSTRAP_SUPER_ADMIN_TELEGRAM_ID?.trim();
  if (!id) return;
  const user = await upsertUserFromTelegram(db, {
    telegramId: id,
    username: 'amirbtc_owner',
    firstName: 'AMIRBTC',
    languageCode: 'fa',
  });
  await db
    .prepare(
      `INSERT INTO admins (user_id, telegram_id, role, is_active)
       VALUES (?, ?, 'super_admin', 1)
       ON CONFLICT(user_id) DO UPDATE SET role = 'super_admin', is_active = 1, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')`
    )
    .bind(user.id, user.telegram_id)
    .run();
}

export async function createOrderD1(
  db: D1Database,
  env: WorkerEnv,
  params: {
    userId: number;
    planCode: string;
    orderType?: 'new' | 'renew' | 'upgrade';
    targetSubscriptionId?: number | null;
    expectedSenderWallet?: string | null;
    ipAddress?: string | null;
  }
): Promise<D1OrderRow> {
  const user = await db.prepare(`SELECT * FROM users WHERE id = ?`).bind(params.userId).first<D1UserRow>();
  if (!user || user.status !== 'active') {
    throw new DomainError('ACCOUNT_RESTRICTED', 'User account is restricted or missing.', 403);
  }

  const plan = await db
    .prepare(`SELECT * FROM plans WHERE code = ? AND is_active = 1`)
    .bind(params.planCode)
    .first<D1PlanRow>();
  if (!plan) {
    throw new DomainError('PLAN_NOT_FOUND', 'Selected plan is unavailable or inactive.', 404);
  }

  const isLive = (env.PAYMENT_VERIFICATION_MODE ?? 'DRY_RUN') === 'LIVE';
  let normalizedSenderWallet: string | null = null;
  if (params.expectedSenderWallet) {
    if (!isValidEvmAddress(params.expectedSenderWallet)) {
      throw new DomainError('INVALID_SENDER_WALLET', 'Invalid Polygon wallet address.', 400);
    }
    normalizedSenderWallet = normalizeEvmAddress(params.expectedSenderWallet);
  } else if (isLive) {
    throw new DomainError(
      'SENDER_WALLET_REQUIRED_IN_LIVE',
      'Expected sender Polygon wallet (0x...) is required in LIVE mode.',
      400
    );
  }

  const orderType = params.orderType ?? 'new';
  const nowIso = new Date().toISOString();

  // Expire overdue open orders first
  await db
    .prepare(
      `UPDATE orders SET status = 'expired', updated_at = ?
       WHERE status IN ('draft_phase0', 'pending_payment') AND expires_at <= ?`
    )
    .bind(nowIso, nowIso)
    .run();

  if (params.targetSubscriptionId) {
    const sub = await db
      .prepare(`SELECT id, user_id, status FROM subscriptions WHERE id = ?`)
      .bind(params.targetSubscriptionId)
      .first<{ id: number; user_id: number; status: string }>();
    if (!sub || sub.user_id !== params.userId) {
      throw new DomainError('TARGET_SUBSCRIPTION_NOT_FOUND', 'Target subscription not found.', 404);
    }
    if (sub.status === 'revoked' || sub.status === 'suspended') {
      throw new DomainError(
        'CANNOT_RENEW_REVOKED_SUBSCRIPTION',
        'Revoked or suspended subscriptions cannot be renewed without admin authorization.',
        403
      );
    }
    const lic = await db
      .prepare(`SELECT status FROM licenses WHERE subscription_id = ?`)
      .bind(sub.id)
      .first<{ status: string }>();
    if (lic && (lic.status === 'revoked' || lic.status === 'blocked')) {
      throw new DomainError(
        'CANNOT_RENEW_REVOKED_LICENSE',
        'Revoked or blocked licenses cannot be renewed without explicit admin reactivation.',
        403
      );
    }
  }

  const openCntRow = await db
    .prepare(
      `SELECT COUNT(*) AS cnt FROM orders
       WHERE user_id = ? AND status IN ('draft_phase0', 'pending_payment', 'tx_submitted', 'verifying')`
    )
    .bind(params.userId)
    .first<{ cnt: number }>();
  if ((openCntRow?.cnt ?? 0) >= 10) {
    throw new DomainError('TOO_MANY_OPEN_ORDERS', 'Too many open orders for this user.', 429);
  }

  const cooldownIso = new Date(Date.now() - 10 * 60 * 1000).toISOString();
  const activeAmountsRes = await db
    .prepare(
      `SELECT payable_amount_usdc_micro FROM orders
       WHERE status IN ('draft_phase0', 'pending_payment', 'tx_submitted', 'verifying')
          OR (status IN ('expired', 'rejected', 'cancelled') AND updated_at >= ?)`
    )
    .bind(cooldownIso)
    .all<{ payable_amount_usdc_micro: number }>();
  const used = new Set((activeAmountsRes.results ?? []).map((r) => r.payable_amount_usdc_micro));

  const randomSeed = new Uint16Array(1);
  crypto.getRandomValues(randomSeed);
  const startOffset = (randomSeed[0] % 999) + 1;

  // Retry loop against partial unique index `idx_orders_active_payable_amount` under concurrency
  const expiresAt = new Date(
    Date.now() + DOMAIN_CONSTANTS.orderExpiryMinutes * 60 * 1000
  ).toISOString();
  const initialStatus = isLive ? 'pending_payment' : 'draft_phase0';

  for (let i = 0; i < 999; i++) {
    const offset = ((startOffset - 1 + i) % 999) + 1;
    const payableMicro = plan.price_usdc_micro + offset;
    if (used.has(payableMicro)) continue;

    const orderCode = `EDGE-${Date.now().toString(36).toUpperCase()}-${randomHex(3).toUpperCase()}`;
    try {
      await db.batch([
        db
          .prepare(
            `INSERT INTO orders (
               order_code, user_id, plan_id, order_type, target_subscription_id,
               expected_amount_usdc_micro, unique_offset_micro, payable_amount_usdc_micro,
               expected_amount_usd, expected_sender_wallet, network, token_contract,
               destination_wallet, status, expires_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'polygon_pos', ?, ?, ?, ?)`
          )
          .bind(
            orderCode,
            params.userId,
            plan.id,
            orderType,
            params.targetSubscriptionId ?? null,
            plan.price_usdc_micro,
            offset,
            payableMicro,
            plan.price_usd_display,
            normalizedSenderWallet,
            DOMAIN_CONSTANTS.usdcContractAddress,
            DOMAIN_CONSTANTS.destinationWalletAddress,
            initialStatus,
            expiresAt
          ),
        db
          .prepare(
            `INSERT INTO audit_logs (actor_type, actor_id, action, entity_type, entity_id, severity, metadata_json, ip_address)
             VALUES ('user', ?, 'ORDER_CREATED', 'order', ?, 'info', ?, ?)`
          )
          .bind(
            String(params.userId),
            orderCode,
            JSON.stringify({
              planCode: plan.code,
              orderType,
              payableAmountUsdcMicro: payableMicro,
              uniqueOffsetMicro: offset,
              mode: isLive ? 'LIVE' : 'DRY_RUN',
            }),
            params.ipAddress ?? null
          ),
      ]);

      const created = await db
        .prepare(
          `SELECT o.*, p.code AS plan_code, p.name_en AS plan_name_en, p.name_fa AS plan_name_fa
           FROM orders o JOIN plans p ON p.id = o.plan_id WHERE o.order_code = ?`
        )
        .bind(orderCode)
        .first<D1OrderRow>();
      if (created) return created;
    } catch (err) {
      const msg = err instanceof Error ? err.message : '';
      if (msg.includes('UNIQUE') && msg.includes('payable_amount_usdc_micro')) {
        used.add(payableMicro);
        continue;
      }
      throw err;
    }
  }

  throw new DomainError('ORDER_SLOT_EXHAUSTED', 'Concurrent open order slots exhausted.', 503);
}

export async function submitTransactionHashD1(
  db: D1Database,
  env: WorkerEnv,
  params: {
    userId: number;
    orderCode: string;
    txHash: string;
    ipAddress?: string | null;
    nowIso?: string;
  }
): Promise<{ payment: D1PaymentRow; order: D1OrderRow; dryRunBlocked: boolean }> {
  const normalizedHash = normalizeTxHash(params.txHash);
  if (!isValidPolygonTxHash(normalizedHash)) {
    throw new DomainError(
      'INVALID_TX_HASH',
      'Transaction hash must be a valid 66-char Polygon PoS hex string.',
      400
    );
  }

  const order = await db
    .prepare(`SELECT * FROM orders WHERE order_code = ?`)
    .bind(params.orderCode)
    .first<D1OrderRow>();
  if (!order || order.user_id !== params.userId) {
    throw new DomainError('ORDER_NOT_FOUND', 'Order not found for this account.', 404);
  }
  if (['confirmed', 'cancelled', 'expired', 'rejected'].includes(order.status)) {
    throw new DomainError('ORDER_NOT_PAYABLE', `Order is terminal (${order.status}).`, 409);
  }

  const nowIso = params.nowIso ?? new Date().toISOString();
  if (new Date(order.expires_at).getTime() <= new Date(nowIso).getTime()) {
    await db.batch([
      db
        .prepare(`UPDATE orders SET status = 'expired', updated_at = ? WHERE id = ?`)
        .bind(nowIso, order.id),
      db
        .prepare(
          `INSERT INTO audit_logs (actor_type, actor_id, action, entity_type, entity_id, severity)
           VALUES ('user', ?, 'EXPIRED_ORDER_PAYMENT_REJECTED', 'order', ?, 'warning')`
        )
        .bind(String(params.userId), order.order_code),
    ]);
    throw new DomainError('ORDER_EXPIRED', 'Order has expired.', 409);
  }

  const isDryRun = (env.PAYMENT_VERIFICATION_MODE ?? 'DRY_RUN') !== 'LIVE';
  const paymentStatus = isDryRun ? 'dry_run_recorded' : 'submitted';
  const nextOrderStatus = isDryRun ? 'draft_phase0' : 'tx_submitted';
  const note = isDryRun
    ? 'DRY_RUN: TxID syntax, expiry, and anti-replay validated; live Polygon settlement disabled.'
    : 'Queued for Polygon PoS Native USDC receipt verification.';

  try {
    await db.batch([
      db
        .prepare(
          `INSERT INTO payments (
             order_id, user_id, tx_hash, network, token_contract, receiver_address,
             amount_usdc_micro, status, verification_note
           ) VALUES (?, ?, ?, 'polygon_pos', ?, ?, ?, ?, ?)`
        )
        .bind(
          order.id,
          params.userId,
          normalizedHash,
          DOMAIN_CONSTANTS.usdcContractAddress,
          DOMAIN_CONSTANTS.destinationWalletAddress,
          order.payable_amount_usdc_micro,
          paymentStatus,
          note
        ),
      db
        .prepare(
          `UPDATE orders SET status = ?, updated_at = ?
           WHERE id = ? AND status IN ('draft_phase0', 'pending_payment')`
        )
        .bind(nextOrderStatus, nowIso, order.id),
      db
        .prepare(
          `INSERT INTO audit_logs (actor_type, actor_id, action, entity_type, entity_id, severity, metadata_json, ip_address)
           VALUES ('user', ?, ?, 'payment', ?, 'info', ?, ?)`
        )
        .bind(
          String(params.userId),
          isDryRun ? 'TX_SUBMITTED_DRY_RUN' : 'TX_SUBMITTED',
          normalizedHash,
          JSON.stringify({ orderCode: order.order_code, isDryRun }),
          params.ipAddress ?? null
        ),
    ]);
  } catch (err) {
    const msg = err instanceof Error ? err.message : '';
    if (msg.includes('UNIQUE')) {
      const existingOnOrder = await db
        .prepare(
          `SELECT id FROM payments WHERE order_id = ? AND status IN ('submitted', 'dry_run_recorded', 'verifying', 'confirmed')`
        )
        .bind(order.id)
        .first<{ id: number }>();
      if (existingOnOrder) {
        throw new DomainError(
          'ORDER_ALREADY_HAS_ACTIVE_PAYMENT',
          'An active transaction is already linked to this order.',
          409
        );
      }
      await recordSecurityEvent(db, {
        eventType: 'INVALID_TX_ATTEMPT',
        severity: 'medium',
        userId: params.userId,
        ipAddress: params.ipAddress,
        details: { reason: 'DUPLICATE_TX_HASH', orderCode: order.order_code, txHash: normalizedHash },
      });
      throw new DomainError(
        'DUPLICATE_TX_HASH',
        'This transaction hash has already been submitted and cannot be reused.',
        409
      );
    }
    throw err;
  }

  const payment = await db
    .prepare(`SELECT * FROM payments WHERE tx_hash = ? COLLATE NOCASE`)
    .bind(normalizedHash)
    .first<D1PaymentRow>();
  const updatedOrder = await db
    .prepare(`SELECT * FROM orders WHERE id = ?`)
    .bind(order.id)
    .first<D1OrderRow>();

  return { payment: payment!, order: updatedOrder!, dryRunBlocked: isDryRun };
}

export async function verifyPaymentOnChainD1(
  db: D1Database,
  env: WorkerEnv,
  paymentId: number,
  options?: { rpcProvider?: PolygonRpcProvider; actorId?: string }
): Promise<{
  payment: D1PaymentRow;
  order: D1OrderRow;
  verification: PolygonVerificationResult;
  licenseKey?: string;
}> {
  if ((env.PAYMENT_VERIFICATION_MODE ?? 'DRY_RUN') !== 'LIVE') {
    throw new DomainError(
      'DRY_RUN_VERIFICATION_BLOCKED',
      'Live Polygon PoS settlement is disabled in DRY_RUN mode.',
      403
    );
  }
  if ((env.LICENSE_ISSUANCE_MODE ?? 'DRY_RUN') !== 'LIVE') {
    throw new DomainError(
      'PHASE0_ISSUANCE_BLOCKED',
      'Live license issuance is disabled in DRY_RUN mode.',
      403
    );
  }
  if (!env.RSA_PRIVATE_KEY_PEM || !env.RSA_PRIVATE_KEY_PEM.includes('PRIVATE KEY')) {
    throw new DomainError('RSA_KEY_MISSING', 'RSA private signing key is not configured.', 500);
  }

  const rpc =
    options?.rpcProvider ??
    (env.POLYGON_RPC_URL
      ? new WorkerPolygonRpcClient(env.POLYGON_RPC_URL, env.FETCH_IMPL ?? fetch)
      : null);
  if (!rpc) {
    throw new DomainError('RPC_PROVIDER_NOT_CONFIGURED', 'Polygon RPC URL not configured.', 503);
  }

  const existing = await db.prepare(`SELECT * FROM payments WHERE id = ?`).bind(paymentId).first<D1PaymentRow>();
  if (!existing) throw new DomainError('PAYMENT_NOT_FOUND', 'Payment not found.', 404);
  const order = await db.prepare(`SELECT * FROM orders WHERE id = ?`).bind(existing.order_id).first<D1OrderRow>();
  if (!order) throw new DomainError('ORDER_NOT_FOUND', 'Associated order not found.', 404);

  if (existing.status === 'confirmed') {
    return {
      payment: existing,
      order,
      verification: {
        valid: true,
        txHash: existing.tx_hash,
        blockNumber: existing.block_number ?? undefined,
        confirmations: existing.confirmations,
      },
    };
  }

  const nowIso = new Date().toISOString();
  const staleIso = new Date(Date.now() - 90_000).toISOString();
  const claimed = await db
    .prepare(
      `UPDATE payments
       SET status = 'verifying', updated_at = ?
       WHERE id = ? AND (status = 'submitted' OR (status = 'verifying' AND updated_at <= ?))
       RETURNING id`
    )
    .bind(nowIso, paymentId, staleIso)
    .first<{ id: number }>();
  if (!claimed) {
    throw new DomainError('PAYMENT_NOT_VERIFIABLE', 'Payment already verifying or terminal.', 409);
  }

  const chainId = await rpc.getChainId();
  let receipt = null;
  let latestBlock = 0;
  let blockTimestamp: number | null = null;
  if (chainId === DOMAIN_CONSTANTS.chainId) {
    [receipt, latestBlock] = await Promise.all([
      rpc.getTransactionReceipt(existing.tx_hash),
      rpc.getLatestBlockNumber(),
    ]);
    if (receipt?.blockNumber) {
      blockTimestamp = await rpc.getBlockTimestamp(receipt.blockNumber);
    }
  }

  const verification = verifyPolygonUsdcReceipt({
    txHash: existing.tx_hash,
    receipt,
    latestBlockNumber: latestBlock,
    expectedAmountUsdcMicro: order.payable_amount_usdc_micro,
    chainId,
    blockTimestamp,
    orderCreatedEpoch: Math.floor(new Date(order.created_at).getTime() / 1000),
    orderExpiresEpoch: Math.floor(new Date(order.expires_at).getTime() / 1000),
    expectedSenderWallet: order.expected_sender_wallet,
    requireExactAmount: true,
    minConfirmations: Number(env.POLYGON_MIN_CONFIRMATIONS ?? DOMAIN_CONSTANTS.minConfirmations),
    expectedContract: order.token_contract,
    expectedDestinationWallet: order.destination_wallet,
  });

  const actorId = options?.actorId ?? 'worker_verifier';
  const finishIso = new Date().toISOString();

  if (!verification.valid) {
    const isPending =
      verification.reason === 'RECEIPT_NOT_FOUND' ||
      verification.reason === 'INSUFFICIENT_CONFIRMATIONS';
    const nextPayStatus = isPending ? 'submitted' : 'failed';
    const nextOrderStatus = isPending ? 'tx_submitted' : 'rejected';
    const archivedTx = isPending ? existing.tx_hash : `rejected:${paymentId}:${existing.tx_hash}`;
    const note = isPending
      ? verification.reason ?? 'PENDING_FINALITY'
      : `${verification.reason ?? 'FAILED'} (original_tx=${existing.tx_hash})`;

    await db.batch([
      db
        .prepare(
          `UPDATE payments
           SET status = ?, tx_hash = ?, block_number = ?, confirmations = ?, sender_address = ?, verification_note = ?, updated_at = ?
           WHERE id = ?`
        )
        .bind(
          nextPayStatus,
          archivedTx,
          verification.blockNumber ?? null,
          verification.confirmations ?? 0,
          verification.senderAddress ?? null,
          note,
          finishIso,
          paymentId
        ),
      db
        .prepare(`UPDATE orders SET status = ?, updated_at = ? WHERE id = ?`)
        .bind(nextOrderStatus, finishIso, order.id),
      db
        .prepare(
          `INSERT INTO audit_logs (actor_type, actor_id, action, entity_type, entity_id, severity, metadata_json)
           VALUES ('system', ?, ?, 'payment', ?, ?, ?)`
        )
        .bind(
          actorId,
          isPending ? 'PAYMENT_PENDING_FINALITY' : 'PAYMENT_VERIFICATION_REJECTED',
          String(paymentId),
          isPending ? 'info' : 'warning',
          JSON.stringify({ orderCode: order.order_code, reason: verification.reason })
        ),
    ]);

    const updatedPay = (await db.prepare(`SELECT * FROM payments WHERE id = ?`).bind(paymentId).first<D1PaymentRow>())!;
    const updatedOrder = (await db.prepare(`SELECT * FROM orders WHERE id = ?`).bind(order.id).first<D1OrderRow>())!;
    return { payment: updatedPay, order: updatedOrder, verification };
  }

  const user = (await db.prepare(`SELECT * FROM users WHERE id = ?`).bind(order.user_id).first<D1UserRow>())!;
  const plan = (await db.prepare(`SELECT * FROM plans WHERE id = ?`).bind(order.plan_id).first<D1PlanRow>())!;
  if (user.status !== 'active') {
    throw new DomainError('ACCOUNT_RESTRICTED', 'Cannot issue license to restricted account.', 403);
  }

  const keyId = env.RSA_KEY_ID ?? 'edge-rsa-v1';

  if (order.order_type === 'renew' && order.target_subscription_id) {
    const sub = await db
      .prepare(`SELECT * FROM subscriptions WHERE id = ?`)
      .bind(order.target_subscription_id)
      .first<{ id: number; user_id: number; status: string; expires_at: string; version: number }>();
    const lic = sub
      ? await db
          .prepare(`SELECT * FROM licenses WHERE subscription_id = ?`)
          .bind(sub.id)
          .first<{ id: number; license_key: string; status: string; max_devices: number; issued_at: string; version: number }>()
      : null;

    if (!sub || !lic || sub.status === 'revoked' || sub.status === 'suspended' || lic.status === 'revoked' || lic.status === 'blocked') {
      throw new DomainError(
        'RENEWAL_BLOCKED_REVOKED_OR_SUSPENDED',
        'Cannot renew a revoked, blocked, or suspended license/subscription without explicit admin reactivation.',
        409
      );
    }

    const baseMs = Math.max(Date.now(), new Date(sub.expires_at).getTime());
    const newExpiresAt = new Date(baseMs + plan.duration_days * 86400 * 1000).toISOString();
    const effectiveMaxDevices = Math.max(lic.max_devices, plan.max_devices);
    const { canonicalJson, signatureBase64 } = await signRsaSha256(
      {
        expiresAt: newExpiresAt,
        issuedAt: lic.issued_at,
        keyId,
        licenseKey: lic.license_key,
        maxDevices: effectiveMaxDevices,
        offlineGraceHours: 72,
        payloadVersion: 1,
        planCode: plan.code,
        product: DOMAIN_CONSTANTS.productName,
        telegramId: user.telegram_id,
      },
      env.RSA_PRIVATE_KEY_PEM
    );

    await db.batch([
      db
        .prepare(
          `UPDATE payments
           SET status = 'confirmed', sender_address = ?, amount_usdc_micro = ?, block_number = ?,
               confirmations = ?, verification_note = 'Verified on Polygon PoS (Native USDC)',
               verified_at = ?, updated_at = ?
           WHERE id = ? AND status = 'verifying'`
        )
        .bind(
          verification.senderAddress ?? null,
          verification.matchedAmountUsdcMicro ?? order.payable_amount_usdc_micro,
          verification.blockNumber ?? null,
          verification.confirmations ?? 0,
          finishIso,
          finishIso,
          paymentId
        ),
      db.prepare(`UPDATE orders SET status = 'confirmed', updated_at = ? WHERE id = ?`).bind(finishIso, order.id),
      db
        .prepare(
          `UPDATE subscriptions
           SET plan_id = ?, status = 'active', expires_at = ?, auto_renew_reminded = 0,
               version = version + 1, updated_at = ?
           WHERE id = ? AND status IN ('active', 'expired')`
        )
        .bind(plan.id, newExpiresAt, finishIso, sub.id),
      db
        .prepare(
          `UPDATE licenses
           SET rsa_key_id = ?, payload_json = ?, signature_base64 = ?, status = 'active',
               max_devices = ?, expires_at = ?, version = version + 1, updated_at = ?
           WHERE id = ? AND status IN ('active', 'expired')`
        )
        .bind(keyId, canonicalJson, signatureBase64, effectiveMaxDevices, newExpiresAt, finishIso, lic.id),
      db
        .prepare(
          `INSERT INTO subscription_events (subscription_id, user_id, event_type, previous_status, new_status, actor_type, actor_id, reason)
           VALUES (?, ?, 'RENEWED', ?, 'active', 'system', ?, ?)`
        )
        .bind(sub.id, user.id, sub.status, actorId, `Confirmed order ${order.order_code}`),
      db
        .prepare(
          `INSERT INTO license_history (license_id, action, previous_status, new_status, actor_type, actor_id, reason)
           VALUES (?, 'RENEWED', ?, 'active', 'system', ?, ?)`
        )
        .bind(lic.id, lic.status, actorId, `Extended via ${order.order_code}`),
      db
        .prepare(
          `INSERT INTO audit_logs (actor_type, actor_id, action, entity_type, entity_id, metadata_json)
           VALUES ('system', ?, 'LICENSE_RENEWED', 'license', ?, ?)`
        )
        .bind(actorId, lic.license_key, JSON.stringify({ orderCode: order.order_code, newExpiresAt })),
    ]);

    const updatedPay = (await db.prepare(`SELECT * FROM payments WHERE id = ?`).bind(paymentId).first<D1PaymentRow>())!;
    const updatedOrder = (await db.prepare(`SELECT * FROM orders WHERE id = ?`).bind(order.id).first<D1OrderRow>())!;
    return { payment: updatedPay, order: updatedOrder, verification, licenseKey: lic.license_key };
  }

  // New license issuance inside single atomic D1 batch
  const expiresAt = new Date(Date.now() + plan.duration_days * 86400 * 1000).toISOString();
  const licenseKey = `EDGE-${randomHex(2).toUpperCase()}-${randomHex(2).toUpperCase()}-${randomHex(2).toUpperCase()}-${randomHex(2).toUpperCase()}`;
  const { canonicalJson, signatureBase64 } = await signRsaSha256(
    {
      expiresAt,
      issuedAt: finishIso,
      keyId,
      licenseKey,
      maxDevices: plan.max_devices,
      offlineGraceHours: 72,
      payloadVersion: 1,
      planCode: plan.code,
      product: DOMAIN_CONSTANTS.productName,
      telegramId: user.telegram_id,
    },
    env.RSA_PRIVATE_KEY_PEM
  );

  await db.batch([
    db
      .prepare(
        `UPDATE payments
         SET status = 'confirmed', sender_address = ?, amount_usdc_micro = ?, block_number = ?,
             confirmations = ?, verification_note = 'Verified on Polygon PoS (Native USDC)',
             verified_at = ?, updated_at = ?
         WHERE id = ? AND status = 'verifying'`
      )
      .bind(
        verification.senderAddress ?? null,
        verification.matchedAmountUsdcMicro ?? order.payable_amount_usdc_micro,
        verification.blockNumber ?? null,
        verification.confirmations ?? 0,
        finishIso,
        finishIso,
        paymentId
      ),
    db.prepare(`UPDATE orders SET status = 'confirmed', updated_at = ? WHERE id = ?`).bind(finishIso, order.id),
    db
      .prepare(
        `INSERT INTO subscriptions (user_id, plan_id, order_id, status, starts_at, expires_at)
         VALUES (?, ?, ?, 'active', ?, ?)`
      )
      .bind(user.id, plan.id, order.id, finishIso, expiresAt),
    db
      .prepare(
        `INSERT INTO licenses (
           license_key, subscription_id, user_id, rsa_key_id, payload_json, signature_base64,
           status, max_devices, offline_grace_hours, issued_at, expires_at, updated_at
         )
         SELECT ?, s.id, ?, ?, ?, ?, 'active', ?, 72, ?, ?, ?
         FROM subscriptions s WHERE s.order_id = ?`
      )
      .bind(
        licenseKey,
        user.id,
        keyId,
        canonicalJson,
        signatureBase64,
        plan.max_devices,
        finishIso,
        expiresAt,
        finishIso,
        order.id
      ),
    db
      .prepare(
        `INSERT INTO subscription_events (subscription_id, user_id, event_type, previous_status, new_status, actor_type, actor_id, reason)
         SELECT s.id, ?, 'CREATED', NULL, 'active', 'system', ?, ?
         FROM subscriptions s WHERE s.order_id = ?`
      )
      .bind(user.id, actorId, `Issued from confirmed order ${order.order_code}`, order.id),
    db
      .prepare(
        `INSERT INTO license_history (license_id, action, previous_status, new_status, actor_type, actor_id, reason)
         SELECT l.id, 'ISSUED', NULL, 'active', 'system', ?, ?
         FROM licenses l WHERE l.license_key = ?`
      )
      .bind(actorId, `Issued from confirmed order ${order.order_code}`, licenseKey),
    db
      .prepare(
        `INSERT INTO notifications (user_id, channel, type, dedupe_key, title, body)
         VALUES (?, 'telegram_bot', 'LICENSE_ISSUED', ?, 'لایسنس EDGE شما فعال شد', ?)`
      )
      .bind(
        user.id,
        `license_issued:${order.id}`,
        `سفارش ${order.order_code} تأیید شد. کلید لایسنس: ${licenseKey}`
      ),
    db
      .prepare(
        `INSERT INTO audit_logs (actor_type, actor_id, action, entity_type, entity_id, metadata_json)
         VALUES ('system', ?, 'LICENSE_ISSUED', 'license', ?, ?)`
      )
      .bind(actorId, licenseKey, JSON.stringify({ orderCode: order.order_code, planCode: plan.code })),
  ]);

  const updatedPay = (await db.prepare(`SELECT * FROM payments WHERE id = ?`).bind(paymentId).first<D1PaymentRow>())!;
  const updatedOrder = (await db.prepare(`SELECT * FROM orders WHERE id = ?`).bind(order.id).first<D1OrderRow>())!;
  return { payment: updatedPay, order: updatedOrder, verification, licenseKey };
}
