import crypto from 'crypto';
import { PAYMENT_NETWORK } from '../../../shared/constants';
import type { OrderRecord, OrderType, PaymentRecord } from '../../../shared/types';
import { runImmediateTransaction, type SqliteDb } from '../../db/connection';
import { AuditService } from '../audit/auditService';
import type { LicenseService } from '../license/licenseService';
import { PlanRepository } from '../plans/planRepository';
import { SupportService } from '../support/supportService';
import { UserRepository } from '../users/userRepository';
import {
  isValidEvmAddress,
  isValidPolygonTxHash,
  normalizeEvmAddress,
  normalizeTxHash,
  verifyPolygonUsdcReceipt,
  type PolygonRpcProvider,
  type PolygonVerificationResult,
} from './polygonVerifier';

export interface PaymentServiceOptions {
  verificationMode: 'DRY_RUN' | 'LIVE';
  minConfirmations?: number;
  requireSenderWalletInLive?: boolean;
  rpcProvider?: PolygonRpcProvider;
  licenseService?: LicenseService;
}

export class PaymentError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly statusCode = 400
  ) {
    super(message);
    this.name = 'PaymentError';
  }
}

export function formatMicroUsdc(micro: number): string {
  const whole = Math.floor(micro / 1_000_000);
  const frac = String(micro % 1_000_000).padStart(6, '0');
  return `${whole}.${frac}`;
}

export class PaymentService {
  private readonly plans: PlanRepository;
  private readonly audit: AuditService;
  private readonly users: UserRepository;
  private readonly support: SupportService;

  constructor(
    private readonly db: SqliteDb,
    private readonly options: PaymentServiceOptions
  ) {
    this.plans = new PlanRepository(db);
    this.audit = new AuditService(db);
    this.users = new UserRepository(db);
    this.support = new SupportService(db);
  }

  /**
   * Transitions any overdue open orders whose `expires_at <= now` to `expired`.
   */
  expireStaleOrders(nowIso = new Date().toISOString()): number {
    const res = this.db
      .prepare(
        `UPDATE orders
         SET status = 'expired', updated_at = ?
         WHERE status IN ('draft_phase0', 'pending_payment')
           AND expires_at <= ?`
      )
      .run(nowIso, nowIso);
    return res.changes;
  }

  /**
   * Allocates a unique micro-USDC offset (1..999 micro-USDC = $0.000001..$0.000999)
   * not currently held by any open order for this base plan price.
   * Prevents cross-order TxID front-running between concurrent buyers of the same plan.
   */
  private allocateUniqueMicroOffset(basePriceMicro: number): number {
    // Exclude offsets of open orders AND recently expired/cancelled/rejected orders (10-min cooldown)
    // so an offset can never be recycled within the on-chain block timestamp window.
    const cooldownCutoffIso = new Date(Date.now() - 10 * 60 * 1000).toISOString();
    const activeAmounts = new Set(
      (
        this.db
          .prepare(
            `SELECT payable_amount_usdc_micro FROM orders
             WHERE payable_amount_usdc_micro IS NOT NULL
               AND (
                 status IN ('draft_phase0', 'pending_payment', 'tx_submitted', 'verifying')
                 OR (status IN ('expired', 'rejected', 'cancelled') AND updated_at >= ?)
               )`
          )
          .all(cooldownCutoffIso) as Array<{ payable_amount_usdc_micro: number }>
      ).map((r) => r.payable_amount_usdc_micro)
    );

    // Random start offset for unpredictability, linearly probing within 1..999
    const start = (crypto.randomInt(1, 999) % 999) + 1;
    for (let i = 0; i < 999; i++) {
      const candidate = ((start - 1 + i) % 999) + 1;
      if (!activeAmounts.has(basePriceMicro + candidate)) {
        return candidate;
      }
    }
    throw new PaymentError(
      'ORDER_SLOT_EXHAUSTED',
      'Too many concurrent open orders for this plan. Please try again shortly.',
      503
    );
  }

  /**
   * Creates an order using ONLY authoritative server-side plan pricing from SQLite.
   * Assigns an anti-front-running unique micro-USDC offset and optional sender wallet binding.
   */
  createOrder(
    userId: number,
    planCode: string,
    ipAddress?: string | null,
    extra?: {
      orderType?: OrderType;
      targetSubscriptionId?: number | null;
      expectedSenderWallet?: string | null;
    }
  ): OrderRecord {
    const plan = this.plans.findByCode(planCode);
    if (!plan || plan.is_active !== 1) {
      throw new PaymentError('PLAN_NOT_FOUND', 'Selected plan is unavailable or inactive.', 404);
    }

    const requireWallet =
      this.options.verificationMode === 'LIVE' && (this.options.requireSenderWalletInLive ?? true);
    let normalizedSenderWallet: string | null = null;
    if (extra?.expectedSenderWallet) {
      if (!isValidEvmAddress(extra.expectedSenderWallet)) {
        throw new PaymentError(
          'INVALID_SENDER_WALLET',
          'Sender wallet must be a valid 42-character Polygon address (0x...).',
          400
        );
      }
      normalizedSenderWallet = normalizeEvmAddress(extra.expectedSenderWallet);
    } else if (requireWallet) {
      throw new PaymentError(
        'SENDER_WALLET_REQUIRED_IN_LIVE',
        'A verified buyer Polygon wallet address (0x...) is required for LIVE orders to prevent front-running.',
        400
      );
    }

    const orderType: OrderType = extra?.orderType ?? 'new';
    const orderCode = `EDGE-${Date.now().toString(36).toUpperCase()}-${crypto
      .randomBytes(3)
      .toString('hex')
      .toUpperCase()}`;
    const expiresAt = new Date(
      Date.now() + PAYMENT_NETWORK.orderExpiryMinutes * 60 * 1000
    ).toISOString();

    const initialStatus =
      this.options.verificationMode === 'DRY_RUN' ? 'draft_phase0' : 'pending_payment';

    return runImmediateTransaction(this.db, () => {
      // Expire stale orders before allocating a unique offset & checking open-order cap
      this.expireStaleOrders();

      const openCountRow = this.db
        .prepare(
          `SELECT COUNT(*) AS cnt FROM orders
           WHERE user_id = ? AND status IN ('draft_phase0', 'pending_payment', 'tx_submitted', 'verifying')`
        )
        .get(userId) as { cnt: number };
      if (openCountRow.cnt >= 10) {
        throw new PaymentError(
          'TOO_MANY_OPEN_ORDERS',
          'You have too many pending orders. Complete or wait for existing orders to expire.',
          429
        );
      }

      if (extra?.targetSubscriptionId) {
        const sub = this.db
          .prepare('SELECT id, user_id FROM subscriptions WHERE id = ?')
          .get(extra.targetSubscriptionId) as { id: number; user_id: number } | undefined;
        if (!sub || sub.user_id !== userId) {
          throw new PaymentError(
            'TARGET_SUBSCRIPTION_NOT_FOUND',
            'Target subscription not found for this account.',
            404
          );
        }
      }

      const uniqueOffsetMicro = this.allocateUniqueMicroOffset(plan.price_usdc_micro);
      const payableMicro = plan.price_usdc_micro + uniqueOffsetMicro;

      const res = this.db
        .prepare(
          `INSERT INTO orders (
             order_code,
             user_id,
             plan_id,
             order_type,
             target_subscription_id,
             expected_amount_usdc_micro,
             unique_offset_micro,
             payable_amount_usdc_micro,
             expected_amount_usd,
             expected_sender_wallet,
             network,
             token_contract,
             destination_wallet,
             status,
             expires_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'polygon_pos', ?, ?, ?, ?)`
        )
        .run(
          orderCode,
          userId,
          plan.id,
          orderType,
          extra?.targetSubscriptionId ?? null,
          plan.price_usdc_micro,
          uniqueOffsetMicro,
          payableMicro,
          plan.price_usd_display,
          normalizedSenderWallet,
          PAYMENT_NETWORK.usdcContractAddress,
          PAYMENT_NETWORK.destinationWalletAddress,
          initialStatus,
          expiresAt
        );

      const createdId = Number(res.lastInsertRowid);
      this.audit.record({
        actorType: 'user',
        actorId: String(userId),
        action: 'ORDER_CREATED',
        entityType: 'order',
        entityId: orderCode,
        metadata: {
          planCode: plan.code,
          orderType,
          expectedAmountUsdcMicro: plan.price_usdc_micro,
          payableAmountUsdcMicro: payableMicro,
          uniqueOffsetMicro,
          mode: this.options.verificationMode,
        },
        ipAddress,
      });

      return this.findOrderById(createdId)!;
    });
  }

  /**
   * Registers a user-submitted Polygon PoS TxID against an owned, unexpired order.
   * - Enforces strict hex format (`0x` + 64 hex chars).
   * - Enforces real-time `order.expires_at` expiration check.
   * - Enforces at most ONE active/confirmed payment per order (prevents race/spam).
   * - Enforces global `UNIQUE(tx_hash)` inside an IMMEDIATE transaction (anti-replay).
   * - In DRY_RUN mode: records dry-run intake ONLY; refuses real settlement.
   */
  submitTransactionHash(params: {
    userId: number;
    orderCode: string;
    txHash: string;
    ipAddress?: string | null;
    nowIso?: string;
  }): { payment: PaymentRecord; order: OrderRecord; dryRunBlocked: boolean } {
    const normalizedHash = normalizeTxHash(params.txHash);
    if (!isValidPolygonTxHash(normalizedHash)) {
      throw new PaymentError(
        'INVALID_TX_HASH',
        'Transaction hash must be a valid 66-character Polygon PoS hex string (0x...).',
        400
      );
    }

    const nowIso = params.nowIso ?? new Date().toISOString();
    const txFlags: {
      replayDetected: { orderCode: string; existingPaymentId: number } | null;
      expiredDetected: { orderCode: string; expiresAt: string } | null;
    } = {
      replayDetected: null,
      expiredDetected: null,
    };

    const outcome = runImmediateTransaction(this.db, () => {
      const order = this.findOrderByCode(params.orderCode);
      if (!order || order.user_id !== params.userId) {
        throw new PaymentError('ORDER_NOT_FOUND', 'Order not found for this account.', 404);
      }

      if (['confirmed', 'cancelled', 'expired', 'rejected'].includes(order.status)) {
        throw new PaymentError(
          'ORDER_NOT_PAYABLE',
          `Order is in terminal state (${order.status}).`,
          409
        );
      }

      // Real-time order expiration enforcement
      if (new Date(order.expires_at).getTime() <= new Date(nowIso).getTime()) {
        this.db
          .prepare(`UPDATE orders SET status = 'expired', updated_at = ? WHERE id = ?`)
          .run(nowIso, order.id);
        txFlags.expiredDetected = { orderCode: order.order_code, expiresAt: order.expires_at };
        return null;
      }

      // Prevent attaching multiple active payments to the same order
      const existingOrderPayment = this.db
        .prepare(
          `SELECT id, status FROM payments
           WHERE order_id = ? AND status IN ('submitted', 'dry_run_recorded', 'verifying', 'confirmed')`
        )
        .get(order.id) as { id: number; status: string } | undefined;

      if (existingOrderPayment) {
        throw new PaymentError(
          'ORDER_ALREADY_HAS_ACTIVE_PAYMENT',
          'An active transaction is already linked to this order.',
          409
        );
      }

      // Global anti-replay check
      const duplicate = this.db
        .prepare('SELECT id, order_id FROM payments WHERE tx_hash = ? COLLATE NOCASE')
        .get(normalizedHash) as { id: number; order_id: number } | undefined;

      if (duplicate) {
        txFlags.replayDetected = { orderCode: order.order_code, existingPaymentId: duplicate.id };
        return null;
      }

      const isDryRun = this.options.verificationMode === 'DRY_RUN';
      const paymentStatus = isDryRun ? 'dry_run_recorded' : 'submitted';
      const orderNextStatus = isDryRun ? 'draft_phase0' : 'tx_submitted';
      const payableMicro = order.payable_amount_usdc_micro ?? order.expected_amount_usdc_micro;
      const note = isDryRun
        ? 'Phase 1 DRY_RUN: TxID syntax, expiry, and anti-replay validated; live Polygon settlement disabled.'
        : 'Queued for Polygon PoS Native USDC receipt verification.';

      const insertRes = this.db
        .prepare(
          `INSERT INTO payments (
             order_id,
             user_id,
             tx_hash,
             network,
             token_contract,
             receiver_address,
             amount_usdc_micro,
             status,
             verification_note
           ) VALUES (?, ?, ?, 'polygon_pos', ?, ?, ?, ?, ?)`
        )
        .run(
          order.id,
          params.userId,
          normalizedHash,
          PAYMENT_NETWORK.usdcContractAddress,
          PAYMENT_NETWORK.destinationWalletAddress,
          payableMicro,
          paymentStatus,
          note
        );

      this.db
        .prepare(`UPDATE orders SET status = ?, updated_at = ? WHERE id = ?`)
        .run(orderNextStatus, nowIso, order.id);

      const paymentId = Number(insertRes.lastInsertRowid);
      this.audit.record({
        actorType: 'user',
        actorId: String(params.userId),
        action: isDryRun ? 'TX_SUBMITTED_DRY_RUN' : 'TX_SUBMITTED',
        entityType: 'payment',
        entityId: String(paymentId),
        metadata: { orderCode: order.order_code, txHash: normalizedHash, isDryRun },
        ipAddress: params.ipAddress,
      });

      const payment = this.db
        .prepare('SELECT * FROM payments WHERE id = ?')
        .get(paymentId) as PaymentRecord;
      const updatedOrder = this.findOrderById(order.id)!;

      return { payment, order: updatedOrder, dryRunBlocked: isDryRun };
    });

    if (txFlags.expiredDetected) {
      this.audit.record({
        actorType: 'user',
        actorId: String(params.userId),
        action: 'EXPIRED_ORDER_PAYMENT_REJECTED',
        entityType: 'order',
        entityId: txFlags.expiredDetected.orderCode,
        severity: 'warning',
        metadata: txFlags.expiredDetected,
        ipAddress: params.ipAddress,
      });
      throw new PaymentError('ORDER_EXPIRED', 'Order has expired and can no longer be paid.', 409);
    }

    if (txFlags.replayDetected || !outcome) {
      this.audit.record({
        actorType: 'user',
        actorId: String(params.userId),
        action: 'DUPLICATE_TX_REPLAY_BLOCKED',
        entityType: 'payment',
        entityId: normalizedHash,
        severity: 'warning',
        metadata: txFlags.replayDetected ?? { orderCode: params.orderCode },
        ipAddress: params.ipAddress,
      });
      throw new PaymentError(
        'DUPLICATE_TX_HASH',
        'This transaction hash has already been submitted and cannot be reused.',
        409
      );
    }

    return outcome;
  }

  /**
   * Executes full Polygon PoS on-chain verification for a submitted payment:
   * 1. Blocked in DRY_RUN mode (never contacts external RPC in DRY_RUN).
   * 2. Verifies eth_chainId === 137, receipt hash, status === 0x1, confirmations,
   *    block timestamp within [order.created_at, order.expires_at], Native USDC contract,
   *    treasury destination wallet, exact anti-front-running payable micro-USDC amount,
   *    and optional sender wallet binding.
   * 3. Atomically confirms payment + order and issues/renews the RSA-signed license.
   */
  async verifyPaymentOnChain(
    paymentId: number,
    overrides?: {
      rpcProvider?: PolygonRpcProvider;
      licenseService?: LicenseService;
      actorId?: string;
    }
  ): Promise<{
    payment: PaymentRecord;
    order: OrderRecord;
    verification: PolygonVerificationResult;
    licenseKey?: string;
  }> {
    if (this.options.verificationMode !== 'LIVE') {
      throw new PaymentError(
        'DRY_RUN_VERIFICATION_BLOCKED',
        'Live Polygon PoS settlement is disabled in DRY_RUN mode.',
        403
      );
    }

    const rpc = overrides?.rpcProvider ?? this.options.rpcProvider;
    const licService = overrides?.licenseService ?? this.options.licenseService;
    if (!rpc) {
      throw new PaymentError('RPC_PROVIDER_NOT_CONFIGURED', 'Polygon RPC provider is unavailable.', 503);
    }

    const payment = this.db
      .prepare('SELECT * FROM payments WHERE id = ?')
      .get(paymentId) as PaymentRecord | undefined;
    if (!payment) {
      throw new PaymentError('PAYMENT_NOT_FOUND', 'Payment record not found.', 404);
    }
    if (payment.status === 'confirmed') {
      const order = this.findOrderById(payment.order_id)!;
      return {
        payment,
        order,
        verification: {
          valid: true,
          txHash: payment.tx_hash,
          blockNumber: payment.block_number ?? undefined,
          confirmations: payment.confirmations,
        },
      };
    }

    const order = this.findOrderById(payment.order_id);
    if (!order) {
      throw new PaymentError('ORDER_NOT_FOUND', 'Associated order not found.', 404);
    }

    // Transition to verifying atomically to prevent concurrent double-verification races.
    // Re-claiming a 'verifying' row is ONLY allowed if its previous lock is stale (>90s old).
    const staleLockCutoffIso = new Date(Date.now() - 90_000).toISOString();
    const claimed = runImmediateTransaction(this.db, () => {
      const current = this.db
        .prepare('SELECT status, updated_at FROM payments WHERE id = ?')
        .get(paymentId) as { status: string; updated_at: string } | undefined;
      if (!current) return false;
      const canClaim =
        current.status === 'submitted' ||
        (current.status === 'verifying' && current.updated_at <= staleLockCutoffIso);
      if (!canClaim) {
        return false;
      }
      const nowIso = new Date().toISOString();
      this.db
        .prepare(`UPDATE payments SET status = 'verifying', updated_at = ? WHERE id = ?`)
        .run(nowIso, paymentId);
      this.db
        .prepare(`UPDATE orders SET status = 'verifying', updated_at = ? WHERE id = ?`)
        .run(nowIso, order.id);
      return true;
    });

    if (!claimed) {
      throw new PaymentError('PAYMENT_NOT_VERIFIABLE', 'Payment cannot be verified in its current state.', 409);
    }

    // External RPC calls happen outside SQLite write lock
    const chainId = await rpc.getChainId();
    let receipt = null;
    let latestBlock = 0;
    let blockTimestamp: number | null = null;

    if (chainId === PAYMENT_NETWORK.chainId) {
      [receipt, latestBlock] = await Promise.all([
        rpc.getTransactionReceipt(payment.tx_hash),
        rpc.getLatestBlockNumber(),
      ]);
      if (receipt?.blockNumber) {
        blockTimestamp = await rpc.getBlockTimestamp(receipt.blockNumber);
      }
    }

    const payableMicro = order.payable_amount_usdc_micro ?? order.expected_amount_usdc_micro;
    const verification = verifyPolygonUsdcReceipt({
      txHash: payment.tx_hash,
      receipt,
      latestBlockNumber: latestBlock,
      expectedAmountUsdcMicro: payableMicro,
      chainId,
      blockTimestamp,
      orderCreatedEpoch: Math.floor(new Date(order.created_at).getTime() / 1000),
      orderExpiresEpoch: Math.floor(new Date(order.expires_at).getTime() / 1000),
      expectedSenderWallet: order.expected_sender_wallet ?? null,
      requireExactAmount: true,
      minConfirmations: this.options.minConfirmations ?? PAYMENT_NETWORK.minConfirmations,
      expectedContract: order.token_contract,
      expectedDestinationWallet: order.destination_wallet,
    });

    const actorId = overrides?.actorId ?? 'payment_verifier';
    const nowIso = new Date().toISOString();

    if (!verification.valid) {
      const isPendingFinality =
        verification.reason === 'RECEIPT_NOT_FOUND' ||
        verification.reason === 'INSUFFICIENT_CONFIRMATIONS';

      const nextPayStatus = isPendingFinality ? 'submitted' : 'failed';
      const nextOrderStatus = isPendingFinality ? 'tx_submitted' : 'rejected';

      // Anti-TxID-Squatting: when a payment is permanently rejected for a mismatch (e.g. an attacker
      // submitted someone else's public mempool TxID against their own order), archive the rejected
      // tx_hash under `rejected:<id>:<hash>` so the legitimate buyer is NEVER permanently blocked from
      // claiming their real transaction hash. Confirmed/active tx_hashes stay globally locked forever.
      const archivedTxHash = isPendingFinality
        ? payment.tx_hash
        : `rejected:${paymentId}:${payment.tx_hash}`;
      const detailedNote = isPendingFinality
        ? verification.reason ?? 'PENDING_FINALITY'
        : `${verification.reason ?? 'VERIFICATION_FAILED'} (original_tx=${payment.tx_hash})`;

      runImmediateTransaction(this.db, () => {
        this.db
          .prepare(
            `UPDATE payments
             SET status = ?, tx_hash = ?, block_number = ?, confirmations = ?, sender_address = ?, verification_note = ?, updated_at = ?
             WHERE id = ?`
          )
          .run(
            nextPayStatus,
            archivedTxHash,
            verification.blockNumber ?? null,
            verification.confirmations ?? 0,
            verification.senderAddress ?? null,
            detailedNote,
            nowIso,
            paymentId
          );
        this.db
          .prepare(`UPDATE orders SET status = ?, updated_at = ? WHERE id = ?`)
          .run(nextOrderStatus, nowIso, order.id);

        this.audit.record({
          actorType: 'system',
          actorId,
          action: isPendingFinality ? 'PAYMENT_PENDING_FINALITY' : 'PAYMENT_VERIFICATION_REJECTED',
          entityType: 'payment',
          entityId: String(paymentId),
          severity: isPendingFinality ? 'info' : 'warning',
          metadata: {
            orderCode: order.order_code,
            txHash: payment.tx_hash,
            reason: verification.reason,
            chainId: verification.chainId,
            confirmations: verification.confirmations,
          },
        });
      });

      return {
        payment: this.db.prepare('SELECT * FROM payments WHERE id = ?').get(paymentId) as PaymentRecord,
        order: this.findOrderById(order.id)!,
        verification,
      };
    }

    // Confirmed on-chain! Atomically finalize payment + order and issue/renew license.
    let issuedLicenseKey: string | undefined;

    runImmediateTransaction(this.db, () => {
      const freshPay = this.db
        .prepare('SELECT status FROM payments WHERE id = ?')
        .get(paymentId) as { status: string };
      if (freshPay.status === 'confirmed') {
        return;
      }

      this.db
        .prepare(
          `UPDATE payments
           SET status = 'confirmed',
               sender_address = ?,
               amount_usdc_micro = ?,
               block_number = ?,
               confirmations = ?,
               verification_note = 'Verified on Polygon PoS (Native USDC)',
               verified_at = ?,
               updated_at = ?
           WHERE id = ?`
        )
        .run(
          verification.senderAddress ?? null,
          verification.matchedAmountUsdcMicro ?? payableMicro,
          verification.blockNumber ?? null,
          verification.confirmations ?? 0,
          nowIso,
          nowIso,
          paymentId
        );

      this.db
        .prepare(`UPDATE orders SET status = 'confirmed', updated_at = ? WHERE id = ?`)
        .run(nowIso, order.id);

      this.audit.record({
        actorType: 'system',
        actorId,
        action: 'PAYMENT_CONFIRMED_ON_CHAIN',
        entityType: 'payment',
        entityId: String(paymentId),
        metadata: {
          orderCode: order.order_code,
          txHash: payment.tx_hash,
          blockNumber: verification.blockNumber,
          confirmations: verification.confirmations,
          amountUsdcMicro: verification.matchedAmountUsdcMicro,
        },
      });

      if (licService) {
        const user = this.users.findById(order.user_id);
        const plan = this.plans.findById(order.plan_id);
        if (user && plan) {
          if (order.order_type === 'renew' && order.target_subscription_id) {
            const renewed = licService.renewSubscription({
              subscriptionId: order.target_subscription_id,
              planId: plan.id,
              planCode: plan.code,
              durationDays: plan.duration_days,
              maxDevices: plan.max_devices,
              confirmedOrderId: order.id,
              actorId,
            });
            issuedLicenseKey = renewed.license.license_key;
          } else {
            const issued = licService.issueForSubscription({
              userId: user.id,
              telegramId: user.telegram_id,
              planId: plan.id,
              planCode: plan.code,
              durationDays: plan.duration_days,
              maxDevices: plan.max_devices,
              orderId: order.id,
              actorId,
              requireConfirmedPayment: true,
            });
            issuedLicenseKey = issued.license.license_key;
          }

          this.support.queueNotification({
            userId: user.id,
            channel: 'telegram_bot',
            type: 'LICENSE_ISSUED',
            title: 'لایسنس EDGE شما فعال شد',
            body: `سفارش ${order.order_code} تأیید شد. کلید لایسنس: ${issuedLicenseKey}`,
          });
        }
      }
    });

    return {
      payment: this.db.prepare('SELECT * FROM payments WHERE id = ?').get(paymentId) as PaymentRecord,
      order: this.findOrderById(order.id)!,
      verification,
      licenseKey: issuedLicenseKey,
    };
  }

  findOrderById(id: number): OrderRecord | undefined {
    return this.db
      .prepare(
        `SELECT o.*, p.code AS plan_code, p.name_en AS plan_name_en, p.name_fa AS plan_name_fa
         FROM orders o
         JOIN plans p ON p.id = o.plan_id
         WHERE o.id = ?`
      )
      .get(id) as OrderRecord | undefined;
  }

  findOrderByCode(orderCode: string): OrderRecord | undefined {
    return this.db
      .prepare(
        `SELECT o.*, p.code AS plan_code, p.name_en AS plan_name_en, p.name_fa AS plan_name_fa
         FROM orders o
         JOIN plans p ON p.id = o.plan_id
         WHERE o.order_code = ?`
      )
      .get(orderCode) as OrderRecord | undefined;
  }

  listUserOrders(userId: number): OrderRecord[] {
    this.expireStaleOrders();
    return this.db
      .prepare(
        `SELECT o.*, p.code AS plan_code, p.name_en AS plan_name_en, p.name_fa AS plan_name_fa
         FROM orders o
         JOIN plans p ON p.id = o.plan_id
         WHERE o.user_id = ?
         ORDER BY o.id DESC
         LIMIT 50`
      )
      .all(userId) as OrderRecord[];
  }

  listUserPayments(userId: number): PaymentRecord[] {
    return this.db
      .prepare(
        `SELECT pay.*, o.order_code
         FROM payments pay
         JOIN orders o ON o.id = pay.order_id
         WHERE pay.user_id = ?
         ORDER BY pay.id DESC
         LIMIT 50`
      )
      .all(userId) as PaymentRecord[];
  }
}
