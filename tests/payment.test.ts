import { describe, expect, it } from 'vitest';
import { openDatabase } from '../src/server/db/connection';
import { runMigrations } from '../src/server/db/migrator';
import { LicenseService } from '../src/server/modules/license/licenseService';
import { PaymentError, PaymentService } from '../src/server/modules/payment/paymentService';
import {
  PolygonRpcClient,
  verifyPolygonUsdcReceipt,
  type EvmTransactionReceipt,
  type PolygonRpcProvider,
} from '../src/server/modules/payment/polygonVerifier';
import { UserRepository } from '../src/server/modules/users/userRepository';
import { generateEphemeralRsaKeyPair } from '../src/server/security/rsaSigner';
import { PAYMENT_NETWORK } from '../src/shared/constants';

function padAddressTopic(address: string): string {
  return `0x${address.toLowerCase().replace(/^0x/, '').padStart(64, '0')}`;
}

function encodeUint256(amount: bigint): string {
  return `0x${amount.toString(16).padStart(64, '0')}`;
}

describe('Payment Engine: Polygon PoS Native USDC Verifier, Anti-Front-Running, Expiry & Mocked RPC', () => {
  const sampleTxHash =
    '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  const secondTxHash =
    '0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc';
  const senderWallet = '0x1111111111111111111111111111111111111111';
  const otherWallet = '0x2222222222222222222222222222222222222222';

  const makeReceipt = (
    amountMicro: bigint = 4_990_000n,
    overrides?: Partial<EvmTransactionReceipt>
  ): EvmTransactionReceipt => ({
    transactionHash: sampleTxHash,
    status: '0x1',
    blockNumber: '0x3b9aca0', // 62500000
    from: senderWallet,
    to: PAYMENT_NETWORK.usdcContractAddress,
    logs: [
      {
        address: PAYMENT_NETWORK.usdcContractAddress,
        topics: [
          PAYMENT_NETWORK.erc20TransferTopic,
          padAddressTopic(senderWallet),
          padAddressTopic(PAYMENT_NETWORK.destinationWalletAddress),
        ],
        data: encodeUint256(amountMicro),
      },
    ],
    ...overrides,
  });

  it('verifies valid Polygon PoS Native USDC transfer with chainId=137, block timestamp window & exact payable amount', () => {
    const createdEpoch = 1_760_000_000;
    const result = verifyPolygonUsdcReceipt({
      txHash: sampleTxHash,
      receipt: makeReceipt(4_990_123n),
      latestBlockNumber: 62500040,
      expectedAmountUsdcMicro: 4_990_123,
      chainId: 137,
      blockTimestamp: createdEpoch + 120,
      orderCreatedEpoch: createdEpoch,
      orderExpiresEpoch: createdEpoch + 2700,
      expectedSenderWallet: senderWallet,
      requireExactAmount: true,
    });

    expect(result.valid).toBe(true);
    expect(result.matchedAmountUsdcMicro).toBe(4_990_123);
    expect(result.confirmations).toBe(41);
    expect(result.receiverAddress).toBe(PAYMENT_NETWORK.destinationWalletAddress);
    expect(result.senderAddress).toBe(senderWallet);
  });

  it('rejects wrong chainId, receipt hash mismatch, pre-order/post-expiry timestamps, sender mismatch, and cross-order amount mismatch', () => {
    const createdEpoch = 1_760_000_000;
    const expiresEpoch = createdEpoch + 2700;

    // Wrong chainId (e.g. Ethereum Mainnet = 1 or Amoy = 80002)
    expect(
      verifyPolygonUsdcReceipt({
        txHash: sampleTxHash,
        receipt: makeReceipt(4_990_123n),
        latestBlockNumber: 62500040,
        expectedAmountUsdcMicro: 4_990_123,
        chainId: 80002,
      }).reason
    ).toBe('WRONG_CHAIN_ID');

    // Receipt transactionHash mismatch
    expect(
      verifyPolygonUsdcReceipt({
        txHash: sampleTxHash,
        receipt: makeReceipt(4_990_123n, { transactionHash: secondTxHash }),
        latestBlockNumber: 62500040,
        expectedAmountUsdcMicro: 4_990_123,
        chainId: 137,
      }).reason
    ).toBe('RECEIPT_TX_HASH_MISMATCH');

    // Historical tx predating order creation
    expect(
      verifyPolygonUsdcReceipt({
        txHash: sampleTxHash,
        receipt: makeReceipt(4_990_123n),
        latestBlockNumber: 62500040,
        expectedAmountUsdcMicro: 4_990_123,
        chainId: 137,
        blockTimestamp: createdEpoch - 3600,
        orderCreatedEpoch: createdEpoch,
        orderExpiresEpoch: expiresEpoch,
      }).reason
    ).toBe('TX_PREDATES_ORDER');

    // Transaction mined after order expiry
    expect(
      verifyPolygonUsdcReceipt({
        txHash: sampleTxHash,
        receipt: makeReceipt(4_990_123n),
        latestBlockNumber: 62500040,
        expectedAmountUsdcMicro: 4_990_123,
        chainId: 137,
        blockTimestamp: expiresEpoch + 600,
        orderCreatedEpoch: createdEpoch,
        orderExpiresEpoch: expiresEpoch,
      }).reason
    ).toBe('TX_AFTER_ORDER_EXPIRY');

    // Sender wallet mismatch
    expect(
      verifyPolygonUsdcReceipt({
        txHash: sampleTxHash,
        receipt: makeReceipt(4_990_123n),
        latestBlockNumber: 62500040,
        expectedAmountUsdcMicro: 4_990_123,
        chainId: 137,
        expectedSenderWallet: otherWallet,
      }).reason
    ).toBe('SENDER_WALLET_MISMATCH');

    // Anti-front-running: exact amount mismatch (attacker submits another user's tx with different micro-offset)
    expect(
      verifyPolygonUsdcReceipt({
        txHash: sampleTxHash,
        receipt: makeReceipt(4_990_777n),
        latestBlockNumber: 62500040,
        expectedAmountUsdcMicro: 4_990_123,
        chainId: 137,
        requireExactAmount: true,
      }).reason
    ).toBe('AMOUNT_MISMATCH_CROSS_ORDER');

    // Bridged USDC.e rejected
    const bridgedReceipt = makeReceipt(4_990_000n, {
      logs: [
        {
          address: '0x2791bca1f2de4661ed88a30c99a7a9449aa84174',
          topics: [
            PAYMENT_NETWORK.erc20TransferTopic,
            padAddressTopic(senderWallet),
            padAddressTopic(PAYMENT_NETWORK.destinationWalletAddress),
          ],
          data: encodeUint256(4_990_000n),
        },
      ],
    });
    expect(
      verifyPolygonUsdcReceipt({
        txHash: sampleTxHash,
        receipt: bridgedReceipt,
        latestBlockNumber: 62500040,
        expectedAmountUsdcMicro: 4_990_000,
        chainId: 137,
      }).reason
    ).toBe('NO_MATCHING_NATIVE_USDC_TRANSFER');

    // Reverted tx & insufficient confirmations
    expect(
      verifyPolygonUsdcReceipt({
        txHash: sampleTxHash,
        receipt: makeReceipt(4_990_000n, { status: '0x0' }),
        latestBlockNumber: 62500040,
        expectedAmountUsdcMicro: 4_990_000,
        chainId: 137,
      }).reason
    ).toBe('TX_REVERTED');

    expect(
      verifyPolygonUsdcReceipt({
        txHash: sampleTxHash,
        receipt: makeReceipt(4_990_000n),
        latestBlockNumber: 62500005,
        expectedAmountUsdcMicro: 4_990_000,
        chainId: 137,
      }).reason
    ).toBe('INSUFFICIENT_CONFIRMATIONS');
  });

  it('allocates distinct anti-front-running micro-USDC amounts, enforces order expiry, single active payment per order, and anti-replay', () => {
    const db = openDatabase(':memory:');
    try {
      runMigrations(db);
      const users = new UserRepository(db);
      const buyerA = users.upsertFromTelegram({ telegramId: '555000111', firstName: 'BuyerA' });
      const buyerB = users.upsertFromTelegram({ telegramId: '555000222', firstName: 'BuyerB' });

      const service = new PaymentService(db, { verificationMode: 'DRY_RUN' });
      const orderA = service.createOrder(buyerA.id, 'EDGE_6M');
      const orderB = service.createOrder(buyerB.id, 'EDGE_6M');

      // Base price remains fixed ($8.99), payable amounts have distinct anti-front-running offsets
      expect(orderA.expected_amount_usd).toBe('8.99');
      expect(orderA.expected_amount_usdc_micro).toBe(8_990_000);
      expect(orderA.unique_offset_micro).toBeGreaterThanOrEqual(1);
      expect(orderA.unique_offset_micro).toBeLessThanOrEqual(999);
      expect(orderA.payable_amount_usdc_micro).not.toBe(orderB.payable_amount_usdc_micro);

      // Submit TxID on orderA
      const submit1 = service.submitTransactionHash({
        userId: buyerA.id,
        orderCode: orderA.order_code,
        txHash: sampleTxHash,
      });
      expect(submit1.dryRunBlocked).toBe(true);
      expect(submit1.payment.status).toBe('dry_run_recorded');

      // Second different TxID on the SAME orderA blocked (`ORDER_ALREADY_HAS_ACTIVE_PAYMENT`)
      expect(() =>
        service.submitTransactionHash({
          userId: buyerA.id,
          orderCode: orderA.order_code,
          txHash: secondTxHash,
        })
      ).toThrow(/already linked to this order/i);

      // Replay exact same TxID (even uppercase) on buyerB's order -> MUST fail
      expect(() =>
        service.submitTransactionHash({
          userId: buyerB.id,
          orderCode: orderB.order_code,
          txHash: sampleTxHash.toUpperCase(),
        })
      ).toThrow(PaymentError);

      // Real-time expired order rejection
      const expiredFutureNow = new Date(Date.now() + 2 * 60 * 60 * 1000).toISOString();
      expect(() =>
        service.submitTransactionHash({
          userId: buyerB.id,
          orderCode: orderB.order_code,
          txHash: secondTxHash,
          nowIso: expiredFutureNow,
        })
      ).toThrow(/expired/i);

      const refreshedOrderB = service.findOrderById(orderB.id);
      expect(refreshedOrderB?.status).toBe('expired');

      const replayAudit = db
        .prepare(`SELECT action FROM audit_logs WHERE action = 'DUPLICATE_TX_REPLAY_BLOCKED'`)
        .get() as { action: string } | undefined;
      expect(replayAudit?.action).toBe('DUPLICATE_TX_REPLAY_BLOCKED');

      const expiredAudit = db
        .prepare(`SELECT action FROM audit_logs WHERE action = 'EXPIRED_ORDER_PAYMENT_REJECTED'`)
        .get() as { action: string } | undefined;
      expect(expiredAudit?.action).toBe('EXPIRED_ORDER_PAYMENT_REJECTED');
    } finally {
      db.close();
    }
  });

  it('wires mocked PolygonRpcProvider end-to-end: rejects cross-order hijack, then confirms legitimate payment and issues RSA-2048 license', async () => {
    const db = openDatabase(':memory:');
    try {
      runMigrations(db);
      const users = new UserRepository(db);
      const buyer = users.upsertFromTelegram({ telegramId: '555000333', firstName: 'LiveBuyer' });
      const attacker = users.upsertFromTelegram({ telegramId: '555000444', firstName: 'Attacker' });

      const { privateKeyPem, publicKeyPem } = generateEphemeralRsaKeyPair();
      const licenseService = new LicenseService(db, {
        issuanceMode: 'LIVE',
        rsaPrivateKeyPem: privateKeyPem,
        rsaPublicKeyPem: publicKeyPem,
        rsaKeyId: 'edge-rsa-p1-test',
      });

      const paymentService = new PaymentService(db, {
        verificationMode: 'LIVE',
        minConfirmations: 30,
        licenseService,
      });

      // 0. LIVE order without buyer Polygon wallet MUST be rejected by default
      expect(() => paymentService.createOrder(attacker.id, 'EDGE_3M')).toThrow(
        /verified buyer Polygon wallet/i
      );

      const legitimateOrder = paymentService.createOrder(buyer.id, 'EDGE_3M', null, {
        expectedSenderWallet: senderWallet,
      });
      const attackerOrder = paymentService.createOrder(attacker.id, 'EDGE_3M', null, {
        expectedSenderWallet: otherWallet,
      });

      const nowEpoch = Math.floor(Date.now() / 1000);
      const mockRpc: PolygonRpcProvider = {
        getChainId: async () => 137,
        getLatestBlockNumber: async () => 62500045,
        getBlockTimestamp: async () => nowEpoch + 5,
        getTransactionReceipt: async (hash) =>
          makeReceipt(BigInt(legitimateOrder.payable_amount_usdc_micro!), {
            transactionHash: hash,
          }),
      };

      // 1. TxID Squatting / Front-Running Attack:
      // Attacker sees buyer's REAL TxID (`sampleTxHash`) on-chain and submits it to attacker's order FIRST!
      // Verification MUST reject attacker (SENDER_WALLET_MISMATCH) AND release the raw tx_hash so the
      // legitimate buyer is NOT permanently poisoned/blocked from claiming their own paid TxID!
      const attackSub = paymentService.submitTransactionHash({
        userId: attacker.id,
        orderCode: attackerOrder.order_code,
        txHash: sampleTxHash,
      });
      const attackVerify = await paymentService.verifyPaymentOnChain(attackSub.payment.id, {
        rpcProvider: mockRpc,
      });
      expect(attackVerify.verification.valid).toBe(false);
      expect(attackVerify.verification.reason).toBe('SENDER_WALLET_MISMATCH');
      expect(attackVerify.payment.status).toBe('failed');
      expect(attackVerify.order.status).toBe('rejected');
      expect(attackVerify.licenseKey).toBeUndefined();

      // 2. Legitimate buyer now submits their REAL `sampleTxHash` -> succeeds despite attacker's prior squatting attempt!
      // Also test concurrent double-verification race: launching two simultaneous calls MUST issue strictly 1 license.
      const legitSub = paymentService.submitTransactionHash({
        userId: buyer.id,
        orderCode: legitimateOrder.order_code,
        txHash: sampleTxHash,
      });
      const [r1, r2] = await Promise.allSettled([
        paymentService.verifyPaymentOnChain(legitSub.payment.id, { rpcProvider: mockRpc }),
        paymentService.verifyPaymentOnChain(legitSub.payment.id, { rpcProvider: mockRpc }),
      ]);

      const fulfilled = [r1, r2].filter((r) => r.status === 'fulfilled');
      expect(fulfilled.length).toBe(1);
      const legitVerify = (fulfilled[0] as PromiseFulfilledResult<Awaited<ReturnType<typeof paymentService.verifyPaymentOnChain>>>).value;

      expect(legitVerify.verification.valid).toBe(true);
      expect(legitVerify.payment.status).toBe('confirmed');
      expect(legitVerify.order.status).toBe('confirmed');
      expect(legitVerify.licenseKey).toMatch(/^EDGE-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}$/);

      const subCount = (
        db.prepare('SELECT COUNT(*) AS cnt FROM subscriptions WHERE order_id = ?').get(legitimateOrder.id) as { cnt: number }
      ).cnt;
      const licCount = (
        db.prepare('SELECT COUNT(*) AS cnt FROM licenses WHERE user_id = ?').get(buyer.id) as { cnt: number }
      ).cnt;
      expect(subCount).toBe(1);
      expect(licCount).toBe(1);

      // Notification queued for user
      const notif = db
        .prepare(`SELECT type, status FROM notifications WHERE user_id = ?`)
        .get(buyer.id) as { type: string; status: string } | undefined;
      expect(notif?.type).toBe('LICENSE_ISSUED');
    } finally {
      db.close();
    }
  });

  it('isolates expectedSenderWallet transfers in multi-log batch transactions (prevents piggybacking on another sender)', () => {
    const batchReceipt = makeReceipt(1n, {
      logs: [
        {
          address: PAYMENT_NETWORK.usdcContractAddress,
          topics: [
            PAYMENT_NETWORK.erc20TransferTopic,
            padAddressTopic(senderWallet),
            padAddressTopic(PAYMENT_NETWORK.destinationWalletAddress),
          ],
          data: encodeUint256(1n), // only 1 micro-USDC from expected sender
        },
        {
          address: PAYMENT_NETWORK.usdcContractAddress,
          topics: [
            PAYMENT_NETWORK.erc20TransferTopic,
            padAddressTopic(otherWallet),
            padAddressTopic(PAYMENT_NETWORK.destinationWalletAddress),
          ],
          data: encodeUint256(4_990_122n), // bulk sent by unrelated wallet
        },
      ],
    });

    const res = verifyPolygonUsdcReceipt({
      txHash: sampleTxHash,
      receipt: batchReceipt,
      latestBlockNumber: 62500040,
      expectedAmountUsdcMicro: 4_990_123,
      chainId: 137,
      expectedSenderWallet: senderWallet,
      requireExactAmount: true,
    });
    expect(res.valid).toBe(false);
    expect(res.reason).toBe('UNDERPAID_AMOUNT');
    expect(res.matchedAmountUsdcMicro).toBe(1);
  });

  it('handles PolygonRpcClient HTTP errors and JSON-RPC error responses safely without connecting to mainnet', async () => {
    const failingRpc = new PolygonRpcClient('http://127.0.0.1:1/mock-rpc', {
      timeoutMs: 500,
      fetchImpl: async () => new Response('Bad Gateway', { status: 502 }),
    });
    await expect(failingRpc.getChainId()).rejects.toThrow(/POLYGON_RPC_HTTP_502/);

    const jsonRpcErr = new PolygonRpcClient('http://127.0.0.1:1/mock-rpc', {
      fetchImpl: async () =>
        new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, error: { message: 'rate limited' } }), {
          status: 200,
        }),
    });
    await expect(jsonRpcErr.getLatestBlockNumber()).rejects.toThrow(/POLYGON_RPC_ERROR/);
  });
});
