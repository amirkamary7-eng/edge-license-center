import Database from 'better-sqlite3';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { afterEach, describe, expect, it } from 'vitest';
import { verifyAndDecryptR2BackupForTest } from '../cloudflare-worker/src/backupR2';
import { verifyRsaSha256 } from '../cloudflare-worker/src/crypto';
import type {
  D1Database,
  D1PreparedStatement,
  D1Result,
  R2Bucket,
  R2ObjectBody,
  WorkerEnv,
} from '../cloudflare-worker/src/d1Types';
import worker, { resetWorkerRateLimiterForTests } from '../cloudflare-worker/src/index';
import { DOMAIN_CONSTANTS } from '../cloudflare-worker/src/d1Types';
import { verifyPaymentOnChainD1 } from '../cloudflare-worker/src/ordersAndPayments';
import type { PolygonRpcProvider } from '../cloudflare-worker/src/polygon';
import { createSignedTelegramInitData } from '../src/server/security/telegramAuth';

/**
 * Genuine SQLite-backed D1Database adapter (runs real D1 SQL migrations with PRAGMA foreign_keys = ON).
 */
function createSqliteD1Adapter(): { db: D1Database; rawDb: Database.Database } {
  const rawDb = new Database(':memory:');
  rawDb.pragma('foreign_keys = ON');

  const m1 = fs.readFileSync(
    path.resolve(process.cwd(), 'cloudflare-worker/migrations/0001_path_b1_d1_schema.sql'),
    'utf8'
  );
  const m2 = fs.readFileSync(
    path.resolve(process.cwd(), 'cloudflare-worker/migrations/0002_seed_core_data.sql'),
    'utf8'
  );
  rawDb.exec(m1);
  rawDb.exec(m2);

  class SqliteStmt implements D1PreparedStatement {
    private params: unknown[] = [];
    constructor(private readonly sql: string) {}

    bind(...values: unknown[]): D1PreparedStatement {
      this.params = values;
      return this;
    }

    async first<T = Record<string, unknown>>(colName?: string): Promise<T | null> {
      const stmt = rawDb.prepare(this.sql);
      const row = (stmt.reader ? stmt.get(...this.params) : stmt.get(...this.params)) as
        | Record<string, unknown>
        | undefined;
      if (!row) return null;
      if (colName) return (row[colName] as T) ?? null;
      return row as T;
    }

    async all<T = Record<string, unknown>>(): Promise<D1Result<T>> {
      const stmt = rawDb.prepare(this.sql);
      if (stmt.reader) {
        const results = stmt.all(...this.params) as T[];
        return { results, success: true, meta: { changes: 0, last_row_id: 0 } };
      }
      const info = stmt.run(...this.params);
      return {
        results: [],
        success: true,
        meta: { changes: info.changes, last_row_id: Number(info.lastInsertRowid) },
      };
    }

    async run(): Promise<D1Result> {
      const stmt = rawDb.prepare(this.sql);
      if (stmt.reader) {
        const results = stmt.all(...this.params) as Record<string, unknown>[];
        return { results, success: true, meta: { changes: 0, last_row_id: 0 } };
      }
      const info = stmt.run(...this.params);
      return {
        results: [],
        success: true,
        meta: { changes: info.changes, last_row_id: Number(info.lastInsertRowid) },
      };
    }

    execSyncInternal(): D1Result {
      const stmt = rawDb.prepare(this.sql);
      if (stmt.reader) {
        const results = stmt.all(...this.params) as Record<string, unknown>[];
        return { results, success: true, meta: { changes: 0, last_row_id: 0 } };
      }
      const info = stmt.run(...this.params);
      return {
        results: [],
        success: true,
        meta: { changes: info.changes, last_row_id: Number(info.lastInsertRowid) },
      };
    }
  }

  const db: D1Database = {
    prepare(query: string) {
      return new SqliteStmt(query);
    },
    async batch<T = Record<string, unknown>>(statements: D1PreparedStatement[]): Promise<Array<D1Result<T>>> {
      const tx = rawDb.transaction(() => {
        return statements.map((s) => (s as SqliteStmt).execSyncInternal() as D1Result<T>);
      });
      return tx();
    },
    async exec(query: string) {
      rawDb.exec(query);
      return { count: 1, duration: 1 };
    },
  };

  return { db, rawDb };
}

function createInMemoryR2Bucket(): R2Bucket {
  const store = new Map<
    string,
    { data: Uint8Array; customMetadata?: Record<string, string>; uploaded: Date }
  >();
  return {
    async put(key, value, options) {
      const bytes =
        typeof value === 'string'
          ? new TextEncoder().encode(value)
          : value instanceof ArrayBuffer
          ? new Uint8Array(value)
          : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
      store.set(key, {
        data: bytes,
        customMetadata: options?.customMetadata,
        uploaded: new Date(),
      });
      return { key };
    },
    async get(key): Promise<R2ObjectBody | null> {
      const item = store.get(key);
      if (!item) return null;
      return {
        key,
        size: item.data.byteLength,
        customMetadata: item.customMetadata,
        async arrayBuffer() {
          return item.data.buffer.slice(item.data.byteOffset, item.data.byteOffset + item.data.byteLength) as ArrayBuffer;
        },
        async text() {
          return new TextDecoder().decode(item.data);
        },
      };
    },
    async list(options) {
      const prefix = options?.prefix ?? '';
      const objects = Array.from(store.entries())
        .filter(([k]) => k.startsWith(prefix))
        .map(([key, v]) => ({ key, size: v.data.byteLength, uploaded: v.uploaded }));
      return { objects, truncated: false };
    },
    async delete(keys) {
      const arr = Array.isArray(keys) ? keys : [keys];
      for (const k of arr) store.delete(k);
    },
  };
}

function generateRsaPkcs8KeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  return { publicKeyPem: publicKey, privateKeyPem: privateKey };
}

function generateAndroidEcdsaP256KeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256',
  });
  const spkiDer = publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
  return {
    publicKeySpkiBase64: spkiDer.toString('base64'),
    signMessageDerBase64(message: string): string {
      const signer = crypto.createSign('SHA256');
      signer.update(message, 'utf8');
      signer.end();
      return signer.sign(privateKey).toString('base64');
    },
  };
}

function encodeTransferDataHex(microUsdc: number): string {
  return `0x${BigInt(microUsdc).toString(16).padStart(64, '0')}`;
}

function padTopicAddress(addr: string): string {
  return `0x${addr.toLowerCase().replace(/^0x/, '').padStart(64, '0')}`;
}

describe('Phase 1.6 Path B-1 Staging Implementation (Cloudflare Worker + D1 + R2 + Cron + Keystore PoP)', () => {
  const cleanups: Array<() => void> = [];

  afterEach(() => {
    while (cleanups.length > 0) cleanups.pop()!();
    resetWorkerRateLimiterForTests();
  });

  it('applies D1 Path B-1 migrations 0001+0002 with frozen plan prices, immutable settings triggers, and foreign keys', async () => {
    const { db, rawDb } = createSqliteD1Adapter();
    cleanups.push(() => rawDb.close());

    const healthRes = await worker.fetch(new Request('https://staging.edge.workers.dev/v1/health'), {
      DB: db,
      PAYMENT_VERIFICATION_MODE: 'DRY_RUN',
      LICENSE_ISSUANCE_MODE: 'DRY_RUN',
    });
    expect(healthRes.status).toBe(200);
    const health = (await healthRes.json()) as { ok: boolean; architecture: string; paymentMode: string; licenseMode: string };
    expect(health.ok).toBe(true);
    expect(health.architecture).toBe('PATH_B1_CLOUDFLARE_WORKER_D1');
    expect(health.paymentMode).toBe('DRY_RUN');
    expect(health.licenseMode).toBe('DRY_RUN');

    const cfgRes = await worker.fetch(new Request('https://staging.edge.workers.dev/api/v1/public/config'), { DB: db });
    const cfg = (await cfgRes.json()) as { plans: Array<{ code: string; price_usdc_micro: number }> };
    expect(cfg.plans.map((p) => [p.code, p.price_usdc_micro])).toEqual([
      ['EDGE_1M', 1990000],
      ['EDGE_3M', 4990000],
      ['EDGE_6M', 8990000],
      ['EDGE_12M', 16990000],
    ]);

    // Immutable settings protection trigger
    expect(() =>
      rawDb.prepare(`UPDATE system_settings SET value = '0x000' WHERE key = 'payment_destination_wallet'`).run()
    ).toThrow(/IMMUTABLE_SYSTEM_SETTING/);
  });

  it('enforces DRY_RUN safety locks on Mini App orders/payments and blocks unauthenticated & replayed initData', async () => {
    const { db, rawDb } = createSqliteD1Adapter();
    cleanups.push(() => rawDb.close());

    const botToken = '123456:STAGING_BOT_TOKEN';
    const env: WorkerEnv = {
      DB: db,
      TELEGRAM_BOT_TOKEN: botToken,
      SESSION_SECRET: 'staging-session-secret-0123456789abcdef',
      PAYMENT_VERIFICATION_MODE: 'DRY_RUN',
      LICENSE_ISSUANCE_MODE: 'DRY_RUN',
      TELEGRAM_BOT_SEND_ENABLED: 'false',
      BOOTSTRAP_SUPER_ADMIN_TELEGRAM_ID: '999000111',
    };

    // Unauthenticated rejected 401
    const unauth = await worker.fetch(new Request('https://staging.edge.workers.dev/api/v1/me'), env);
    expect(unauth.status).toBe(401);

    // Single-use initData exchange -> Bearer token
    const initData = createSignedTelegramInitData({ id: 55112233, first_name: 'StagingBuyer' }, botToken);
    const ex1 = await worker.fetch(
      new Request('https://staging.edge.workers.dev/api/v1/auth/telegram', {
        method: 'POST',
        headers: { 'X-Telegram-Init-Data': initData },
      }),
      env
    );
    expect(ex1.status).toBe(200);
    const { token } = (await ex1.json()) as { token: string };
    expect(token.startsWith('edge1.')).toBe(true);

    // Replay of same initData blocked
    const exReplay = await worker.fetch(
      new Request('https://staging.edge.workers.dev/api/v1/auth/telegram', {
        method: 'POST',
        headers: { 'X-Telegram-Init-Data': initData },
      }),
      env
    );
    expect(exReplay.status).toBe(401);

    // Create order idempotently in DRY_RUN -> unique micro-offset
    const rOrder1 = await worker.fetch(
      new Request('https://staging.edge.workers.dev/api/v1/orders', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
          'Idempotency-Key': 'idem-b1-order-0001',
        },
        body: JSON.stringify({ planCode: 'EDGE_1M' }),
      }),
      env
    );
    expect(rOrder1.status).toBe(201);
    const { order } = (await rOrder1.json()) as {
      order: { order_code: string; status: string; payable_amount_usdc_micro: number; unique_offset_micro: number };
    };
    expect(order.status).toBe('draft_phase0');
    expect(order.unique_offset_micro).toBeGreaterThanOrEqual(1);
    expect(order.payable_amount_usdc_micro).toBe(1990000 + order.unique_offset_micro);

    // Idempotency replay returns cached response; conflicting body returns 409
    const rOrderReplay = await worker.fetch(
      new Request('https://staging.edge.workers.dev/api/v1/orders', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
          'Idempotency-Key': 'idem-b1-order-0001',
        },
        body: JSON.stringify({ planCode: 'EDGE_1M' }),
      }),
      env
    );
    expect(rOrderReplay.headers.get('X-Idempotent-Replayed')).toBe('true');

    const rOrderConflict = await worker.fetch(
      new Request('https://staging.edge.workers.dev/api/v1/orders', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
          'Idempotency-Key': 'idem-b1-order-0001',
        },
        body: JSON.stringify({ planCode: 'EDGE_3M' }),
      }),
      env
    );
    expect(rOrderConflict.status).toBe(409);

    // Submit TxHash in DRY_RUN -> dry_run_recorded, zero license issued
    const txHash = `0x${'a'.repeat(64)}`;
    const txRes = await worker.fetch(
      new Request('https://staging.edge.workers.dev/api/v1/payments/submit-tx', {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ orderCode: order.order_code, txHash }),
      }),
      env
    );
    expect(txRes.status).toBe(201);
    const txJson = (await txRes.json()) as { dryRunBlocked: boolean; payment: { id: number; status: string } };
    expect(txJson.dryRunBlocked).toBe(true);
    expect(txJson.payment.status).toBe('dry_run_recorded');

    // verifyPaymentOnChainD1 MUST refuse in DRY_RUN
    await expect(verifyPaymentOnChainD1(db, env, txJson.payment.id)).rejects.toMatchObject({
      code: 'DRY_RUN_VERIFICATION_BLOCKED',
    });
  });

  it('completes isolated simulated LIVE payment -> atomic RSA license -> Android ECDSA PoP activation -> signed receipt -> Edge-First revocation -> renewal block', async () => {
    const { db, rawDb } = createSqliteD1Adapter();
    cleanups.push(() => rawDb.close());

    const rsa = generateRsaPkcs8KeyPair();
    const botToken = '123456:STAGING_LIVE_SIM_TOKEN';
    const adminTgId = '999000111';
    const buyerWallet = '0x1111111111111111111111111111111111111111';

    const env: WorkerEnv = {
      DB: db,
      TELEGRAM_BOT_TOKEN: botToken,
      SESSION_SECRET: 'staging-live-sim-session-secret-0123456789',
      PAYMENT_VERIFICATION_MODE: 'LIVE',
      LICENSE_ISSUANCE_MODE: 'LIVE',
      TELEGRAM_BOT_SEND_ENABLED: 'false',
      BOOTSTRAP_SUPER_ADMIN_TELEGRAM_ID: adminTgId,
      RSA_PRIVATE_KEY_PEM: rsa.privateKeyPem,
      RSA_PUBLIC_KEY_PEM: rsa.publicKeyPem,
      RSA_KEY_ID: 'edge-rsa-staging-v1',
    };

    const buyerInit = createSignedTelegramInitData({ id: 77889900, first_name: 'AndroidCustomer' }, botToken);
    const adminInit = createSignedTelegramInitData({ id: Number(adminTgId), first_name: 'AMIRBTC' }, botToken);

    // 1. Create order with expectedSenderWallet
    const ordRes = await worker.fetch(
      new Request('https://staging.edge.workers.dev/api/v1/orders', {
        method: 'POST',
        headers: { 'X-Telegram-Init-Data': buyerInit, 'Content-Type': 'application/json' },
        body: JSON.stringify({ planCode: 'EDGE_3M', expectedSenderWallet: buyerWallet }),
      }),
      env
    );
    expect(ordRes.status).toBe(201);
    const { order } = (await ordRes.json()) as {
      order: { id: number; order_code: string; payable_amount_usdc_micro: number; created_at: string };
    };

    // 2. Submit TxHash
    const validTxHash = `0x${'b'.repeat(64)}`;
    const subRes = await worker.fetch(
      new Request('https://staging.edge.workers.dev/api/v1/payments/submit-tx', {
        method: 'POST',
        headers: { 'X-Telegram-Init-Data': buyerInit, 'Content-Type': 'application/json' },
        body: JSON.stringify({ orderCode: order.order_code, txHash: validTxHash }),
      }),
      env
    );
    expect(subRes.status).toBe(201);
    const { payment } = (await subRes.json()) as { payment: { id: number } };

    // 3. Duplicate TxHash across another order MUST fail with 409 DUPLICATE_TX_HASH
    const ord2Res = await worker.fetch(
      new Request('https://staging.edge.workers.dev/api/v1/orders', {
        method: 'POST',
        headers: { 'X-Telegram-Init-Data': buyerInit, 'Content-Type': 'application/json' },
        body: JSON.stringify({ planCode: 'EDGE_1M', expectedSenderWallet: buyerWallet }),
      }),
      env
    );
    const { order: order2 } = (await ord2Res.json()) as { order: { order_code: string } };
    const dupTxRes = await worker.fetch(
      new Request('https://staging.edge.workers.dev/api/v1/payments/submit-tx', {
        method: 'POST',
        headers: { 'X-Telegram-Init-Data': buyerInit, 'Content-Type': 'application/json' },
        body: JSON.stringify({ orderCode: order2.order_code, txHash: validTxHash }),
      }),
      env
    );
    expect(dupTxRes.status).toBe(409);

    // 4. Mock Polygon PoS RPC: test < 30 confirmations pending, then >= 30 confirmations Native USDC confirmed
    const orderCreatedEpoch = Math.floor(new Date(order.created_at).getTime() / 1000);
    let latestBlock = 50000010; // only 11 confirmations (tx in block 50000000)
    const mockRpc: PolygonRpcProvider = {
      async getChainId() {
        return 137;
      },
      async getLatestBlockNumber() {
        return latestBlock;
      },
      async getBlockTimestamp() {
        return orderCreatedEpoch + 20;
      },
      async getTransactionReceipt(txHash) {
        return {
          transactionHash: txHash,
          status: '0x1',
          blockNumber: `0x${(50000000).toString(16)}`,
          from: buyerWallet,
          to: DOMAIN_CONSTANTS.usdcContractAddress,
          logs: [
            {
              address: DOMAIN_CONSTANTS.usdcContractAddress,
              topics: [
                DOMAIN_CONSTANTS.erc20TransferTopic,
                padTopicAddress(buyerWallet),
                padTopicAddress(DOMAIN_CONSTANTS.destinationWalletAddress),
              ],
              data: encodeTransferDataHex(order.payable_amount_usdc_micro),
            },
          ],
        };
      },
    };

    const pendingVerify = await verifyPaymentOnChainD1(db, env, payment.id, { rpcProvider: mockRpc });
    expect(pendingVerify.verification.valid).toBe(false);
    expect(pendingVerify.verification.reason).toBe('INSUFFICIENT_CONFIRMATIONS');
    expect(pendingVerify.payment.status).toBe('submitted');

    // Advance finality >= 30 blocks
    latestBlock = 50000035;
    const confirmedVerify = await verifyPaymentOnChainD1(db, env, payment.id, { rpcProvider: mockRpc });
    expect(confirmedVerify.verification.valid).toBe(true);
    expect(confirmedVerify.payment.status).toBe('confirmed');
    expect(confirmedVerify.licenseKey).toMatch(/^EDGE-[0-9A-F]{4}-/);
    const licenseKey = confirmedVerify.licenseKey!;

    // 5. Android Keystore ECDSA P-256 Challenge -> Activate (ZERO shared APK secret)
    const androidKey = generateAndroidEcdsaP256KeyPair();
    const deviceKeyId = 'dk_pixel9_hw_001';
    const deviceFingerprint = 'fp_pixel9_001';

    const chgRes = await worker.fetch(
      new Request('https://staging.edge.workers.dev/v1/license/challenge', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ licenseKey, deviceKeyId, deviceFingerprint }),
      }),
      env
    );
    expect(chgRes.status).toBe(200);
    const { challengeId, challengeNonce } = (await chgRes.json()) as {
      challengeId: string;
      challengeNonce: string;
    };

    const proofMsg = ['EDGE_ACTIVATE_V1', challengeId, challengeNonce, licenseKey, deviceKeyId, deviceFingerprint].join('\n');
    const actRes = await worker.fetch(
      new Request('https://staging.edge.workers.dev/v1/license/activate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          challengeId,
          licenseKey,
          deviceKeyId,
          deviceFingerprint,
          devicePublicKeySpkiBase64: androidKey.publicKeySpkiBase64,
          proofSignatureBase64: androidKey.signMessageDerBase64(proofMsg),
          attestationLevel: 'strongbox',
          deviceModel: 'Pixel 9 Pro',
        }),
      }),
      env
    );
    expect(actRes.status).toBe(200);
    const actJson = (await actRes.json()) as {
      activated: boolean;
      licensePayloadJson: string;
      licenseSignatureBase64: string;
      receipt: Record<string, unknown>;
      receiptSignatureBase64: string;
    };
    expect(actJson.activated).toBe(true);
    expect(await verifyRsaSha256(actJson.licensePayloadJson, actJson.licenseSignatureBase64, rsa.publicKeyPem)).toBe(true);

    // 6. Android Daily Signed Validation -> valid=true + signed RSA receipt + anti-replay nonce
    const validateBody = JSON.stringify({ licenseKey, deviceKeyId, appVersion: '2.2.0' });
    const ts = String(Math.floor(Date.now() / 1000));
    const nonce = 'nonce-android-valid-0001';
    const bodySha = crypto.createHash('sha256').update(validateBody).digest('hex');
    const canonicalSignMsg = `POST\n/v1/license/validate\n${ts}\n${nonce}\n${licenseKey}\n${deviceKeyId}\n${bodySha}`;
    const devSig = androidKey.signMessageDerBase64(canonicalSignMsg);

    const valRes = await worker.fetch(
      new Request('https://staging.edge.workers.dev/v1/license/validate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'CF-Connecting-IP': '198.51.100.44',
          'X-Device-Timestamp': ts,
          'X-Device-Nonce': nonce,
          'X-Device-Signature': devSig,
        },
        body: validateBody,
      }),
      env
    );
    expect(valRes.status).toBe(200);
    const valJson = (await valRes.json()) as {
      valid: boolean;
      receipt: { decisionCode: string; offlineGraceSec: number };
      receiptSignatureBase64: string;
    };
    expect(valJson.valid).toBe(true);
    expect(valJson.receipt.decisionCode).toBe('OK');
    expect(valJson.receipt.offlineGraceSec).toBe(72 * 3600);

    // Replay same nonce -> 401 REPLAYED_NONCE
    const replayVal = await worker.fetch(
      new Request('https://staging.edge.workers.dev/v1/license/validate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'CF-Connecting-IP': '198.51.100.44',
          'X-Device-Timestamp': ts,
          'X-Device-Nonce': nonce,
          'X-Device-Signature': devSig,
        },
        body: validateBody,
      }),
      env
    );
    expect(replayVal.status).toBe(401);

    // 7. Edge-First Atomic Revocation by Super Admin -> immediately kills next Android validation + blocks renewal
    const revRes = await worker.fetch(
      new Request(`https://staging.edge.workers.dev/api/v1/admin/licenses/${licenseKey}/status`, {
        method: 'PATCH',
        headers: { 'X-Telegram-Init-Data': adminInit, 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'revoked', reason: 'Chargeback fraud check' }),
      }),
      env
    );
    expect(revRes.status).toBe(200);

    const nonce2 = 'nonce-android-valid-0002';
    const canonicalSignMsg2 = `POST\n/v1/license/validate\n${ts}\n${nonce2}\n${licenseKey}\n${deviceKeyId}\n${bodySha}`;
    const postRevVal = await worker.fetch(
      new Request('https://staging.edge.workers.dev/v1/license/validate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'CF-Connecting-IP': '198.51.100.44',
          'X-Device-Timestamp': ts,
          'X-Device-Nonce': nonce2,
          'X-Device-Signature': androidKey.signMessageDerBase64(canonicalSignMsg2),
        },
        body: validateBody,
      }),
      env
    );
    const postRevJson = (await postRevVal.json()) as {
      valid: boolean;
      reason: string;
      receipt: { revocationSeq: number };
    };
    expect(postRevJson.valid).toBe(false);
    expect(postRevJson.reason).toBe('REVOKED:ADMIN_REVOKED');
    expect(postRevJson.receipt.revocationSeq).toBeGreaterThanOrEqual(1);

    // Attempt renewal on revoked subscription -> MUST be blocked (403)
    const licListRes = await worker.fetch(
      new Request('https://staging.edge.workers.dev/api/v1/licenses', {
        headers: { 'X-Telegram-Init-Data': buyerInit },
      }),
      env
    );
    const { subscriptions } = (await licListRes.json()) as { subscriptions: Array<{ id: number }> };
    const renewBlocked = await worker.fetch(
      new Request('https://staging.edge.workers.dev/api/v1/orders', {
        method: 'POST',
        headers: { 'X-Telegram-Init-Data': buyerInit, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          planCode: 'EDGE_1M',
          orderType: 'renew',
          targetSubscriptionId: subscriptions[0].id,
          expectedSenderWallet: buyerWallet,
        }),
      }),
      env
    );
    expect(renewBlocked.status).toBe(403);
  });

  it('runs @EDGE_LicenceBot webhook fail-closed, deduplicates update_id, executes Daily Cron + R2 AES-GCM/RSA-OAEP encrypted backup & offline recovery', async () => {
    const { db, rawDb } = createSqliteD1Adapter();
    cleanups.push(() => rawDb.close());

    const r2 = createInMemoryR2Bucket();
    const backupKeys = generateRsaPkcs8KeyPair(); // privateKey stays strictly offline!
    let telegramCalls = 0;

    const env: WorkerEnv = {
      DB: db,
      BACKUP_BUCKET: r2,
      BACKUP_RSA_PUBLIC_KEY_PEM: backupKeys.publicKeyPem,
      TELEGRAM_BOT_TOKEN: '123456:STAGING_CRON_WEBHOOK_TOKEN',
      TELEGRAM_WEBHOOK_SECRET: 'staging-webhook-secret-xyz',
      TELEGRAM_BOT_SEND_ENABLED: 'false',
      PAYMENT_VERIFICATION_MODE: 'DRY_RUN',
      LICENSE_ISSUANCE_MODE: 'DRY_RUN',
      BOOTSTRAP_SUPER_ADMIN_TELEGRAM_ID: '999000111',
      MINI_APP_URL: 'https://staging-miniapp.edge.example',
      FETCH_IMPL: async () => {
        telegramCalls += 1;
        return new Response(JSON.stringify({ ok: true, result: { message_id: 1 } }), { status: 200 });
      },
    };

    // 1. Fail-closed 503 when secret missing, 401 when wrong secret
    const wh503 = await worker.fetch(
      new Request('https://staging.edge.workers.dev/api/v1/bot/webhook', {
        method: 'POST',
        body: JSON.stringify({ update_id: 1 }),
      }),
      { ...env, TELEGRAM_WEBHOOK_SECRET: '' }
    );
    expect(wh503.status).toBe(503);

    const wh401 = await worker.fetch(
      new Request('https://staging.edge.workers.dev/api/v1/bot/webhook', {
        method: 'POST',
        headers: { 'X-Telegram-Bot-Api-Secret-Token': 'wrong' },
        body: JSON.stringify({ update_id: 1 }),
      }),
      env
    );
    expect(wh401.status).toBe(401);

    // 2. Valid /start + buy:EDGE_1M + duplicate update_id protection
    const whStart = await worker.fetch(
      new Request('https://staging.edge.workers.dev/api/v1/bot/webhook', {
        method: 'POST',
        headers: { 'X-Telegram-Bot-Api-Secret-Token': 'staging-webhook-secret-xyz' },
        body: JSON.stringify({
          update_id: 1001,
          message: {
            message_id: 1,
            from: { id: 44556677, first_name: 'BotTester' },
            chat: { id: 44556677, type: 'private' },
            text: '/start@EDGE_LicenceBot',
          },
        }),
      }),
      env
    );
    expect(whStart.status).toBe(200);
    const whStartBody = (await whStart.json()) as { duplicate: boolean; dispatched: boolean; reply: { text: string } };
    expect(whStartBody.duplicate).toBe(false);
    expect(whStartBody.dispatched).toBe(false);
    expect(whStartBody.reply.text).toContain('EDGE LICENSE CENTER');

    const whDup = await worker.fetch(
      new Request('https://staging.edge.workers.dev/api/v1/bot/webhook', {
        method: 'POST',
        headers: { 'X-Telegram-Bot-Api-Secret-Token': 'staging-webhook-secret-xyz' },
        body: JSON.stringify({ update_id: 1001 }),
      }),
      env
    );
    expect(((await whDup.json()) as { duplicate: boolean }).duplicate).toBe(true);
    expect(telegramCalls).toBe(0); // TELEGRAM_BOT_SEND_ENABLED=false strictly honored

    // 3. Seed an expired open order & past-due active license to verify Daily Cron cleanup + R2 Encrypted Backup
    await worker.fetch(
      new Request('https://staging.edge.workers.dev/api/v1/bot/webhook', {
        method: 'POST',
        headers: { 'X-Telegram-Bot-Api-Secret-Token': 'staging-webhook-secret-xyz' },
        body: JSON.stringify({
          update_id: 1002,
          callback_query: {
            id: 'cb-1002',
            from: { id: 44556677, first_name: 'BotTester' },
            data: 'buy:EDGE_1M',
          },
        }),
      }),
      env
    );

    rawDb.prepare(`UPDATE orders SET expires_at = '2020-01-01T00:00:00.000Z'`).run();

    // Execute Worker Cron scheduled()
    await worker.scheduled({ cron: '0 0 * * *', scheduledTime: Date.now() }, env);

    const expiredOrder = rawDb.prepare(`SELECT status FROM orders LIMIT 1`).get() as { status: string };
    expect(expiredOrder.status).toBe('expired');

    const cronRow = rawDb
      .prepare(`SELECT status, summary_json FROM cron_runs ORDER BY run_date_utc DESC LIMIT 1`)
      .get() as { status: string; summary_json: string };
    expect(cronRow.status).toBe('completed');
    const summary = JSON.parse(cronRow.summary_json) as {
      expiredOrders: number;
      backupResult: { skipped: boolean; r2Key: string };
    };
    expect(summary.expiredOrders).toBe(1);
    expect(summary.backupResult.skipped).toBe(false);
    expect(summary.backupResult.r2Key).toMatch(/^backups\/d1\//);

    // Verify encrypted R2 backup decrypts cleanly ONLY with the offline private key and matches SHA-256
    const decrypted = await verifyAndDecryptR2BackupForTest(
      r2,
      summary.backupResult.r2Key,
      backupKeys.privateKeyPem
    );
    expect(decrypted.snapshot.schemaVersion).toBe('path_b1_d1_v1');
    expect(decrypted.snapshot.rowCounts.plans).toBe(4);
    expect(decrypted.snapshot.rowCounts.orders).toBe(1);
    expect(telegramCalls).toBe(0);
  });
});
