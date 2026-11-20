import fs from 'fs';
import http from 'http';
import os from 'os';
import path from 'path';
import { afterEach, describe, expect, it } from 'vitest';
import { createApiApp } from '../src/server/app';
import type {
  AnswerCallbackQueryParams,
  SendMessageParams,
  TelegramBotTransport,
} from '../src/server/bot/telegramClient';
import { loadEnv } from '../src/server/config/env';
import { restoreDatabaseBackup } from '../src/server/db/backup';
import { openDatabase, type SqliteDb } from '../src/server/db/connection';
import { runMigrations } from '../src/server/db/migrator';
import {
  BackgroundScheduler,
  runMaintenanceTick,
  runNotificationDispatcherTick,
  runPaymentPollerTick,
  runScheduledBackupTick,
} from '../src/server/jobs/scheduler';
import { LicenseService } from '../src/server/modules/license/licenseService';
import { PaymentService } from '../src/server/modules/payment/paymentService';
import type {
  EvmTransactionReceipt,
  PolygonRpcProvider,
} from '../src/server/modules/payment/polygonVerifier';
import { SupportService } from '../src/server/modules/support/supportService';
import { UserRepository } from '../src/server/modules/users/userRepository';
import { generateEphemeralRsaKeyPair } from '../src/server/security/rsaSigner';
import { createSignedTelegramInitData } from '../src/server/security/telegramAuth';
import { PAYMENT_NETWORK } from '../src/shared/constants';

const TRANSFER_TOPIC =
  '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';

function padAddressTopic(addr: string): string {
  return `0x${'0'.repeat(24)}${addr.toLowerCase().replace(/^0x/, '')}`;
}

function encodeUint256Hex(amountMicro: number): string {
  return `0x${BigInt(amountMicro).toString(16).padStart(64, '0')}`;
}

function buildMockReceipt(params: {
  txHash: string;
  sender: string;
  receiver?: string;
  contract?: string;
  amountMicro: number;
  blockNumber: number;
}): EvmTransactionReceipt {
  return {
    transactionHash: params.txHash,
    status: '0x1',
    blockNumber: `0x${params.blockNumber.toString(16)}`,
    from: params.sender,
    to: params.contract ?? PAYMENT_NETWORK.usdcContractAddress,
    logs: [
      {
        address: params.contract ?? PAYMENT_NETWORK.usdcContractAddress,
        topics: [
          TRANSFER_TOPIC,
          padAddressTopic(params.sender),
          padAddressTopic(params.receiver ?? PAYMENT_NETWORK.destinationWalletAddress),
        ],
        data: encodeUint256Hex(params.amountMicro),
      },
    ],
  };
}

class RecordingBotClient implements TelegramBotTransport {
  readonly sentMessages: SendMessageParams[] = [];
  readonly callbackAnswers: AnswerCallbackQueryParams[] = [];
  failNextMessages = 0;

  async sendMessage(params: SendMessageParams): Promise<{ ok: boolean; messageId?: number }> {
    if (this.failNextMessages > 0) {
      this.failNextMessages -= 1;
      throw new Error('TELEGRAM_API_ERROR_sendMessage_502');
    }
    this.sentMessages.push(params);
    return { ok: true, messageId: this.sentMessages.length };
  }

  async answerCallbackQuery(params: AnswerCallbackQueryParams): Promise<{ ok: boolean }> {
    this.callbackAnswers.push(params);
    return { ok: true };
  }
}

describe('Phase 1.2 Staging Integration — @EDGE_LicenceBot E2E, Poller, Notifications & Backup/Restore', () => {
  const cleanups: Array<() => Promise<void> | void> = [];

  afterEach(async () => {
    while (cleanups.length > 0) {
      const fn = cleanups.pop()!;
      await fn();
    }
  });

  it('executes full @EDGE_LicenceBot webhook commands end-to-end (start, plans, buy, tx/pay, status, renew, upgrade, profile, license, support, ticket)', async () => {
    const db = openDatabase(':memory:');
    runMigrations(db);
    const botClient = new RecordingBotClient();
    const webhookSecret = 'staging-webhook-secret-998877';

    const env = loadEnv({
      NODE_ENV: 'test',
      APP_URL: 'https://staging.edge-license.example.com',
      PAYMENT_VERIFICATION_MODE: 'DRY_RUN',
      LICENSE_ISSUANCE_MODE: 'DRY_RUN',
      TELEGRAM_WEBHOOK_SECRET: webhookSecret,
      TELEGRAM_BOT_SEND_ENABLED: 'false',
      RATE_LIMIT_ENABLED: 'false',
    });

    const app = createApiApp({ db, env, botClient });
    const server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
    const addr = server.address();
    if (!addr || typeof addr === 'string') throw new Error('Bind failed');
    const baseUrl = `http://127.0.0.1:${addr.port}`;

    cleanups.push(async () => {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      db.close();
    });

    let updateId = 1000;
    const sendWebhook = async (payload: Record<string, unknown>) => {
      const res = await fetch(`${baseUrl}/api/v1/bot/webhook`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Telegram-Bot-Api-Secret-Token': webhookSecret,
        },
        body: JSON.stringify({ update_id: ++updateId, ...payload }),
      });
      expect(res.status).toBe(200);
      return (await res.json()) as {
        ok: boolean;
        reply?: { text: string; inlineKeyboard: unknown[] };
      };
    };

    const userFrom = { id: 55110022, first_name: 'AmirTest', username: 'amir_staging', language_code: 'fa' };

    // 1. /start@EDGE_LicenceBot
    const startRes = await sendWebhook({
      message: { message_id: 1, from: userFrom, chat: { id: 55110022, type: 'private' }, text: '/start@EDGE_LicenceBot' },
    });
    expect(startRes.reply?.text).toContain('@EDGE_LicenceBot');
    expect(botClient.sentMessages.length).toBe(1);

    // 2. /plans
    const plansRes = await sendWebhook({
      message: { message_id: 2, from: userFrom, chat: { id: 55110022, type: 'private' }, text: '/plans' },
    });
    expect(plansRes.reply?.text).toContain('EDGE_1M');
    expect(plansRes.reply?.text).toContain('EDGE_12M');

    // 3. Callback buy:EDGE_3M
    const buyRes = await sendWebhook({
      callback_query: { id: 'cb-buy-3m', from: userFrom, data: 'buy:EDGE_3M' },
    });
    expect(buyRes.reply?.text).toContain('EDGE-');
    expect(botClient.callbackAnswers.some((c) => c.callbackQueryId === 'cb-buy-3m')).toBe(true);

    const orderMatch = buyRes.reply?.text.match(/EDGE-[A-Z0-9-]+/);
    expect(orderMatch).toBeTruthy();
    const orderCode = orderMatch![0];

    // 4. /pay alias (submits TxID in DRY_RUN mode)
    const txHash = `0x${'a'.repeat(64)}`;
    const payRes = await sendWebhook({
      message: {
        message_id: 3,
        from: userFrom,
        chat: { id: 55110022, type: 'private' },
        text: `/pay ${orderCode} ${txHash}`,
      },
    });
    expect(payRes.reply?.text).toContain('DRY_RUN');
    expect(payRes.reply?.text).toContain('dry_run_recorded');

    // 5. /status shows order + payment status
    const statusRes = await sendWebhook({
      message: { message_id: 4, from: userFrom, chat: { id: 55110022, type: 'private' }, text: '/status' },
    });
    expect(statusRes.reply?.text).toContain(orderCode);
    expect(statusRes.reply?.text).toContain('dry_run_recorded');

    // 6. /renew & /upgrade (no prior active sub -> prompts plan purchase cleanly)
    const renewRes = await sendWebhook({
      message: { message_id: 5, from: userFrom, chat: { id: 55110022, type: 'private' }, text: '/renew' },
    });
    expect(renewRes.reply?.text).toContain('اشتراک قبلی');

    const upgradeRes = await sendWebhook({
      message: { message_id: 6, from: userFrom, chat: { id: 55110022, type: 'private' }, text: '/upgrade' },
    });
    expect(upgradeRes.reply?.text).toContain('اشتراک قبلی');

    // 7. /profile & /license
    const profileRes = await sendWebhook({
      message: { message_id: 7, from: userFrom, chat: { id: 55110022, type: 'private' }, text: '/profile' },
    });
    expect(profileRes.reply?.text).toContain('55110022');

    const licenseRes = await sendWebhook({
      message: { message_id: 8, from: userFrom, chat: { id: 55110022, type: 'private' }, text: '/license' },
    });
    expect(licenseRes.reply?.text).toContain('لایسنس');

    // 8. /support & /ticket
    const supportRes = await sendWebhook({
      message: { message_id: 9, from: userFrom, chat: { id: 55110022, type: 'private' }, text: '/support' },
    });
    expect(supportRes.reply?.text).toContain('/ticket');

    const ticketRes = await sendWebhook({
      message: {
        message_id: 10,
        from: userFrom,
        chat: { id: 55110022, type: 'private' },
        text: '/ticket Staging Check | Testing E2E ticket creation via @EDGE_LicenceBot',
      },
    });
    expect(ticketRes.reply?.text).toContain('TKT-');
  });

  it('verifies Mini App initData auth, anti-replay, RBAC roles, and banned/suspended user blocking', async () => {
    const db = openDatabase(':memory:');
    runMigrations(db);
    const botToken = '99999999:STAGING_TEST_BOT_TOKEN_NOT_REAL';
    const sessionSecret = 'staging-session-secret-0123456789';

    const env = loadEnv({
      NODE_ENV: 'test',
      TELEGRAM_BOT_TOKEN: botToken,
      SESSION_SECRET: sessionSecret,
      BOOTSTRAP_SUPER_ADMIN_TELEGRAM_ID: '77000001',
      RATE_LIMIT_ENABLED: 'false',
    });

    const app = createApiApp({ db, env });
    const server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
    const addr = server.address();
    if (!addr || typeof addr === 'string') throw new Error('Bind failed');
    const baseUrl = `http://127.0.0.1:${addr.port}`;

    cleanups.push(async () => {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      db.close();
    });

    // Exchange initData for super_admin
    const superInit = createSignedTelegramInitData(
      { id: 77000001, first_name: 'Owner', username: 'amirbtc_owner' },
      botToken
    );
    const ex1 = await fetch(`${baseUrl}/api/v1/auth/telegram`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Telegram-Init-Data': superInit },
    });
    expect(ex1.status).toBe(200);
    const superSession = (await ex1.json()) as { token: string; adminRole: string };
    expect(superSession.adminRole).toBe('super_admin');

    // Replay of identical initData must fail closed (401)
    const exReplay = await fetch(`${baseUrl}/api/v1/auth/telegram`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Telegram-Init-Data': superInit },
    });
    expect(exReplay.status).toBe(401);

    // Regular customer session
    const custInit = createSignedTelegramInitData(
      { id: 77000002, first_name: 'Customer', username: 'edge_buyer' },
      botToken
    );
    const custEx = await fetch(`${baseUrl}/api/v1/auth/telegram`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Telegram-Init-Data': custInit },
    });
    expect(custEx.status).toBe(200);
    const custSession = (await custEx.json()) as { token: string; user: { id: number }; adminRole: null };
    expect(custSession.adminRole).toBeNull();

    // Customer cannot access admin dashboard (403)
    const deniedAdmin = await fetch(`${baseUrl}/api/v1/admin/dashboard`, {
      headers: { Authorization: `Bearer ${custSession.token}` },
    });
    expect(deniedAdmin.status).toBe(403);

    // Super admin suspends customer -> customer's active Bearer token immediately blocked (403)
    const suspendRes = await fetch(`${baseUrl}/api/v1/admin/users/${custSession.user.id}/status`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${superSession.token}`,
      },
      body: JSON.stringify({ status: 'suspended' }),
    });
    expect(suspendRes.status).toBe(200);

    const blockedMe = await fetch(`${baseUrl}/api/v1/me`, {
      headers: { Authorization: `Bearer ${custSession.token}` },
    });
    expect(blockedMe.status).toBe(403);
    const blockedBody = (await blockedMe.json()) as { error: string; status: string };
    expect(blockedBody.error).toBe('ACCOUNT_RESTRICTED');
    expect(blockedBody.status).toBe('suspended');
  });

  it('runs Background Payment Poller with Mock Polygon RPC (skips in DRY_RUN, confirms 30-block finality, issues RSA license & queues notification)', async () => {
    const db = openDatabase(':memory:');
    runMigrations(db);
    cleanups.push(() => {
      db.close();
    });

    const users = new UserRepository(db);
    const buyer = users.upsertFromTelegram({
      telegramId: '88000001',
      firstName: 'PollerBuyer',
      username: 'poller_buyer',
    });

    const keys = generateEphemeralRsaKeyPair();
    const licenseService = new LicenseService(db, {
      issuanceMode: 'LIVE',
      rsaPrivateKeyPem: keys.privateKeyPem,
      rsaPublicKeyPem: keys.publicKeyPem,
      rsaKeyId: 'staging-rsa-v1',
    });

    const buyerWallet = '0x1111111111111111111111111111111111111111';
    const txHash = `0x${'c'.repeat(64)}`;
    let mockLatestBlock = 60_000_010; // only 11 confirmations initially (< 30)
    let mockAmountMicro = 0;
    const nowEpoch = Math.floor(Date.now() / 1000);

    const mockRpc: PolygonRpcProvider = {
      async getChainId() {
        return 137;
      },
      async getLatestBlockNumber() {
        return mockLatestBlock;
      },
      async getTransactionReceipt(hash: string) {
        return buildMockReceipt({
          txHash: hash,
          sender: buyerWallet,
          amountMicro: mockAmountMicro,
          blockNumber: 60_000_000,
        });
      },
      async getBlockTimestamp() {
        return nowEpoch + 5;
      },
    };

    const paymentService = new PaymentService(db, {
      verificationMode: 'LIVE',
      minConfirmations: 30,
      requireSenderWalletInLive: true,
      rpcProvider: mockRpc,
      licenseService,
    });

    // 1. DRY_RUN guardrail: poller must strictly skip without calling RPC
    const dryRunTick = await runPaymentPollerTick({
      db,
      paymentService,
      verificationMode: 'DRY_RUN',
    });
    expect(dryRunTick.skipped).toBe(true);
    expect(dryRunTick.reason).toBe('DRY_RUN_MODE');

    // 2. Create order + submit TxID in Staging test harness
    const order = paymentService.createOrder(buyer.id, 'EDGE_6M', null, {
      expectedSenderWallet: buyerWallet,
    });
    mockAmountMicro = order.payable_amount_usdc_micro!;
    paymentService.submitTransactionHash({
      userId: buyer.id,
      orderCode: order.order_code,
      txHash,
    });

    // 3. First poll at 11 confirmations -> stays submitted (pending finality)
    const tick1 = await runPaymentPollerTick({
      db,
      paymentService,
      verificationMode: 'LIVE',
    });
    expect(tick1.skipped).toBe(false);
    expect(tick1.checked).toBe(1);
    expect(tick1.pending).toBe(1);
    expect(tick1.confirmed).toBe(0);

    // 4. Advance mock Polygon chain to >= 30 confirmations -> confirms & issues RSA license
    mockLatestBlock = 60_000_035;
    const tick2 = await runPaymentPollerTick({
      db,
      paymentService,
      verificationMode: 'LIVE',
    });
    expect(tick2.confirmed).toBe(1);
    expect(tick2.errors).toBe(0);

    const issuedLicenses = licenseService.listUserLicenses(buyer.id);
    expect(issuedLicenses.length).toBe(1);
    expect(issuedLicenses[0].status).toBe('active');

    // Verify Android gateway validation works immediately on newly issued license
    const validation = licenseService.validateForAndroid({
      licenseKey: issuedLicenses[0].license_key,
      deviceFingerprint: 'staging-android-fp-001',
      deviceModel: 'Pixel 9 Pro',
    });
    expect(validation.valid).toBe(true);
    expect(validation.signatureValid).toBe(true);

    // Confirm LICENSE_ISSUED notification was queued
    const support = new SupportService(db);
    const notes = support.listUserNotifications(buyer.id);
    expect(notes.some((n) => n.type === 'LICENSE_ISSUED' && n.status === 'pending')).toBe(true);
  });

  it('runs Maintenance & Notification Scheduler (3-day renewal reminder once, expiry transitions, DRY_RUN send guard, retry & dispatch)', async () => {
    const db = openDatabase(':memory:');
    runMigrations(db);
    cleanups.push(() => {
      db.close();
    });

    const users = new UserRepository(db);
    const user = users.upsertFromTelegram({
      telegramId: '88000002',
      firstName: 'NotifyUser',
      username: 'notify_user',
    });

    const paymentService = new PaymentService(db, { verificationMode: 'DRY_RUN' });
    const keys = generateEphemeralRsaKeyPair();
    const licenseService = new LicenseService(db, {
      issuanceMode: 'LIVE',
      rsaPrivateKeyPem: keys.privateKeyPem,
      rsaPublicKeyPem: keys.publicKeyPem,
      rsaKeyId: 'staging-rsa-v1',
    });

    // Seed an order already past expires_at & an expired idempotency record
    const oldOrder = paymentService.createOrder(user.id, 'EDGE_1M');
    db.prepare(`UPDATE orders SET expires_at = '2020-01-01T00:00:00.000Z' WHERE id = ?`).run(
      oldOrder.id
    );
    db.prepare(
      `INSERT INTO idempotency_records (scope, idempotency_key, actor_id, request_hash, response_status, response_body_json, expires_at)
       VALUES ('test_scope', 'expired-key-1', '88000002', 'hash', 200, '{}', '2020-01-01T00:00:00.000Z')`
    ).run();

    // Seed 2 subscriptions: one expiring in 2 days (should trigger reminder), one already expired
    const now = new Date('2026-11-20T12:00:00.000Z');
    const inTwoDays = new Date(now.getTime() + 2 * 24 * 60 * 60 * 1000).toISOString();
    const pastIso = new Date(now.getTime() - 60 * 60 * 1000).toISOString();
    const startedIso = new Date(now.getTime() - 28 * 24 * 60 * 60 * 1000).toISOString();

    const soonIssued = licenseService.issueForSubscription({
      userId: user.id,
      telegramId: user.telegram_id,
      planId: 1,
      planCode: 'EDGE_1M',
      durationDays: 30,
      maxDevices: 1,
      actorId: 'test_seed',
      requireConfirmedPayment: false,
    });
    db.prepare(`UPDATE subscriptions SET starts_at = ?, expires_at = ? WHERE id = ?`).run(
      startedIso,
      inTwoDays,
      soonIssued.subscription.id
    );

    const expiredIssued = licenseService.issueForSubscription({
      userId: user.id,
      telegramId: user.telegram_id,
      planId: 1,
      planCode: 'EDGE_1M',
      durationDays: 30,
      maxDevices: 1,
      actorId: 'test_seed',
      requireConfirmedPayment: false,
    });
    db.prepare(`UPDATE subscriptions SET starts_at = ?, expires_at = ? WHERE id = ?`).run(
      startedIso,
      pastIso,
      expiredIssued.subscription.id
    );
    db.prepare(`UPDATE licenses SET expires_at = ? WHERE id = ?`).run(
      pastIso,
      expiredIssued.license.id
    );

    // Run maintenance tick #1
    const m1 = runMaintenanceTick({ db, paymentService, nowIso: now.toISOString() });
    expect(m1.expiredOrders).toBe(1);
    expect(m1.purgedIdempotencyRecords).toBe(1);
    expect(m1.expiredSubscriptions).toBe(1);
    expect(m1.expiredLicenses).toBe(1);
    expect(m1.renewalRemindersQueued).toBe(1);

    // Run maintenance tick #2 -> MUST NOT queue duplicate reminder
    const m2 = runMaintenanceTick({ db, paymentService, nowIso: now.toISOString() });
    expect(m2.renewalRemindersQueued).toBe(0);

    // Notification dispatch when TELEGRAM_BOT_SEND_ENABLED=false -> strictly skipped!
    const botClient = new RecordingBotClient();
    const skippedSend = await runNotificationDispatcherTick({
      db,
      telegramBotSendEnabled: false,
      botClient,
    });
    expect(skippedSend.skipped).toBe(true);
    expect(skippedSend.pendingCount).toBe(1);
    expect(botClient.sentMessages.length).toBe(0);

    // Simulate 1 transient Telegram API error -> stays pending with attempts=1, then succeeds on retry
    botClient.failNextMessages = 1;
    const retryTick = await runNotificationDispatcherTick({
      db,
      telegramBotSendEnabled: true,
      botClient,
      maxAttempts: 3,
    });
    expect(retryTick.retried).toBe(1);
    expect(retryTick.sent).toBe(0);

    const successTick = await runNotificationDispatcherTick({
      db,
      telegramBotSendEnabled: true,
      botClient,
      maxAttempts: 3,
    });
    expect(successTick.sent).toBe(1);
    expect(botClient.sentMessages.length).toBe(1);
    expect(botClient.sentMessages[0].chatId).toBe(88000002);
    expect(botClient.sentMessages[0].text).toContain('یادآوری تمدید اشتراک EDGE');
  });

  it('executes scheduled SQLite WAL backup with retention pruning and verified disaster-recovery restore', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'edge-p12-backup-'));
    const dbPath = path.join(tmpDir, 'staging.sqlite');
    const backupDir = path.join(tmpDir, 'backups');

    cleanups.push(() => {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    const db: SqliteDb = openDatabase(dbPath);
    runMigrations(db);

    const users = new UserRepository(db);
    const user = users.upsertFromTelegram({
      telegramId: '88000099',
      firstName: 'BackupOwner',
      username: 'backup_owner',
    });
    const paymentService = new PaymentService(db, { verificationMode: 'DRY_RUN' });
    const order = paymentService.createOrder(user.id, 'EDGE_12M');

    // Run 3 scheduled backups with maxRetained = 2 to verify pruning
    const scheduler = new BackgroundScheduler({
      db,
      paymentService,
      verificationMode: 'DRY_RUN',
      telegramBotSendEnabled: false,
      backupDir,
      backupRetentionCount: 2,
    });

    await runScheduledBackupTick({ db, backupDir, label: 'edge_scheduled', maxRetained: 2 });
    await new Promise((r) => setTimeout(r, 15));
    await runScheduledBackupTick({ db, backupDir, label: 'edge_scheduled', maxRetained: 2 });
    await new Promise((r) => setTimeout(r, 15));
    const latestBackup = await scheduler.runBackupOnce();

    expect(latestBackup).toBeTruthy();
    expect(latestBackup!.backup.sizeBytes).toBeGreaterThan(0);
    expect(fs.existsSync(`${latestBackup!.backup.backupFile}.sha256`)).toBe(true);

    const remainingSnapshots = fs
      .readdirSync(backupDir)
      .filter((f) => f.endsWith('.sqlite'));
    expect(remainingSnapshots.length).toBe(2);

    // Close DB, simulate total database corruption/loss, then restore from verified snapshot
    db.close();
    fs.writeFileSync(dbPath, 'CORRUPTED_BY_DISASTER_SIMULATION', 'utf8');

    const restoreResult = restoreDatabaseBackup(latestBackup!.backup.backupFile, dbPath, {
      requireChecksumFile: true,
    });
    expect(restoreResult.integrityOk).toBe(true);
    expect(restoreResult.sha256).toBe(latestBackup!.backup.sha256);

    // Re-open restored DB and confirm data integrity
    const restoredDb = openDatabase(dbPath);
    try {
      const restoredOrder = restoredDb
        .prepare('SELECT order_code, status FROM orders WHERE order_code = ?')
        .get(order.order_code) as { order_code: string; status: string } | undefined;
      expect(restoredOrder?.order_code).toBe(order.order_code);
      expect(restoredOrder?.status).toBe('draft_phase0');
    } finally {
      restoredDb.close();
    }
  });

  it('prevents duplicate notifications when two concurrent schedulers run simultaneously against the same SQLite DB', async () => {
    const db = openDatabase(':memory:');
    runMigrations(db);
    cleanups.push(() => {
      db.close();
    });

    const users = new UserRepository(db);
    const user = users.upsertFromTelegram({
      telegramId: '88000123',
      firstName: 'ConcurrentUser',
      username: 'concurrent_user',
    });

    const support = new SupportService(db);
    support.queueNotification({
      userId: user.id,
      channel: 'telegram_bot',
      type: 'LICENSE_ISSUED',
      title: 'لایسنس آماده است',
      body: 'تست عدم ارسال اعلان تکراری در اجرای همزمان',
    });

    const slowBot: TelegramBotTransport & { sent: SendMessageParams[] } = {
      sent: [],
      async sendMessage(params: SendMessageParams) {
        await new Promise((r) => setTimeout(r, 35));
        this.sent.push(params);
        return { ok: true, messageId: this.sent.length };
      },
      async answerCallbackQuery() {
        return { ok: true };
      },
    };

    // Launch two direct concurrent dispatchers simultaneously with distinct workerIds
    const [resA, resB] = await Promise.all([
      runNotificationDispatcherTick({
        db,
        telegramBotSendEnabled: true,
        botClient: slowBot,
        workerId: 'worker_A',
      }),
      runNotificationDispatcherTick({
        db,
        telegramBotSendEnabled: true,
        botClient: slowBot,
        workerId: 'worker_B',
      }),
    ]);

    // Exactly ONE message must be delivered total; the competing worker skips via SQLite lease lock
    expect(slowBot.sent.length).toBe(1);
    expect(resA.sent + resB.sent).toBe(1);
    expect(resA.skippedLocked + resB.skippedLocked).toBeGreaterThanOrEqual(1);

    // Also verify two BackgroundScheduler instances sharing DB respect cross-process job lease
    support.queueNotification({
      userId: user.id,
      channel: 'telegram_bot',
      type: 'SUBSCRIPTION_EXPIRY_REMINDER',
      title: 'یادآوری دوم',
      body: 'تست قفل سطح Job در Scheduler',
    });

    const paymentService = new PaymentService(db, { verificationMode: 'DRY_RUN' });
    const sched1 = new BackgroundScheduler({
      db,
      paymentService,
      verificationMode: 'DRY_RUN',
      telegramBotSendEnabled: true,
      botClient: slowBot,
      backupDir: os.tmpdir(),
    });
    const sched2 = new BackgroundScheduler({
      db,
      paymentService,
      verificationMode: 'DRY_RUN',
      telegramBotSendEnabled: true,
      botClient: slowBot,
      backupDir: os.tmpdir(),
    });

    const [s1, s2] = await Promise.all([
      sched1.runNotificationsOnce(),
      sched2.runNotificationsOnce(),
    ]);

    expect(slowBot.sent.length).toBe(2);
    expect([s1, s2].filter((x) => x === null).length).toBe(1);
  });
});
