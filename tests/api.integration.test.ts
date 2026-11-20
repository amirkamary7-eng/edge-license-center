import http from 'http';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createApiApp } from '../src/server/app';
import { loadEnv } from '../src/server/config/env';
import { openDatabase, type SqliteDb } from '../src/server/db/connection';
import { runMigrations } from '../src/server/db/migrator';
import { createSignedTelegramInitData } from '../src/server/security/telegramAuth';

describe('Express API Integration Suite (Auth, Orders, Anti-Replay, Bot Webhook, Admin RBAC)', () => {
  const testBotToken = '999888777:INTEGRATION_TEST_BOT_TOKEN';
  const testWebhookSecret = 'test_webhook_secret_64_hex';
  const testGatewaySecret = 'test_gateway_secret_64_hex';
  const adminTelegramId = '100000001';

  let db: SqliteDb;
  let server: http.Server;
  let baseUrl: string;

  beforeAll(async () => {
    db = openDatabase(':memory:');
    runMigrations(db);

    const env = loadEnv({
      NODE_ENV: 'test',
      PAYMENT_VERIFICATION_MODE: 'DRY_RUN',
      LICENSE_ISSUANCE_MODE: 'DRY_RUN',
      TELEGRAM_BOT_TOKEN: testBotToken,
      TELEGRAM_WEBHOOK_SECRET: testWebhookSecret,
      GATEWAY_SHARED_SECRET: testGatewaySecret,
      BOOTSTRAP_SUPER_ADMIN_TELEGRAM_ID: adminTelegramId,
      ALLOW_PHASE0_PREVIEW_SESSION: 'false',
    });

    const app = createApiApp({ db, env });
    server = http.createServer(app);
    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', () => resolve());
    });
    const addr = server.address();
    if (!addr || typeof addr === 'string') {
      throw new Error('Failed to bind test server');
    }
    baseUrl = `http://127.0.0.1:${addr.port}`;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    db.close();
  });

  it('serves health and immutable public plan configuration', async () => {
    const healthRes = await fetch(`${baseUrl}/api/v1/health`);
    expect(healthRes.status).toBe(200);
    const health = (await healthRes.json()) as { ok: boolean; paymentMode: string };
    expect(health.ok).toBe(true);
    expect(health.paymentMode).toBe('DRY_RUN');

    const cfgRes = await fetch(`${baseUrl}/api/v1/public/config`);
    expect(cfgRes.status).toBe(200);
    const cfg = (await cfgRes.json()) as { plans: Array<{ price_usd_display: string }> };
    expect(cfg.plans.map((p) => p.price_usd_display)).toEqual(['1.99', '4.99', '8.99', '16.99']);
  });

  it('enforces Telegram initData auth, order checkout, duplicate TxID block, and Admin RBAC', async () => {
    // 1. Unauthenticated access rejected
    const unauth = await fetch(`${baseUrl}/api/v1/me`);
    expect(unauth.status).toBe(401);

    // 2. Customer signed initData accepted
    const customerInitData = createSignedTelegramInitData(
      { id: 200000002, first_name: 'Customer', username: 'edge_buyer' },
      testBotToken
    );

    const meRes = await fetch(`${baseUrl}/api/v1/me`, {
      headers: { 'X-Telegram-Init-Data': customerInitData },
    });
    expect(meRes.status).toBe(200);
    const me = (await meRes.json()) as { adminRole: string | null };
    expect(me.adminRole).toBeNull();

    // 3. Customer denied from Admin dashboard
    const forbiddenAdmin = await fetch(`${baseUrl}/api/v1/admin/dashboard`, {
      headers: { 'X-Telegram-Init-Data': customerInitData },
    });
    expect(forbiddenAdmin.status).toBe(403);

    // 4. Customer creates order and submits TxID; replay returns 409
    const orderRes = await fetch(`${baseUrl}/api/v1/orders`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Telegram-Init-Data': customerInitData,
      },
      body: JSON.stringify({ planCode: 'EDGE_3M' }),
    });
    expect(orderRes.status).toBe(201);
    const { order } = (await orderRes.json()) as { order: { order_code: string; expected_amount_usd: string } };
    expect(order.expected_amount_usd).toBe('4.99');

    const txHash = '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
    const txRes1 = await fetch(`${baseUrl}/api/v1/payments/submit-tx`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Telegram-Init-Data': customerInitData,
      },
      body: JSON.stringify({ orderCode: order.order_code, txHash }),
    });
    expect(txRes1.status).toBe(201);

    const txRes2 = await fetch(`${baseUrl}/api/v1/payments/submit-tx`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Telegram-Init-Data': customerInitData,
      },
      body: JSON.stringify({ orderCode: order.order_code, txHash }),
    });
    expect(txRes2.status).toBe(409);

    // 5. Bootstrapped Super Admin can access dashboard
    const adminInitData = createSignedTelegramInitData(
      { id: Number(adminTelegramId), first_name: 'AMIRBTC' },
      testBotToken
    );
    const adminDash = await fetch(`${baseUrl}/api/v1/admin/dashboard`, {
      headers: { 'X-Telegram-Init-Data': adminInitData },
    });
    expect(adminDash.status).toBe(200);
    const dashBody = (await adminDash.json()) as { summary: { totalOrders: number; totalUsers: number } };
    expect(dashBody.summary.totalOrders).toBe(1);
    expect(dashBody.summary.totalUsers).toBeGreaterThanOrEqual(2);
  });

  it('protects Telegram Bot webhook and Cloudflare Worker gateway endpoints with shared secrets', async () => {
    const badWebhook = await fetch(`${baseUrl}/api/v1/bot/webhook`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Telegram-Bot-Api-Secret-Token': 'wrong' },
      body: JSON.stringify({ update_id: 1 }),
    });
    expect(badWebhook.status).toBe(401);

    const goodWebhook = await fetch(`${baseUrl}/api/v1/bot/webhook`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Telegram-Bot-Api-Secret-Token': testWebhookSecret,
      },
      body: JSON.stringify({
        update_id: 101,
        message: {
          message_id: 1,
          from: { id: 300000003, first_name: 'BotTester' },
          chat: { id: 300000003, type: 'private' },
          text: '/start',
        },
      }),
    });
    expect(goodWebhook.status).toBe(200);
    const botJson = (await goodWebhook.json()) as { ok: boolean; reply: { text: string } };
    expect(botJson.ok).toBe(true);
    expect(botJson.reply.text).toContain('@EDGE_LicenceBot');

    const badGateway = await fetch(`${baseUrl}/api/v1/gateway/validate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Edge-Gateway-Secret': 'wrong' },
      body: JSON.stringify({
        licenseKey: 'EDGE-0000-0000-0000-0000',
        deviceFingerprint: 'fp-12345678',
      }),
    });
    expect(badGateway.status).toBe(401);
  });
});
