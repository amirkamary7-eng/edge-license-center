import crypto from 'crypto';
import http from 'http';
import { afterEach, describe, expect, it } from 'vitest';
import worker, { resetWorkerRateLimiterForTests } from '../cloudflare-worker/src/index';
import { createApiApp } from '../src/server/app';
import {
  TelegramBotApiClient,
  type TelegramBotTransport,
} from '../src/server/bot/telegramClient';
import { loadEnv, type ServerEnv } from '../src/server/config/env';
import { openDatabase, type SqliteDb } from '../src/server/db/connection';
import { runMigrations } from '../src/server/db/migrator';
import { UserRepository } from '../src/server/modules/users/userRepository';
import { generateEphemeralRsaKeyPair } from '../src/server/security/rsaSigner';
import { createSignedTelegramInitData } from '../src/server/security/telegramAuth';

async function startTestServer(
  envOverrides: Record<string, string | undefined>,
  options?: { botClient?: TelegramBotTransport }
): Promise<{
  db: SqliteDb;
  env: ServerEnv;
  baseUrl: string;
  close: () => Promise<void>;
}> {
  const db = openDatabase(':memory:');
  runMigrations(db);
  const env = loadEnv({
    NODE_ENV: 'test',
    PAYMENT_VERIFICATION_MODE: 'DRY_RUN',
    LICENSE_ISSUANCE_MODE: 'DRY_RUN',
    RATE_LIMIT_ENABLED: 'false',
    ...envOverrides,
  });
  const app = createApiApp({ db, env, botClient: options?.botClient });
  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
  const addr = server.address();
  if (!addr || typeof addr === 'string') throw new Error('Bind failed');
  return {
    db,
    env,
    baseUrl: `http://127.0.0.1:${addr.port}`,
    close: async () => {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      db.close();
    },
  };
}

describe('Phase 1 Security Hardening, RBAC Matrix, Bot Transport & Cloudflare Worker Suite', () => {
  const cleanups: Array<() => Promise<void>> = [];

  afterEach(async () => {
    while (cleanups.length > 0) {
      const fn = cleanups.pop()!;
      await fn();
    }
    resetWorkerRateLimiterForTests();
  });

  it('fails closed (503) when TELEGRAM_WEBHOOK_SECRET or GATEWAY_SHARED_SECRET are empty', async () => {
    const srv = await startTestServer({
      TELEGRAM_WEBHOOK_SECRET: '',
      GATEWAY_SHARED_SECRET: '',
    });
    cleanups.push(srv.close);

    const webhookRes = await fetch(`${srv.baseUrl}/api/v1/bot/webhook`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ update_id: 1 }),
    });
    expect(webhookRes.status).toBe(503);
    const whBody = (await webhookRes.json()) as { error: string };
    expect(whBody.error).toBe('WEBHOOK_SECRET_NOT_CONFIGURED');

    const gatewayRes = await fetch(`${srv.baseUrl}/api/v1/gateway/validate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        licenseKey: 'EDGE-1111-2222-3333-4444',
        deviceFingerprint: 'android-device-001',
      }),
    });
    expect(gatewayRes.status).toBe(503);
    const gwBody = (await gatewayRes.json()) as { error: string };
    expect(gwBody.error).toBe('GATEWAY_SECRET_NOT_CONFIGURED');
  });

  it('defaults ALLOW_PHASE0_PREVIEW_SESSION to false and NEVER grants admin privileges when explicitly enabled', async () => {
    // 1. Default env must have preview disabled -> 401
    const defaultEnv = loadEnv({});
    expect(defaultEnv.ALLOW_PHASE0_PREVIEW_SESSION).toBe(false);

    const lockedSrv = await startTestServer({});
    cleanups.push(lockedSrv.close);
    const lockedMe = await fetch(`${lockedSrv.baseUrl}/api/v1/me`);
    expect(lockedMe.status).toBe(401);

    // 2. Even when explicitly enabled in dev/test, preview user has ZERO admin privileges
    const previewSrv = await startTestServer({
      ALLOW_PHASE0_PREVIEW_SESSION: 'true',
    });
    cleanups.push(previewSrv.close);

    const meRes = await fetch(`${previewSrv.baseUrl}/api/v1/me`);
    expect(meRes.status).toBe(200);
    const me = (await meRes.json()) as { adminRole: string | null; permissions: string[] };
    expect(me.adminRole).toBeNull();
    expect(me.permissions).toEqual([]);

    const adminRes = await fetch(`${previewSrv.baseUrl}/api/v1/admin/dashboard`);
    expect(adminRes.status).toBe(403);
  });

  it('enforces single-use Telegram initData anti-replay on /api/v1/auth/telegram and accepts resulting Bearer token', async () => {
    const botToken = '111222333:SESSION_TEST_TOKEN';
    const srv = await startTestServer({
      TELEGRAM_BOT_TOKEN: botToken,
      SESSION_SECRET: 'test-session-secret-0123456789',
    });
    cleanups.push(srv.close);

    const initData = createSignedTelegramInitData(
      { id: 444555666, first_name: 'SessionUser', username: 'session_u' },
      botToken
    );

    const firstExchange = await fetch(`${srv.baseUrl}/api/v1/auth/telegram`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Telegram-Init-Data': initData },
    });
    expect(firstExchange.status).toBe(200);
    const { token } = (await firstExchange.json()) as { token: string };
    expect(token.startsWith('edge1.')).toBe(true);

    // Replaying the exact same initData MUST be blocked with 401
    const replayExchange = await fetch(`${srv.baseUrl}/api/v1/auth/telegram`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Telegram-Init-Data': initData },
    });
    expect(replayExchange.status).toBe(401);
    expect(((await replayExchange.json()) as { error: string }).error).toBe(
      'TELEGRAM_INIT_DATA_REPLAYED'
    );

    // Bearer session token works on protected endpoints
    const meRes = await fetch(`${srv.baseUrl}/api/v1/me`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(meRes.status).toBe(200);
    const me = (await meRes.json()) as { authMode: string; user: { telegram_id: string } };
    expect(me.authMode).toBe('bearer_session');
    expect(me.user.telegram_id).toBe('444555666');
  });

  it('enforces HTTP Idempotency-Key replay caching, 409 payload conflict, and sliding-window rate limiting (429)', async () => {
    const botToken = '111222333:IDEM_RATE_TOKEN';
    const srv = await startTestServer({
      TELEGRAM_BOT_TOKEN: botToken,
      RATE_LIMIT_ENABLED: 'true',
    });
    cleanups.push(srv.close);

    const initData = createSignedTelegramInitData(
      { id: 7001001, first_name: 'IdemUser' },
      botToken
    );

    // 1. Same Idempotency-Key + same payload returns exact same order without creating a second row
    const key = 'idem-order-key-0001';
    const r1 = await fetch(`${srv.baseUrl}/api/v1/orders`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Telegram-Init-Data': initData,
        'Idempotency-Key': key,
      },
      body: JSON.stringify({ planCode: 'EDGE_1M' }),
    });
    expect(r1.status).toBe(201);
    const body1 = (await r1.json()) as { order: { order_code: string } };

    const r2 = await fetch(`${srv.baseUrl}/api/v1/orders`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Telegram-Init-Data': initData,
        'Idempotency-Key': key,
      },
      body: JSON.stringify({ planCode: 'EDGE_1M' }),
    });
    expect(r2.status).toBe(201);
    expect(r2.headers.get('x-idempotent-replayed')).toBe('true');
    const body2 = (await r2.json()) as { order: { order_code: string } };
    expect(body2.order.order_code).toBe(body1.order.order_code);

    // 2. Reusing Idempotency-Key with a DIFFERENT payload returns 409
    const rConflict = await fetch(`${srv.baseUrl}/api/v1/orders`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Telegram-Init-Data': initData,
        'Idempotency-Key': key,
      },
      body: JSON.stringify({ planCode: 'EDGE_12M' }),
    });
    expect(rConflict.status).toBe(409);

    // 3. Exceeding sensitive write rate limit (15/min) triggers 429 + Retry-After
    let hit429 = false;
    for (let i = 0; i < 18; i++) {
      const resp = await fetch(`${srv.baseUrl}/api/v1/auth/telegram`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ initData: 'invalid' }),
      });
      if (resp.status === 429) {
        expect(resp.headers.get('retry-after')).toBeTruthy();
        hit429 = true;
        break;
      }
    }
    expect(hit429).toBe(true);
  });

  it('enforces all 5 RBAC roles across admin endpoints and prevents removing/demoting the last super_admin', async () => {
    const botToken = '111222333:RBAC_TEST_TOKEN';
    const superTg = '800000001';
    const srv = await startTestServer({
      TELEGRAM_BOT_TOKEN: botToken,
      BOOTSTRAP_SUPER_ADMIN_TELEGRAM_ID: superTg,
    });
    cleanups.push(srv.close);

    const users = new UserRepository(srv.db);
    const makeRoleHeaders = (tgId: string, role?: 'admin' | 'finance' | 'support' | 'auditor') => {
      if (role) {
        const u = users.upsertFromTelegram({ telegramId: tgId, firstName: role });
        users.ensureAdminRole(u.id, tgId, role);
      }
      return {
        'Content-Type': 'application/json',
        'X-Telegram-Init-Data': createSignedTelegramInitData(
          { id: Number(tgId), first_name: role ?? 'super' },
          botToken
        ),
      };
    };

    const superHeaders = makeRoleHeaders(superTg);
    const adminHeaders = makeRoleHeaders('800000002', 'admin');
    const financeHeaders = makeRoleHeaders('800000003', 'finance');
    const supportHeaders = makeRoleHeaders('800000004', 'support');
    const auditorHeaders = makeRoleHeaders('800000005', 'auditor');

    // Finance can read financial report, CANNOT modify plans or admins
    expect(
      (await fetch(`${srv.baseUrl}/api/v1/admin/reports/finance`, { headers: financeHeaders })).status
    ).toBe(200);
    expect(
      (
        await fetch(`${srv.baseUrl}/api/v1/admin/plans/EDGE_1M`, {
          method: 'PATCH',
          headers: financeHeaders,
          body: JSON.stringify({ isActive: false }),
        })
      ).status
    ).toBe(403);

    // Support can read tickets/users, CANNOT read finance or write admins
    expect(
      (await fetch(`${srv.baseUrl}/api/v1/admin/tickets`, { headers: supportHeaders })).status
    ).toBe(200);
    expect(
      (await fetch(`${srv.baseUrl}/api/v1/admin/reports/finance`, { headers: supportHeaders })).status
    ).toBe(403);

    // Auditor can read security logs, CANNOT mutate user status
    expect(
      (await fetch(`${srv.baseUrl}/api/v1/admin/reports/security`, { headers: auditorHeaders })).status
    ).toBe(200);
    expect(
      (
        await fetch(`${srv.baseUrl}/api/v1/admin/users/1/status`, {
          method: 'PATCH',
          headers: auditorHeaders,
          body: JSON.stringify({ status: 'suspended' }),
        })
      ).status
    ).toBe(403);

    // Admin can update user status, CANNOT modify plans or assign admin roles
    expect(
      (
        await fetch(`${srv.baseUrl}/api/v1/admin/users/4/status`, {
          method: 'PATCH',
          headers: adminHeaders,
          body: JSON.stringify({ status: 'active' }),
        })
      ).status
    ).toBe(200);
    expect(
      (
        await fetch(`${srv.baseUrl}/api/v1/admin/plans/EDGE_1M`, {
          method: 'PATCH',
          headers: adminHeaders,
          body: JSON.stringify({ isActive: false }),
        })
      ).status
    ).toBe(403);
    expect(
      (
        await fetch(`${srv.baseUrl}/api/v1/admin/admins`, {
          method: 'POST',
          headers: adminHeaders,
          body: JSON.stringify({ telegramId: '800000004', role: 'admin' }),
        })
      ).status
    ).toBe(403);

    // Super Admin CAN toggle plan visibility
    expect(
      (
        await fetch(`${srv.baseUrl}/api/v1/admin/plans/EDGE_1M`, {
          method: 'PATCH',
          headers: superHeaders,
          body: JSON.stringify({ isActive: false }),
        })
      ).status
    ).toBe(200);

    // Super Admin CANNOT demote or deactivate the last active super_admin
    const demoteLastRes = await fetch(`${srv.baseUrl}/api/v1/admin/admins`, {
      method: 'POST',
      headers: superHeaders,
      body: JSON.stringify({ telegramId: superTg, role: 'admin' }),
    });
    expect(demoteLastRes.status).toBe(409);
    expect(((await demoteLastRes.json()) as { error: string }).error).toBe(
      'CANNOT_REMOVE_LAST_SUPER_ADMIN'
    );

    const superAdminRow = srv.db
      .prepare(`SELECT id FROM admins WHERE telegram_id = ?`)
      .get(superTg) as { id: number };
    const deactivateLastRes = await fetch(
      `${srv.baseUrl}/api/v1/admin/admins/${superAdminRow.id}/deactivate`,
      { method: 'PATCH', headers: superHeaders }
    );
    expect(deactivateLastRes.status).toBe(409);
  });

  it('handles Bot commands (/start@EDGE_LicenceBot, /renew, /upgrade, /ticket), deduplicates update_id, blocks banned users, and dispatches Bot API calls', async () => {
    const sentMessages: Array<{ chatId: number; text: string }> = [];
    const answeredCallbacks: string[] = [];

    const mockBotClient: TelegramBotTransport = {
      sendMessage: async (req) => {
        sentMessages.push({ chatId: req.chatId, text: req.text });
        return { ok: true, messageId: sentMessages.length };
      },
      answerCallbackQuery: async (req) => {
        answeredCallbacks.push(req.callbackQueryId);
        return { ok: true };
      },
    };

    const secret = 'bot-webhook-secret-phase1';
    const srv = await startTestServer(
      { TELEGRAM_WEBHOOK_SECRET: secret },
      { botClient: mockBotClient }
    );
    cleanups.push(srv.close);

    const postUpdate = (payload: Record<string, unknown>) =>
      fetch(`${srv.baseUrl}/api/v1/bot/webhook`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Telegram-Bot-Api-Secret-Token': secret,
        },
        body: JSON.stringify(payload),
      });

    // 1. Bot mention normalized `/start@EDGE_LicenceBot` + Bot API sendMessage called
    const startRes = await postUpdate({
      update_id: 5001,
      message: {
        message_id: 1,
        from: { id: 910001, first_name: 'BotBuyer' },
        chat: { id: 910001, type: 'private' },
        text: '/start@EDGE_LicenceBot',
      },
    });
    expect(startRes.status).toBe(200);
    expect(sentMessages.length).toBe(1);
    expect(sentMessages[0].text).toContain('@EDGE_LicenceBot');

    // 2. Duplicate update_id deduplicated cleanly (no duplicate reply dispatched)
    const dupRes = await postUpdate({
      update_id: 5001,
      message: {
        message_id: 1,
        from: { id: 910001, first_name: 'BotBuyer' },
        chat: { id: 910001, type: 'private' },
        text: '/start@EDGE_LicenceBot',
      },
    });
    expect(dupRes.status).toBe(200);
    expect(((await dupRes.json()) as { duplicate?: boolean }).duplicate).toBe(true);
    expect(sentMessages.length).toBe(1);

    // 3. /renew, /upgrade, /ticket commands + callback_query answerCallbackQuery
    const renewRes = await postUpdate({
      update_id: 50020,
      message: {
        message_id: 20,
        from: { id: 910001, first_name: 'BotBuyer' },
        chat: { id: 910001, type: 'private' },
        text: '/renew',
      },
    });
    expect(renewRes.status).toBe(200);

    const upgradeRes = await postUpdate({
      update_id: 50021,
      message: {
        message_id: 21,
        from: { id: 910001, first_name: 'BotBuyer' },
        chat: { id: 910001, type: 'private' },
        text: '/upgrade',
      },
    });
    expect(upgradeRes.status).toBe(200);

    const ticketRes = await postUpdate({
      update_id: 5002,
      message: {
        message_id: 2,
        from: { id: 910001, first_name: 'BotBuyer' },
        chat: { id: 910001, type: 'private' },
        text: '/ticket USDC Transfer | Need help with Polygon USDC confirmation',
      },
    });
    expect(ticketRes.status).toBe(200);
    const ticketCount = (
      srv.db.prepare('SELECT COUNT(*) AS cnt FROM support_tickets').get() as { cnt: number }
    ).cnt;
    expect(ticketCount).toBe(1);

    const cbRes = await postUpdate({
      update_id: 5003,
      callback_query: {
        id: 'cb-query-777',
        from: { id: 910001, first_name: 'BotBuyer' },
        data: 'menu:plans',
        message: { message_id: 3, chat: { id: 910001, type: 'private' } },
      },
    });
    expect(cbRes.status).toBe(200);
    expect(answeredCallbacks).toContain('cb-query-777');

    // 4. Banned user is blocked from creating orders via Bot
    srv.db.prepare(`UPDATE users SET status = 'banned' WHERE telegram_id = '910001'`).run();
    const bannedRes = await postUpdate({
      update_id: 5004,
      message: {
        message_id: 4,
        from: { id: 910001, first_name: 'BotBuyer' },
        chat: { id: 910001, type: 'private' },
        text: '/buy',
      },
    });
    expect(bannedRes.status).toBe(200);
    const bannedBody = (await bannedRes.json()) as { reply: { text: string } };
    expect(bannedBody.reply.text).toContain('banned');
  });

  it('verifies Cloudflare Worker gateway HMAC signing, edge rate limiting (429), 413 payload cap, and backend verification', async () => {
    const gatewaySecret = 'worker-origin-hmac-secret-2026';
    const { privateKeyPem, publicKeyPem } = generateEphemeralRsaKeyPair();
    const srv = await startTestServer({
      GATEWAY_SHARED_SECRET: gatewaySecret,
      LICENSE_ISSUANCE_MODE: 'LIVE',
      RSA_PRIVATE_KEY_PEM: privateKeyPem,
      RSA_PUBLIC_KEY_PEM: publicKeyPem,
    });
    cleanups.push(srv.close);

    // 1. Worker health
    const healthRes = await worker.fetch(new Request('https://edge.worker/v1/health'), {});
    expect(healthRes.status).toBe(200);

    // 2. Worker fails closed (503) when unconfigured
    const uncfgRes = await worker.fetch(
      new Request('https://edge.worker/v1/license/validate', { method: 'POST', body: '{}' }),
      {}
    );
    expect(uncfgRes.status).toBe(503);

    // 3. Worker forwards signed HMAC request cleanly to Express backend
    const workerEnv = {
      ORIGIN_API_URL: srv.baseUrl,
      GATEWAY_SHARED_SECRET: gatewaySecret,
      RATE_LIMIT_MAX_PER_MIN: '3',
    };
    const payload = JSON.stringify({
      licenseKey: 'EDGE-1111-2222-3333-4444',
      deviceFingerprint: 'android-worker-fp-01',
    });

    const forwarded = await worker.fetch(
      new Request('https://edge.worker/v1/license/validate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '198.51.100.10' },
        body: payload,
      }),
      workerEnv
    );
    expect(forwarded.status).toBe(200);
    const forwardedJson = (await forwarded.json()) as { valid: boolean; reason: string };
    expect(forwardedJson.valid).toBe(false);
    expect(forwardedJson.reason).toBe('LICENSE_NOT_FOUND');

    // 4. Tampered HMAC signature directly to backend rejected with 401
    const nowTs = String(Math.floor(Date.now() / 1000));
    const badHmacRes = await fetch(`${srv.baseUrl}/api/v1/gateway/validate`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Edge-Gateway-Secret': gatewaySecret,
        'X-Edge-Timestamp': nowTs,
        'X-Edge-Signature': crypto.createHmac('sha256', 'wrong-key').update(`${nowTs}.${payload}`).digest('hex'),
      },
      body: payload,
    });
    expect(badHmacRes.status).toBe(401);

    // 5. Oversized payload rejected with 413 at Worker edge
    const tooLarge = await worker.fetch(
      new Request('https://edge.worker/v1/license/validate', {
        method: 'POST',
        headers: { 'CF-Connecting-IP': '198.51.100.11' },
        body: 'x'.repeat(5000),
      }),
      workerEnv
    );
    expect(tooLarge.status).toBe(413);

    // 6. Edge per-IP rate limit triggers 429 after RATE_LIMIT_MAX_PER_MIN (3) requests
    for (let i = 0; i < 2; i++) {
      await worker.fetch(
        new Request('https://edge.worker/v1/license/validate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '198.51.100.10' },
          body: payload,
        }),
        workerEnv
      );
    }
    const rateLimited = await worker.fetch(
      new Request('https://edge.worker/v1/license/validate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '198.51.100.10' },
        body: payload,
      }),
      workerEnv
    );
    expect(rateLimited.status).toBe(429);

    // 7. Upstream failure returns clean 502
    const upstreamDown = await worker.fetch(
      new Request('https://edge.worker/v1/license/validate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '198.51.100.99' },
        body: payload,
      }),
      workerEnv,
      async () => {
        throw new Error('ECONNREFUSED');
      }
    );
    expect(upstreamDown.status).toBe(502);
  });

  it('serializes TelegramBotApiClient sendMessage and answerCallbackQuery over mocked fetch transport', async () => {
    const calls: Array<{ url: string; body: Record<string, unknown> }> = [];
    const client = new TelegramBotApiClient('12345:MOCK_BOT_TOKEN', {
      apiRoot: 'https://mock-telegram.local',
      fetchImpl: async (input, init) => {
        calls.push({
          url: String(input),
          body: JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>,
        });
        return new Response(JSON.stringify({ ok: true, result: { message_id: 42 } }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      },
    });

    const msgRes = await client.sendMessage({
      chatId: 910001,
      text: '<b>EDGE</b>',
      inlineKeyboard: [[{ text: 'Plans', callback_data: 'menu:plans' }]],
    });
    expect(msgRes.ok).toBe(true);
    expect(msgRes.messageId).toBe(42);
    expect(calls[0].url).toBe('https://mock-telegram.local/bot12345:MOCK_BOT_TOKEN/sendMessage');
    expect(calls[0].body.chat_id).toBe(910001);
    expect(calls[0].body.parse_mode).toBe('HTML');

    const cbRes = await client.answerCallbackQuery({
      callbackQueryId: 'cb-999',
      text: 'Done',
    });
    expect(cbRes.ok).toBe(true);
    expect(calls[1].url).toBe(
      'https://mock-telegram.local/bot12345:MOCK_BOT_TOKEN/answerCallbackQuery'
    );
    expect(calls[1].body.callback_query_id).toBe('cb-999');
  });
});
