import { describe, expect, it } from 'vitest';
import { openDatabase } from '../src/server/db/connection';
import { runMigrations } from '../src/server/db/migrator';
import {
  hashRequestPayload,
  IdempotencyError,
  IdempotencyStore,
} from '../src/server/security/idempotency';
import { hasAdminPermission } from '../src/server/security/rbac';
import {
  generateEphemeralRsaKeyPair,
  signLicensePayload,
  verifyLicenseSignature,
} from '../src/server/security/rsaSigner';
import {
  deriveSessionSigningKey,
  signSessionToken,
  verifySessionToken,
} from '../src/server/security/sessionToken';
import {
  createSignedTelegramInitData,
  verifyTelegramInitData,
} from '../src/server/security/telegramAuth';
import { PRODUCT_NAME } from '../src/shared/constants';

describe('Security Primitives: Telegram HMAC, Session Tokens, Idempotency, RSA-2048 & RBAC', () => {
  const testBotToken = '123456789:TEST_BOT_TOKEN_FOR_UNIT_TESTS_ONLY';

  it('verifies authentic Telegram Mini App initData HMAC-SHA256 signatures', () => {
    const now = 1_760_000_000;
    const initData = createSignedTelegramInitData(
      { id: 424242, first_name: 'Amir', username: 'amirbtc', language_code: 'fa' },
      testBotToken,
      now
    );

    const verified = verifyTelegramInitData(initData, testBotToken, {
      maxAgeSeconds: 300,
      nowEpochSeconds: now + 45,
    });

    expect(verified.user.id).toBe(424242);
    expect(verified.user.username).toBe('amirbtc');
  });

  it('rejects tampered initData and expired replay attacks', () => {
    const now = 1_760_000_000;
    const valid = createSignedTelegramInitData(
      { id: 424242, first_name: 'Amir' },
      testBotToken,
      now
    );

    // Tamper user ID without updating HMAC
    const tampered = valid.replace('424242', '999999');
    expect(() =>
      verifyTelegramInitData(tampered, testBotToken, { nowEpochSeconds: now + 10 })
    ).toThrow('TELEGRAM_SIGNATURE_MISMATCH');

    // Replay past maxAgeSeconds
    expect(() =>
      verifyTelegramInitData(valid, testBotToken, {
        maxAgeSeconds: 300,
        nowEpochSeconds: now + 601,
      })
    ).toThrow('TELEGRAM_INIT_DATA_EXPIRED');
  });

  it('signs and verifies short-lived HMAC Bearer session tokens and rejects tampering/expiry', () => {
    const signingKey = deriveSessionSigningKey('explicit-session-secret-for-tests', testBotToken);
    const { token } = signSessionToken(
      { telegramId: '424242', userId: 7, ttlSeconds: 600 },
      signingKey
    );

    const verified = verifySessionToken(token, signingKey);
    expect(verified.sub).toBe('424242');
    expect(verified.uid).toBe(7);

    // Tampered token fails signature check
    const parts = token.split('.');
    const tampered = `${parts[0]}.${parts[1]}.${'a'.repeat(parts[2].length)}`;
    expect(() => verifySessionToken(tampered, signingKey)).toThrow('SESSION_TOKEN_INVALID_SIGNATURE');

    // Expired token rejected
    expect(() =>
      verifySessionToken(token, signingKey, verified.exp + 5)
    ).toThrow('SESSION_TOKEN_EXPIRED');
  });

  it('enforces SQLite-backed IdempotencyStore single-claim and payload mismatch conflict (409)', () => {
    const db = openDatabase(':memory:');
    try {
      runMigrations(db);
      const store = new IdempotencyStore(db);

      // Single-use claimOnce (used for Telegram initData anti-replay & update_id dedup)
      expect(store.claimOnce({ scope: 'tg_update', key: '1001', actorId: 'bot' })).toBe(true);
      expect(store.claimOnce({ scope: 'tg_update', key: '1001', actorId: 'bot' })).toBe(false);

      // Cached HTTP response replay + payload mismatch
      const hashA = hashRequestPayload({ planCode: 'EDGE_1M' });
      const hashB = hashRequestPayload({ planCode: 'EDGE_12M' });

      store.saveResponse({
        scope: 'create_order',
        key: 'idem-key-12345678',
        actorId: '424242',
        requestHash: hashA,
        status: 201,
        body: { orderCode: 'EDGE-TEST-1' },
      });

      const replayed = store.findResponse({
        scope: 'create_order',
        key: 'idem-key-12345678',
        actorId: '424242',
        requestHash: hashA,
      });
      expect(replayed?.status).toBe(201);
      expect(replayed?.body).toEqual({ orderCode: 'EDGE-TEST-1' });

      expect(() =>
        store.findResponse({
          scope: 'create_order',
          key: 'idem-key-12345678',
          actorId: '424242',
          requestHash: hashB,
        })
      ).toThrow(IdempotencyError);
    } finally {
      db.close();
    }
  });

  it('signs canonical license payloads with RSA-2048 and rejects tampering', () => {
    const { privateKeyPem, publicKeyPem } = generateEphemeralRsaKeyPair();
    const { canonicalJson, signatureBase64 } = signLicensePayload(
      {
        licenseKey: 'EDGE-AAAA-BBBB-CCCC-DDDD',
        product: PRODUCT_NAME,
        telegramId: '424242',
        planCode: 'EDGE_12M',
        maxDevices: 2,
        issuedAt: '2026-11-19T00:00:00.000Z',
        expiresAt: '2027-11-19T00:00:00.000Z',
        keyId: 'edge-rsa-v1',
      },
      privateKeyPem
    );

    expect(verifyLicenseSignature(canonicalJson, signatureBase64, publicKeyPem)).toBe(true);

    const tamperedPayload = canonicalJson.replace('EDGE_12M', 'EDGE_LIFETIME');
    expect(verifyLicenseSignature(tamperedPayload, signatureBase64, publicKeyPem)).toBe(false);
  });

  it('enforces least-privilege RBAC permissions per admin role', () => {
    expect(hasAdminPermission('super_admin', 'admins:write')).toBe(true);
    expect(hasAdminPermission('admin', 'admins:write')).toBe(false);
    expect(hasAdminPermission('finance', 'reports:finance')).toBe(true);
    expect(hasAdminPermission('finance', 'licenses:write')).toBe(false);
    expect(hasAdminPermission('support', 'users:read')).toBe(true);
    expect(hasAdminPermission('support', 'reports:finance')).toBe(false);
    expect(hasAdminPermission('auditor', 'reports:security')).toBe(true);
    expect(hasAdminPermission('auditor', 'users:write')).toBe(false);
    expect(hasAdminPermission(null, 'dashboard:read')).toBe(false);
  });
});
