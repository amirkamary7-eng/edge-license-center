import { describe, expect, it } from 'vitest';
import { openDatabase } from '../src/server/db/connection';
import { runMigrations } from '../src/server/db/migrator';
import { LicenseError, LicenseService } from '../src/server/modules/license/licenseService';
import { PaymentService } from '../src/server/modules/payment/paymentService';
import { PlanRepository } from '../src/server/modules/plans/planRepository';
import { UserRepository } from '../src/server/modules/users/userRepository';
import { generateEphemeralRsaKeyPair } from '../src/server/security/rsaSigner';

describe('License Engine: Fail-Closed RSA, Confirmed Payment Guard, Renewal, Unbind & Ban Sync', () => {
  it('blocks live license issuance in DRY_RUN mode and refuses LIVE issuance without confirmed payment', () => {
    const db = openDatabase(':memory:');
    try {
      runMigrations(db);
      const users = new UserRepository(db);
      const plans = new PlanRepository(db);
      const user = users.upsertFromTelegram({ telegramId: '777001', firstName: 'Test' });
      const plan = plans.findByCode('EDGE_1M')!;

      const dryRunService = new LicenseService(db, {
        issuanceMode: 'DRY_RUN',
        rsaPrivateKeyPem: '',
        rsaPublicKeyPem: '',
        rsaKeyId: 'edge-rsa-v1',
      });

      expect(() =>
        dryRunService.issueForSubscription({
          userId: user.id,
          telegramId: user.telegram_id,
          planId: plan.id,
          planCode: plan.code,
          durationDays: plan.duration_days,
          maxDevices: plan.max_devices,
          actorId: 'test',
        })
      ).toThrow(LicenseError);

      // Even in LIVE mode, passing an unconfirmed orderId MUST fail with CONFIRMED_PAYMENT_REQUIRED
      const { privateKeyPem, publicKeyPem } = generateEphemeralRsaKeyPair();
      const liveService = new LicenseService(db, {
        issuanceMode: 'LIVE',
        rsaPrivateKeyPem: privateKeyPem,
        rsaPublicKeyPem: publicKeyPem,
        rsaKeyId: 'edge-rsa-v1',
      });
      const payService = new PaymentService(db, { verificationMode: 'LIVE' });
      const unpaidOrder = payService.createOrder(user.id, 'EDGE_1M', null, {
        expectedSenderWallet: '0x1111111111111111111111111111111111111111',
      });

      expect(() =>
        liveService.issueForSubscription({
          userId: user.id,
          telegramId: user.telegram_id,
          planId: plan.id,
          planCode: plan.code,
          durationDays: plan.duration_days,
          maxDevices: plan.max_devices,
          orderId: unpaidOrder.id,
          actorId: 'test',
        })
      ).toThrow(/confirmed on-chain payment/i);
    } finally {
      db.close();
    }
  });

  it('fails closed in validateForAndroid when RSA_PUBLIC_KEY_PEM is missing or invalid', () => {
    const db = openDatabase(':memory:');
    try {
      runMigrations(db);
      const users = new UserRepository(db);
      const plans = new PlanRepository(db);
      const user = users.upsertFromTelegram({ telegramId: '777009', firstName: 'FailClosed' });
      const plan = plans.findByCode('EDGE_1M')!;
      const { privateKeyPem } = generateEphemeralRsaKeyPair();

      const missingPubService = new LicenseService(db, {
        issuanceMode: 'LIVE',
        rsaPrivateKeyPem: privateKeyPem,
        rsaPublicKeyPem: '',
        rsaKeyId: 'edge-rsa-test',
      });

      const { license } = missingPubService.issueForSubscription({
        userId: user.id,
        telegramId: user.telegram_id,
        planId: plan.id,
        planCode: plan.code,
        durationDays: plan.duration_days,
        maxDevices: plan.max_devices,
        actorId: 'unit_test',
      });

      const outcome = missingPubService.validateForAndroid({
        licenseKey: license.license_key,
        deviceFingerprint: 'android-fp-001',
      });
      expect(outcome.valid).toBe(false);
      expect(outcome.reason).toBe('RSA_PUBLIC_KEY_NOT_CONFIGURED');
      expect(outcome.signatureValid).toBe(false);
    } finally {
      db.close();
    }
  });

  it('supports RSA signing, device limit, unbindDevice, renewal re-signing, user ban/suspend check, and subscription sync', () => {
    const db = openDatabase(':memory:');
    try {
      runMigrations(db);
      const users = new UserRepository(db);
      const plans = new PlanRepository(db);
      const user = users.upsertFromTelegram({ telegramId: '777002', firstName: 'AndroidUser' });
      const plan1m = plans.findByCode('EDGE_1M')!; // max_devices = 1
      const plan3m = plans.findByCode('EDGE_3M')!; // duration = 90d, max_devices = 1

      const { privateKeyPem, publicKeyPem } = generateEphemeralRsaKeyPair();
      const service = new LicenseService(db, {
        issuanceMode: 'LIVE',
        rsaPrivateKeyPem: privateKeyPem,
        rsaPublicKeyPem: publicKeyPem,
        rsaKeyId: 'edge-rsa-test',
      });

      const { subscription, license } = service.issueForSubscription({
        userId: user.id,
        telegramId: user.telegram_id,
        planId: plan1m.id,
        planCode: plan1m.code,
        durationDays: plan1m.duration_days,
        maxDevices: plan1m.max_devices,
        actorId: 'unit_test',
      });

      expect(license.license_key).toMatch(/^EDGE-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}$/);

      // 1. First Android device binds and validates cleanly
      const check1 = service.validateForAndroid({
        licenseKey: license.license_key,
        deviceFingerprint: 'android-fp-device-001',
        deviceModel: 'Pixel 9 Pro',
      });
      expect(check1.valid).toBe(true);
      expect(check1.signatureValid).toBe(true);

      // 2. Second distinct device blocked (`DEVICE_LIMIT_EXCEEDED`)
      const check2 = service.validateForAndroid({
        licenseKey: license.license_key,
        deviceFingerprint: 'android-fp-device-002',
      });
      expect(check2.valid).toBe(false);
      expect(check2.reason).toBe('DEVICE_LIMIT_EXCEEDED');

      // 3. Unbinding device-001 frees the slot so device-002 can bind
      const unbindRes = service.unbindDevice({
        licenseKey: license.license_key,
        deviceFingerprint: 'android-fp-device-001',
        actorType: 'user',
        actorId: user.telegram_id,
        requesterUserId: user.id,
      });
      expect(unbindRes.unbound).toBe(true);

      const checkAfterUnbind = service.validateForAndroid({
        licenseKey: license.license_key,
        deviceFingerprint: 'android-fp-device-002',
      });
      expect(checkAfterUnbind.valid).toBe(true);

      // 4. Renewing subscription extends expires_at & produces new valid RSA signature
      const prevExpiresMs = new Date(license.expires_at).getTime();
      const renewed = service.renewSubscription({
        subscriptionId: subscription.id,
        planId: plan3m.id,
        planCode: plan3m.code,
        durationDays: plan3m.duration_days,
        maxDevices: plan3m.max_devices,
        actorId: 'renewal_test',
      });
      expect(new Date(renewed.license.expires_at).getTime()).toBeGreaterThan(
        prevExpiresMs + 80 * 86400 * 1000
      );
      expect(
        service.validateForAndroid({
          licenseKey: license.license_key,
          deviceFingerprint: 'android-fp-device-002',
        }).valid
      ).toBe(true);

      // 5. Banning/Suspending user immediately invalidates Android validation
      db.prepare(`UPDATE users SET status = 'suspended' WHERE id = ?`).run(user.id);
      const suspendedCheck = service.validateForAndroid({
        licenseKey: license.license_key,
        deviceFingerprint: 'android-fp-device-002',
      });
      expect(suspendedCheck.valid).toBe(false);
      expect(suspendedCheck.reason).toBe('USER_SUSPENDED');

      db.prepare(`UPDATE users SET status = 'banned' WHERE id = ?`).run(user.id);
      const bannedCheck = service.validateForAndroid({
        licenseKey: license.license_key,
        deviceFingerprint: 'android-fp-device-002',
      });
      expect(bannedCheck.valid).toBe(false);
      expect(bannedCheck.reason).toBe('USER_BANNED');
      db.prepare(`UPDATE users SET status = 'active' WHERE id = ?`).run(user.id);

      // 6. Revoking & reactivating license keeps subscriptions.status strictly synced + logs license_history
      service.updateLicenseStatus({
        licenseKey: license.license_key,
        status: 'revoked',
        reason: 'Policy test revocation',
        adminActorId: '900000001',
      });
      const subAfterRevoke = db
        .prepare('SELECT status FROM subscriptions WHERE id = ?')
        .get(subscription.id) as { status: string };
      expect(subAfterRevoke.status).toBe('revoked');

      const checkRevoked = service.validateForAndroid({
        licenseKey: license.license_key,
        deviceFingerprint: 'android-fp-device-002',
      });
      expect(checkRevoked.valid).toBe(false);

      service.updateLicenseStatus({
        licenseKey: license.license_key,
        status: 'active',
        reason: 'Reinstated after review',
        adminActorId: '900000001',
      });
      const subAfterReactivate = db
        .prepare('SELECT status FROM subscriptions WHERE id = ?')
        .get(subscription.id) as { status: string };
      expect(subAfterReactivate.status).toBe('active');

      const history = service.listLicenseHistory(license.license_key);
      expect(history.map((h) => h.action)).toEqual(
        expect.arrayContaining([
          'ISSUED',
          'DEVICE_UNBOUND',
          'RENEWED',
          'STATUS_REVOKED',
          'STATUS_ACTIVE',
        ])
      );
    } finally {
      db.close();
    }
  });
});
