import crypto from 'crypto';
import { PRODUCT_NAME } from '../../../shared/constants';
import type {
  DeviceRecord,
  DeviceStatus,
  LicenseHistoryRecord,
  LicenseRecord,
  SubscriptionRecord,
  UserRecord,
} from '../../../shared/types';
import { runImmediateTransaction, type SqliteDb } from '../../db/connection';
import {
  signLicensePayload,
  verifyLicenseSignature,
  type LicenseSignaturePayload,
} from '../../security/rsaSigner';
import { AuditService } from '../audit/auditService';

export interface LicenseServiceOptions {
  issuanceMode: 'DRY_RUN' | 'LIVE';
  rsaPrivateKeyPem: string;
  rsaPublicKeyPem: string;
  rsaKeyId: string;
}

export class LicenseError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly statusCode = 400
  ) {
    super(message);
    this.name = 'LicenseError';
  }
}

export function generateLicenseKey(): string {
  const raw = crypto.randomBytes(8).toString('hex').toUpperCase();
  return `EDGE-${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8, 12)}-${raw.slice(12, 16)}`;
}

export class LicenseService {
  private readonly audit: AuditService;

  constructor(
    private readonly db: SqliteDb,
    private readonly options: LicenseServiceOptions
  ) {
    this.audit = new AuditService(db);
  }

  private recordHistory(params: {
    licenseId: number;
    action: string;
    previousStatus?: string | null;
    newStatus?: string | null;
    actorType: LicenseHistoryRecord['actor_type'];
    actorId: string;
    reason?: string | null;
    metadata?: Record<string, unknown>;
  }): void {
    this.db
      .prepare(
        `INSERT INTO license_history (
           license_id, action, previous_status, new_status, actor_type, actor_id, reason, metadata_json
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        params.licenseId,
        params.action,
        params.previousStatus ?? null,
        params.newStatus ?? null,
        params.actorType,
        params.actorId,
        params.reason ?? null,
        JSON.stringify(params.metadata ?? {})
      );
  }

  /**
   * Issues an RSA-2048 signed license bound to a new subscription.
   * - Strictly blocked in DRY_RUN mode.
   * - When `requireConfirmedPayment` is true (default when `orderId` is provided),
   *   verifies that a `confirmed` payment row exists for that order before issuing.
   */
  issueForSubscription(params: {
    userId: number;
    telegramId: string;
    planId: number;
    planCode: string;
    durationDays: number;
    maxDevices: number;
    orderId?: number | null;
    actorId: string;
    requireConfirmedPayment?: boolean;
  }): { subscription: SubscriptionRecord; license: LicenseRecord } {
    if (this.options.issuanceMode !== 'LIVE') {
      throw new LicenseError(
        'PHASE0_ISSUANCE_BLOCKED',
        'Live license issuance is disabled during DRY_RUN mode.',
        403
      );
    }

    if (!this.options.rsaPrivateKeyPem) {
      throw new LicenseError('RSA_KEY_MISSING', 'RSA private key is not configured.', 500);
    }

    const mustVerifyPayment = params.requireConfirmedPayment ?? params.orderId != null;

    return runImmediateTransaction(this.db, () => {
      if (mustVerifyPayment) {
        if (!params.orderId) {
          throw new LicenseError(
            'CONFIRMED_PAYMENT_REQUIRED',
            'A confirmed order and payment are required before issuing a license.',
            403
          );
        }
        const confirmedPayment = this.db
          .prepare(`SELECT id FROM payments WHERE order_id = ? AND status = 'confirmed'`)
          .get(params.orderId) as { id: number } | undefined;
        if (!confirmedPayment) {
          throw new LicenseError(
            'CONFIRMED_PAYMENT_REQUIRED',
            'Cannot issue license: order does not have a confirmed on-chain payment.',
            403
          );
        }
      }

      if (params.orderId) {
        const existingSub = this.db
          .prepare('SELECT * FROM subscriptions WHERE order_id = ?')
          .get(params.orderId) as SubscriptionRecord | undefined;
        if (existingSub) {
          const existingLic = this.db
            .prepare('SELECT * FROM licenses WHERE subscription_id = ?')
            .get(existingSub.id) as LicenseRecord | undefined;
          if (existingLic) {
            return { subscription: existingSub, license: existingLic };
          }
        }
      }

      const startsAt = new Date();
      const expiresAt = new Date(startsAt.getTime() + params.durationDays * 86400 * 1000);
      const nowIso = startsAt.toISOString();

      const subRes = this.db
        .prepare(
          `INSERT INTO subscriptions (user_id, plan_id, order_id, status, starts_at, expires_at)
           VALUES (?, ?, ?, 'active', ?, ?)`
        )
        .run(
          params.userId,
          params.planId,
          params.orderId ?? null,
          nowIso,
          expiresAt.toISOString()
        );
      const subscriptionId = Number(subRes.lastInsertRowid);

      const licenseKey = generateLicenseKey();
      const payload: LicenseSignaturePayload = {
        licenseKey,
        product: PRODUCT_NAME,
        telegramId: params.telegramId,
        planCode: params.planCode,
        maxDevices: params.maxDevices,
        issuedAt: nowIso,
        expiresAt: expiresAt.toISOString(),
        keyId: this.options.rsaKeyId,
      };

      const { canonicalJson, signatureBase64 } = signLicensePayload(
        payload,
        this.options.rsaPrivateKeyPem
      );

      const licRes = this.db
        .prepare(
          `INSERT INTO licenses (
             license_key,
             subscription_id,
             user_id,
             rsa_key_id,
             payload_json,
             signature_base64,
             status,
             max_devices,
             issued_at,
             expires_at,
             updated_at
           ) VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?)`
        )
        .run(
          licenseKey,
          subscriptionId,
          params.userId,
          this.options.rsaKeyId,
          canonicalJson,
          signatureBase64,
          params.maxDevices,
          nowIso,
          expiresAt.toISOString(),
          nowIso
        );

      const licenseId = Number(licRes.lastInsertRowid);

      this.recordHistory({
        licenseId,
        action: 'ISSUED',
        previousStatus: null,
        newStatus: 'active',
        actorType: 'system',
        actorId: params.actorId,
        reason: params.orderId ? `Issued from confirmed order #${params.orderId}` : 'Issued',
        metadata: { subscriptionId, planCode: params.planCode, maxDevices: params.maxDevices },
      });

      this.audit.record({
        actorType: 'system',
        actorId: params.actorId,
        action: 'LICENSE_ISSUED',
        entityType: 'license',
        entityId: licenseKey,
        metadata: { subscriptionId, planCode: params.planCode, maxDevices: params.maxDevices },
      });

      return {
        subscription: this.db
          .prepare('SELECT * FROM subscriptions WHERE id = ?')
          .get(subscriptionId) as SubscriptionRecord,
        license: this.db
          .prepare('SELECT * FROM licenses WHERE id = ?')
          .get(licenseId) as LicenseRecord,
      };
    });
  }

  /**
   * Renews or upgrades an existing subscription & re-signs the bound RSA-2048 license payload.
   * Requires a confirmed payment when `confirmedOrderId` is provided (or `requireConfirmedPayment` is true).
   */
  renewSubscription(params: {
    subscriptionId: number;
    planId: number;
    planCode: string;
    durationDays: number;
    maxDevices: number;
    confirmedOrderId?: number | null;
    requireConfirmedPayment?: boolean;
    actorId: string;
  }): { subscription: SubscriptionRecord; license: LicenseRecord } {
    if (this.options.issuanceMode !== 'LIVE') {
      throw new LicenseError(
        'PHASE0_ISSUANCE_BLOCKED',
        'Live license renewal is disabled during DRY_RUN mode.',
        403
      );
    }

    if (!this.options.rsaPrivateKeyPem) {
      throw new LicenseError('RSA_KEY_MISSING', 'RSA private key is not configured.', 500);
    }

    const mustVerifyPayment = params.requireConfirmedPayment ?? params.confirmedOrderId != null;

    return runImmediateTransaction(this.db, () => {
      if (mustVerifyPayment) {
        if (!params.confirmedOrderId) {
          throw new LicenseError(
            'CONFIRMED_PAYMENT_REQUIRED',
            'A confirmed payment is required to renew a subscription.',
            403
          );
        }
        const confirmed = this.db
          .prepare(`SELECT id FROM payments WHERE order_id = ? AND status = 'confirmed'`)
          .get(params.confirmedOrderId);
        if (!confirmed) {
          throw new LicenseError(
            'CONFIRMED_PAYMENT_REQUIRED',
            'Cannot renew: associated order has no confirmed payment.',
            403
          );
        }
      }

      const sub = this.db
        .prepare('SELECT * FROM subscriptions WHERE id = ?')
        .get(params.subscriptionId) as SubscriptionRecord | undefined;
      if (!sub) {
        throw new LicenseError('SUBSCRIPTION_NOT_FOUND', 'Subscription not found.', 404);
      }

      const lic = this.db
        .prepare('SELECT * FROM licenses WHERE subscription_id = ?')
        .get(sub.id) as LicenseRecord | undefined;
      if (!lic) {
        throw new LicenseError('LICENSE_NOT_FOUND', 'License for subscription not found.', 404);
      }

      const user = this.db
        .prepare('SELECT * FROM users WHERE id = ?')
        .get(sub.user_id) as UserRecord | undefined;
      if (!user) {
        throw new LicenseError('USER_NOT_FOUND', 'License owner not found.', 404);
      }

      const now = new Date();
      const baseTime = Math.max(now.getTime(), new Date(sub.expires_at).getTime());
      const newExpiresAt = new Date(baseTime + params.durationDays * 86400 * 1000).toISOString();
      const nowIso = now.toISOString();
      const effectiveMaxDevices = Math.max(lic.max_devices, params.maxDevices);

      const payload: LicenseSignaturePayload = {
        licenseKey: lic.license_key,
        product: PRODUCT_NAME,
        telegramId: user.telegram_id,
        planCode: params.planCode,
        maxDevices: effectiveMaxDevices,
        issuedAt: lic.issued_at,
        expiresAt: newExpiresAt,
        keyId: this.options.rsaKeyId,
      };

      const { canonicalJson, signatureBase64 } = signLicensePayload(
        payload,
        this.options.rsaPrivateKeyPem
      );

      this.db
        .prepare(
          `UPDATE subscriptions
           SET plan_id = ?, status = 'active', expires_at = ?, auto_renew_reminded = 0, updated_at = ?
           WHERE id = ?`
        )
        .run(params.planId, newExpiresAt, nowIso, sub.id);

      this.db
        .prepare(
          `UPDATE licenses
           SET rsa_key_id = ?, payload_json = ?, signature_base64 = ?, status = 'active',
               max_devices = ?, expires_at = ?, revoked_at = NULL, revoke_reason = NULL, updated_at = ?
           WHERE id = ?`
        )
        .run(
          this.options.rsaKeyId,
          canonicalJson,
          signatureBase64,
          effectiveMaxDevices,
          newExpiresAt,
          nowIso,
          lic.id
        );

      this.recordHistory({
        licenseId: lic.id,
        action: 'RENEWED',
        previousStatus: lic.status,
        newStatus: 'active',
        actorType: 'system',
        actorId: params.actorId,
        reason: `Extended by ${params.durationDays} days (${params.planCode})`,
        metadata: {
          previousExpiresAt: sub.expires_at,
          newExpiresAt,
          confirmedOrderId: params.confirmedOrderId ?? null,
        },
      });

      this.audit.record({
        actorType: 'system',
        actorId: params.actorId,
        action: 'LICENSE_RENEWED',
        entityType: 'license',
        entityId: lic.license_key,
        metadata: { subscriptionId: sub.id, planCode: params.planCode, newExpiresAt },
      });

      return {
        subscription: this.db
          .prepare('SELECT * FROM subscriptions WHERE id = ?')
          .get(sub.id) as SubscriptionRecord,
        license: this.db
          .prepare('SELECT * FROM licenses WHERE id = ?')
          .get(lic.id) as LicenseRecord,
      };
    });
  }

  /**
   * Updates license status AND keeps the linked subscription status strictly synchronized
   * across revoke, block, and reactivation.
   */
  updateLicenseStatus(params: {
    licenseKey: string;
    status: 'active' | 'revoked' | 'blocked';
    reason: string;
    adminActorId: string;
  }): LicenseRecord {
    return runImmediateTransaction(this.db, () => {
      const license = this.db
        .prepare('SELECT * FROM licenses WHERE license_key = ?')
        .get(params.licenseKey) as LicenseRecord | undefined;
      if (!license) {
        throw new LicenseError('LICENSE_NOT_FOUND', 'License key does not exist.', 404);
      }

      const nowIso = new Date().toISOString();
      const revokedAt = params.status === 'active' ? null : nowIso;

      this.db
        .prepare(
          `UPDATE licenses
           SET status = ?, revoked_at = ?, revoke_reason = ?, updated_at = ?
           WHERE id = ?`
        )
        .run(
          params.status,
          revokedAt,
          params.status === 'active' ? null : params.reason,
          nowIso,
          license.id
        );

      const nextSubStatus =
        params.status === 'revoked'
          ? 'revoked'
          : params.status === 'blocked'
          ? 'suspended'
          : new Date(license.expires_at).getTime() <= Date.now()
          ? 'expired'
          : 'active';

      this.db
        .prepare(`UPDATE subscriptions SET status = ?, updated_at = ? WHERE id = ?`)
        .run(nextSubStatus, nowIso, license.subscription_id);

      this.recordHistory({
        licenseId: license.id,
        action: `STATUS_${params.status.toUpperCase()}`,
        previousStatus: license.status,
        newStatus: params.status,
        actorType: 'admin',
        actorId: params.adminActorId,
        reason: params.reason,
        metadata: { syncedSubscriptionStatus: nextSubStatus },
      });

      this.audit.record({
        actorType: 'admin',
        actorId: params.adminActorId,
        action: `LICENSE_STATUS_${params.status.toUpperCase()}`,
        entityType: 'license',
        entityId: license.license_key,
        severity: params.status === 'active' ? 'info' : 'warning',
        metadata: {
          previousStatus: license.status,
          newStatus: params.status,
          syncedSubscriptionStatus: nextSubStatus,
          reason: params.reason,
        },
      });

      return this.db
        .prepare('SELECT * FROM licenses WHERE id = ?')
        .get(license.id) as LicenseRecord;
    });
  }

  /**
   * Unbinds (revokes/removes) a device from a license so the user or admin can free a device slot.
   */
  unbindDevice(params: {
    licenseKey: string;
    deviceFingerprint: string;
    actorType: 'user' | 'admin';
    actorId: string;
    requesterUserId?: number;
    reason?: string;
  }): { unbound: boolean; licenseKey: string; deviceFingerprint: string } {
    return runImmediateTransaction(this.db, () => {
      const license = this.db
        .prepare('SELECT * FROM licenses WHERE license_key = ?')
        .get(params.licenseKey) as LicenseRecord | undefined;
      if (!license) {
        throw new LicenseError('LICENSE_NOT_FOUND', 'License key does not exist.', 404);
      }
      if (params.actorType === 'user' && license.user_id !== params.requesterUserId) {
        throw new LicenseError('FORBIDDEN_LICENSE_ACCESS', 'License does not belong to you.', 403);
      }

      const device = this.db
        .prepare('SELECT * FROM devices WHERE license_id = ? AND device_fingerprint = ?')
        .get(license.id, params.deviceFingerprint) as DeviceRecord | undefined;
      if (!device) {
        throw new LicenseError('DEVICE_NOT_FOUND', 'Bound device not found for this license.', 404);
      }

      this.db.prepare('DELETE FROM devices WHERE id = ?').run(device.id);

      this.recordHistory({
        licenseId: license.id,
        action: 'DEVICE_UNBOUND',
        previousStatus: license.status,
        newStatus: license.status,
        actorType: params.actorType,
        actorId: params.actorId,
        reason: params.reason ?? 'Device unbound',
        metadata: { deviceFingerprint: params.deviceFingerprint, deviceModel: device.device_model },
      });

      this.audit.record({
        actorType: params.actorType,
        actorId: params.actorId,
        action: 'LICENSE_DEVICE_UNBOUND',
        entityType: 'device',
        entityId: params.deviceFingerprint,
        metadata: { licenseKey: license.license_key },
      });

      return {
        unbound: true,
        licenseKey: license.license_key,
        deviceFingerprint: params.deviceFingerprint,
      };
    });
  }

  updateDeviceStatus(params: {
    licenseKey: string;
    deviceFingerprint: string;
    status: DeviceStatus;
    adminActorId: string;
  }): DeviceRecord {
    return runImmediateTransaction(this.db, () => {
      const license = this.db
        .prepare('SELECT * FROM licenses WHERE license_key = ?')
        .get(params.licenseKey) as LicenseRecord | undefined;
      if (!license) {
        throw new LicenseError('LICENSE_NOT_FOUND', 'License key does not exist.', 404);
      }
      const device = this.db
        .prepare('SELECT * FROM devices WHERE license_id = ? AND device_fingerprint = ?')
        .get(license.id, params.deviceFingerprint) as DeviceRecord | undefined;
      if (!device) {
        throw new LicenseError('DEVICE_NOT_FOUND', 'Bound device not found.', 404);
      }

      this.db
        .prepare('UPDATE devices SET status = ? WHERE id = ?')
        .run(params.status, device.id);

      this.recordHistory({
        licenseId: license.id,
        action: `DEVICE_STATUS_${params.status.toUpperCase()}`,
        previousStatus: device.status,
        newStatus: params.status,
        actorType: 'admin',
        actorId: params.adminActorId,
        metadata: { deviceFingerprint: params.deviceFingerprint },
      });

      return this.db
        .prepare('SELECT * FROM devices WHERE id = ?')
        .get(device.id) as DeviceRecord;
    });
  }

  /**
   * Daily online validation endpoint consumed by EDGE Android via Cloudflare Worker Gateway.
   * Security-hardened (Fail-Closed):
   * 1. Requires valid configured RSA public key (fails closed if missing).
   * 2. Verifies license exists, user is `active` (not banned/suspended), subscription is `active` and unexpired.
   * 3. Verifies stored RSA-2048 signature against public key.
   * 4. Atomically verifies or binds device within `max_devices`.
   * 5. Records security failures in `audit_logs`.
   */
  validateForAndroid(params: {
    licenseKey: string;
    deviceFingerprint: string;
    deviceModel?: string;
    androidVersion?: string;
    appVersion?: string;
    ipAddress?: string | null;
  }): {
    valid: boolean;
    reason?: string;
    licenseStatus?: string;
    expiresAt?: string;
    signatureValid: boolean;
    nextCheckHours: number;
  } {
    // 1. Fail-closed RSA public key guard
    if (!this.options.rsaPublicKeyPem || !this.options.rsaPublicKeyPem.includes('PUBLIC KEY')) {
      this.audit.record({
        actorType: 'gateway',
        actorId: params.deviceFingerprint,
        action: 'RSA_PUBLIC_KEY_MISSING_ON_VALIDATE',
        entityType: 'license',
        entityId: params.licenseKey,
        severity: 'critical',
        ipAddress: params.ipAddress,
      });
      return {
        valid: false,
        reason: 'RSA_PUBLIC_KEY_NOT_CONFIGURED',
        signatureValid: false,
        nextCheckHours: 24,
      };
    }

    const license = this.db
      .prepare('SELECT * FROM licenses WHERE license_key = ?')
      .get(params.licenseKey) as LicenseRecord | undefined;

    if (!license) {
      this.audit.record({
        actorType: 'gateway',
        actorId: params.deviceFingerprint,
        action: 'ANDROID_VALIDATE_UNKNOWN_LICENSE',
        entityType: 'license',
        entityId: params.licenseKey,
        severity: 'warning',
        ipAddress: params.ipAddress,
      });
      return { valid: false, reason: 'LICENSE_NOT_FOUND', signatureValid: false, nextCheckHours: 24 };
    }

    // 2. Enforce account ban / suspension immediately
    const owner = this.db
      .prepare('SELECT id, status FROM users WHERE id = ?')
      .get(license.user_id) as { id: number; status: UserRecord['status'] } | undefined;

    if (!owner || owner.status !== 'active') {
      const reason = owner ? `USER_${owner.status.toUpperCase()}` : 'USER_NOT_FOUND';
      this.audit.record({
        actorType: 'gateway',
        actorId: params.deviceFingerprint,
        action: 'ANDROID_VALIDATE_USER_RESTRICTED',
        entityType: 'license',
        entityId: license.license_key,
        severity: 'warning',
        metadata: { reason },
        ipAddress: params.ipAddress,
      });
      return {
        valid: false,
        reason,
        licenseStatus: license.status,
        expiresAt: license.expires_at,
        signatureValid: false,
        nextCheckHours: 24,
      };
    }

    // 3. Verify linked subscription status
    const subscription = this.db
      .prepare('SELECT id, status, expires_at FROM subscriptions WHERE id = ?')
      .get(license.subscription_id) as
      | { id: number; status: SubscriptionRecord['status']; expires_at: string }
      | undefined;

    if (!subscription || subscription.status !== 'active') {
      const reason = subscription
        ? `SUBSCRIPTION_${subscription.status.toUpperCase()}`
        : 'SUBSCRIPTION_NOT_FOUND';
      return {
        valid: false,
        reason,
        licenseStatus: license.status,
        expiresAt: license.expires_at,
        signatureValid: false,
        nextCheckHours: 24,
      };
    }

    if (license.status !== 'active') {
      return {
        valid: false,
        reason: `LICENSE_${license.status.toUpperCase()}`,
        licenseStatus: license.status,
        expiresAt: license.expires_at,
        signatureValid: false,
        nextCheckHours: 24,
      };
    }

    const nowMs = Date.now();
    if (
      new Date(license.expires_at).getTime() <= nowMs ||
      new Date(subscription.expires_at).getTime() <= nowMs
    ) {
      const nowIso = new Date(nowMs).toISOString();
      runImmediateTransaction(this.db, () => {
        this.db
          .prepare(`UPDATE licenses SET status = 'expired', updated_at = ? WHERE id = ?`)
          .run(nowIso, license.id);
        this.db
          .prepare(`UPDATE subscriptions SET status = 'expired', updated_at = ? WHERE id = ?`)
          .run(nowIso, subscription.id);
      });
      return {
        valid: false,
        reason: 'LICENSE_EXPIRED',
        licenseStatus: 'expired',
        expiresAt: license.expires_at,
        signatureValid: false,
        nextCheckHours: 24,
      };
    }

    // 4. Mandatory RSA-2048 cryptographic verification
    const signatureValid = verifyLicenseSignature(
      license.payload_json,
      license.signature_base64,
      this.options.rsaPublicKeyPem
    );
    if (!signatureValid) {
      this.audit.record({
        actorType: 'gateway',
        actorId: params.deviceFingerprint,
        action: 'RSA_SIGNATURE_VERIFICATION_FAILED',
        entityType: 'license',
        entityId: license.license_key,
        severity: 'critical',
        ipAddress: params.ipAddress,
      });
      return {
        valid: false,
        reason: 'RSA_SIGNATURE_INVALID',
        licenseStatus: license.status,
        signatureValid: false,
        nextCheckHours: 24,
      };
    }

    // 5. Atomic device check / binding inside IMMEDIATE transaction
    const bindOutcome = runImmediateTransaction(this.db, () => {
      const existingDevice = this.db
        .prepare('SELECT * FROM devices WHERE license_id = ? AND device_fingerprint = ?')
        .get(license.id, params.deviceFingerprint) as DeviceRecord | undefined;

      const nowIso = new Date().toISOString();

      if (existingDevice) {
        if (existingDevice.status !== 'active') {
          return { allowed: false as const, reason: `DEVICE_${existingDevice.status.toUpperCase()}` };
        }
        this.db
          .prepare(
            `UPDATE devices
             SET device_model = COALESCE(?, device_model),
                 android_version = COALESCE(?, android_version),
                 app_version = COALESCE(?, app_version),
                 last_seen_at = ?
             WHERE id = ?`
          )
          .run(
            params.deviceModel ?? null,
            params.androidVersion ?? null,
            params.appVersion ?? null,
            nowIso,
            existingDevice.id
          );
      } else {
        const countRow = this.db
          .prepare(`SELECT COUNT(*) AS cnt FROM devices WHERE license_id = ? AND status = 'active'`)
          .get(license.id) as { cnt: number };

        if (countRow.cnt >= license.max_devices) {
          return { allowed: false as const, reason: 'DEVICE_LIMIT_EXCEEDED' };
        }

        this.db
          .prepare(
            `INSERT INTO devices (license_id, user_id, device_fingerprint, device_model, android_version, app_version, status)
             VALUES (?, ?, ?, ?, ?, ?, 'active')`
          )
          .run(
            license.id,
            license.user_id,
            params.deviceFingerprint,
            params.deviceModel ?? null,
            params.androidVersion ?? null,
            params.appVersion ?? null
          );
      }

      this.db
        .prepare('UPDATE licenses SET last_validated_at = ? WHERE id = ?')
        .run(nowIso, license.id);

      return { allowed: true as const };
    });

    if (!bindOutcome.allowed) {
      this.audit.record({
        actorType: 'gateway',
        actorId: params.deviceFingerprint,
        action: 'ANDROID_VALIDATE_DEVICE_REJECTED',
        entityType: 'license',
        entityId: license.license_key,
        severity: 'warning',
        metadata: { reason: bindOutcome.reason },
        ipAddress: params.ipAddress,
      });
      return {
        valid: false,
        reason: bindOutcome.reason,
        licenseStatus: license.status,
        expiresAt: license.expires_at,
        signatureValid,
        nextCheckHours: 24,
      };
    }

    return {
      valid: true,
      licenseStatus: license.status,
      expiresAt: license.expires_at,
      signatureValid,
      nextCheckHours: 24,
    };
  }

  listLicenseHistory(licenseKey: string): LicenseHistoryRecord[] {
    const lic = this.db
      .prepare('SELECT id FROM licenses WHERE license_key = ?')
      .get(licenseKey) as { id: number } | undefined;
    if (!lic) {
      throw new LicenseError('LICENSE_NOT_FOUND', 'License key does not exist.', 404);
    }
    return this.db
      .prepare('SELECT * FROM license_history WHERE license_id = ? ORDER BY id DESC LIMIT 100')
      .all(lic.id) as LicenseHistoryRecord[];
  }

  listUserLicenses(userId: number): Array<LicenseRecord & { devices: DeviceRecord[] }> {
    const licenses = this.db
      .prepare('SELECT * FROM licenses WHERE user_id = ? ORDER BY id DESC')
      .all(userId) as LicenseRecord[];

    return licenses.map((lic) => {
      const devices = this.db
        .prepare('SELECT * FROM devices WHERE license_id = ? ORDER BY id DESC')
        .all(lic.id) as DeviceRecord[];
      return { ...lic, devices };
    });
  }

  listUserSubscriptions(userId: number): SubscriptionRecord[] {
    return this.db
      .prepare('SELECT * FROM subscriptions WHERE user_id = ? ORDER BY id DESC')
      .all(userId) as SubscriptionRecord[];
  }
}
