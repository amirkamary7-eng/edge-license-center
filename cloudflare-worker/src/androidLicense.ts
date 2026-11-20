/**
 * Android License API (Path B-1) & Edge-First Revocation Engine
 * - ZERO shared HMAC secrets embedded in Android APK.
 * - Uses Android Keystore hardware-backed ECDSA P-256 public key binding.
 * - Issues RSA-2048 / SHA-256 signed validation receipts (private key strictly in Worker Secrets).
 */

import {
  randomHex,
  sha256Hex,
  signRsaSha256,
  verifyEcdsaP256Signature,
  verifyRsaSha256,
} from './crypto';
import type { D1Database, WorkerEnv } from './d1Types';
import {
  claimSingleUseKey,
  DomainError,
  recordAuditLog,
  recordSecurityEvent,
} from './ordersAndPayments';

export async function issueDeviceChallengeD1(
  db: D1Database,
  params: {
    licenseKey: string;
    deviceKeyId: string;
    deviceFingerprint: string;
  }
): Promise<{ challengeId: string; challengeNonce: string; expiresAt: string }> {
  const lic = await db
    .prepare(
      `SELECT l.id, l.status, l.expires_at, l.max_devices, s.status AS sub_status, u.status AS user_status
       FROM licenses l
       JOIN subscriptions s ON s.id = l.subscription_id
       JOIN users u ON u.id = l.user_id
       WHERE l.license_key = ?`
    )
    .bind(params.licenseKey)
    .first<{
      id: number;
      status: string;
      expires_at: string;
      max_devices: number;
      sub_status: string;
      user_status: string;
    }>();

  if (!lic) throw new DomainError('LICENSE_NOT_FOUND', 'License not found.', 404);
  if (lic.user_status !== 'active') {
    throw new DomainError(`USER_${lic.user_status.toUpperCase()}`, 'Account is restricted.', 403);
  }
  if (lic.sub_status !== 'active' || lic.status !== 'active') {
    throw new DomainError('LICENSE_NOT_ACTIVE', 'License or subscription is not active.', 403);
  }
  if (new Date(lic.expires_at).getTime() <= Date.now()) {
    throw new DomainError('LICENSE_EXPIRED', 'License has expired.', 403);
  }

  const existingSame = await db
    .prepare(`SELECT id, status FROM devices WHERE license_id = ? AND device_key_id = ?`)
    .bind(lic.id, params.deviceKeyId)
    .first<{ id: number; status: string }>();
  if (!existingSame) {
    const cntRow = await db
      .prepare(`SELECT COUNT(*) AS cnt FROM devices WHERE license_id = ? AND status = 'active'`)
      .bind(lic.id)
      .first<{ cnt: number }>();
    if ((cntRow?.cnt ?? 0) >= lic.max_devices) {
      throw new DomainError('DEVICE_LIMIT_EXCEEDED', 'Maximum device limit reached for license.', 403);
    }
  }

  const challengeId = `chg_${randomHex(12)}`;
  const challengeNonce = randomHex(24);
  const expiresAt = new Date(Date.now() + 90_000).toISOString();

  await db
    .prepare(
      `INSERT INTO activation_challenges (challenge_id, license_key, device_key_id, device_fingerprint, challenge_nonce, expires_at)
       VALUES (?, ?, ?, ?, ?, ?)`
    )
    .bind(
      challengeId,
      params.licenseKey,
      params.deviceKeyId,
      params.deviceFingerprint,
      challengeNonce,
      expiresAt
    )
    .run();

  return { challengeId, challengeNonce, expiresAt };
}

export async function activateDeviceWithProofD1(
  db: D1Database,
  env: WorkerEnv,
  params: {
    challengeId: string;
    licenseKey: string;
    deviceKeyId: string;
    deviceFingerprint: string;
    devicePublicKeySpkiBase64: string;
    proofSignatureBase64: string;
    attestationLevel?: 'strongbox' | 'tee' | 'software';
    deviceModel?: string;
    androidVersion?: string;
    appVersion?: string;
    ipAddress?: string | null;
  }
): Promise<{
  activated: boolean;
  deviceId: number;
  deviceKeyId: string;
  attestationLevel: string;
  licensePayloadJson: string;
  licenseSignatureBase64: string;
  receipt: Record<string, unknown>;
  receiptSignatureBase64: string;
}> {
  const nowIso = new Date().toISOString();
  const challenge = await db
    .prepare(
      `UPDATE activation_challenges
       SET consumed_at = ?
       WHERE challenge_id = ? AND license_key = ? AND device_key_id = ?
         AND device_fingerprint = ? AND consumed_at IS NULL AND expires_at > ?
       RETURNING *`
    )
    .bind(
      nowIso,
      params.challengeId,
      params.licenseKey,
      params.deviceKeyId,
      params.deviceFingerprint,
      nowIso
    )
    .first<{
      challenge_id: string;
      challenge_nonce: string;
    }>();

  if (!challenge) {
    await recordSecurityEvent(db, {
      eventType: 'REPLAY_NONCE',
      severity: 'high',
      licenseKey: params.licenseKey,
      deviceKeyId: params.deviceKeyId,
      ipAddress: params.ipAddress,
      details: { reason: 'CHALLENGE_INVALID_OR_CONSUMED', challengeId: params.challengeId },
    });
    throw new DomainError('CHALLENGE_INVALID_OR_EXPIRED', 'Challenge missing, expired, or already used.', 401);
  }

  // Verify Keystore ECDSA P-256 signature over canonical challenge proof
  const proofMessage = [
    'EDGE_ACTIVATE_V1',
    params.challengeId,
    challenge.challenge_nonce,
    params.licenseKey,
    params.deviceKeyId,
    params.deviceFingerprint,
  ].join('\n');

  const verifiedProof = await verifyEcdsaP256Signature(
    proofMessage,
    params.proofSignatureBase64,
    params.devicePublicKeySpkiBase64
  );

  if (!verifiedProof) {
    await recordSecurityEvent(db, {
      eventType: 'ECDSA_INVALID',
      severity: 'high',
      licenseKey: params.licenseKey,
      deviceKeyId: params.deviceKeyId,
      ipAddress: params.ipAddress,
      details: { stage: 'activate' },
    });
    throw new DomainError('DEVICE_PROOF_INVALID', 'Invalid Android Keystore ECDSA signature.', 401);
  }

  const lic = await db
    .prepare(
      `SELECT l.*, s.status AS sub_status, u.status AS user_status
       FROM licenses l
       JOIN subscriptions s ON s.id = l.subscription_id
       JOIN users u ON u.id = l.user_id
       WHERE l.license_key = ?`
    )
    .bind(params.licenseKey)
    .first<{
      id: number;
      license_key: string;
      user_id: number;
      payload_json: string;
      signature_base64: string;
      status: string;
      max_devices: number;
      offline_grace_hours: number;
      expires_at: string;
      sub_status: string;
      user_status: string;
    }>();

  if (!lic || lic.status !== 'active' || lic.sub_status !== 'active' || lic.user_status !== 'active') {
    throw new DomainError('LICENSE_NOT_ACTIVE', 'License is inactive or restricted.', 403);
  }

  const attestationLevel = params.attestationLevel ?? 'tee';
  const existing = await db
    .prepare(`SELECT id, status FROM devices WHERE license_id = ? AND device_key_id = ?`)
    .bind(lic.id, params.deviceKeyId)
    .first<{ id: number; status: string }>();

  if (existing && existing.status !== 'active') {
    throw new DomainError('DEVICE_RESTRICTED', `Device status is ${existing.status}.`, 403);
  }

  if (!existing) {
    // Atomic capacity-checked insert (prevents race over max_devices)
    const inserted = await db
      .prepare(
        `INSERT INTO devices (
           license_id, user_id, device_fingerprint, device_key_id, device_public_key_spki,
           attestation_level, device_model, android_version, app_version, status, first_bound_at, last_seen_at, updated_at
         )
         SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?
         WHERE (SELECT COUNT(*) FROM devices WHERE license_id = ? AND status = 'active') < ?
         RETURNING id`
      )
      .bind(
        lic.id,
        lic.user_id,
        params.deviceFingerprint,
        params.deviceKeyId,
        params.devicePublicKeySpkiBase64,
        attestationLevel,
        params.deviceModel ?? null,
        params.androidVersion ?? null,
        params.appVersion ?? null,
        nowIso,
        nowIso,
        nowIso,
        lic.id,
        lic.max_devices
      )
      .first<{ id: number }>();

    if (!inserted) {
      throw new DomainError('DEVICE_LIMIT_EXCEEDED', 'Maximum active devices reached for this license.', 403);
    }
  } else {
    await db
      .prepare(
        `UPDATE devices
         SET device_public_key_spki = ?, attestation_level = ?, device_model = COALESCE(?, device_model),
             android_version = COALESCE(?, android_version), app_version = COALESCE(?, app_version),
             last_seen_at = ?, updated_at = ?
         WHERE id = ?`
      )
      .bind(
        params.devicePublicKeySpkiBase64,
        attestationLevel,
        params.deviceModel ?? null,
        params.androidVersion ?? null,
        params.appVersion ?? null,
        nowIso,
        nowIso,
        existing.id
      )
      .run();
  }

  const deviceRow = (await db
    .prepare(`SELECT id FROM devices WHERE license_id = ? AND device_key_id = ?`)
    .bind(lic.id, params.deviceKeyId)
    .first<{ id: number }>())!;

  const revSeqRow = await db
    .prepare(`SELECT COALESCE(MAX(revocation_seq), 0) AS seq FROM revocations WHERE active = 1`)
    .first<{ seq: number }>();

  const offlineGraceSec =
    attestationLevel === 'software'
      ? Math.min(lic.offline_grace_hours, 24) * 3600
      : lic.offline_grace_hours * 3600;

  const receipt = {
    decisionCode: 'OK',
    deviceKeyId: params.deviceKeyId,
    expiresAt: lic.expires_at,
    keyId: env.RSA_KEY_ID ?? 'edge-rsa-v1',
    licenseKey: lic.license_key,
    nextCheckAfterSec: 86400,
    nonce: challenge.challenge_nonce,
    offlineGraceSec,
    receiptVersion: 1,
    revocationSeq: revSeqRow?.seq ?? 0,
    serverTimeUtc: nowIso,
    valid: true,
  };

  if (!env.RSA_PRIVATE_KEY_PEM) {
    throw new DomainError('RSA_KEY_MISSING', 'Worker RSA signing key is not configured.', 500);
  }
  const signedReceipt = await signRsaSha256(receipt, env.RSA_PRIVATE_KEY_PEM);

  await recordAuditLog(db, {
    actorType: 'gateway',
    actorId: params.deviceKeyId,
    action: 'DEVICE_ACTIVATED_ECDSA',
    entityType: 'device',
    entityId: String(deviceRow.id),
    metadata: { licenseKey: params.licenseKey, attestationLevel },
    ipAddress: params.ipAddress,
  });

  return {
    activated: true,
    deviceId: deviceRow.id,
    deviceKeyId: params.deviceKeyId,
    attestationLevel,
    licensePayloadJson: lic.payload_json,
    licenseSignatureBase64: lic.signature_base64,
    receipt,
    receiptSignatureBase64: signedReceipt.signatureBase64,
  };
}

export async function validateAndroidLicenseD1(
  db: D1Database,
  env: WorkerEnv,
  params: {
    licenseKey: string;
    deviceKeyId: string;
    rawBody: string;
    timestampHeader: string | null;
    nonceHeader: string | null;
    deviceSignatureHeader: string | null;
    appVersion?: string;
    ipAddress?: string | null;
  }
): Promise<{ status: number; body: Record<string, unknown> }> {
  if (!env.RSA_PUBLIC_KEY_PEM || !env.RSA_PRIVATE_KEY_PEM) {
    return {
      status: 503,
      body: { valid: false, reason: 'RSA_KEYS_NOT_CONFIGURED' },
    };
  }

  // 1. Strict Timestamp Window (+/- 120s)
  const tsNum = Number(params.timestampHeader ?? '');
  const nowSec = Math.floor(Date.now() / 1000);
  if (!Number.isInteger(tsNum) || Math.abs(nowSec - tsNum) > 120) {
    await recordSecurityEvent(db, {
      eventType: 'TIMESTAMP_SKEW',
      severity: 'medium',
      licenseKey: params.licenseKey,
      deviceKeyId: params.deviceKeyId,
      ipAddress: params.ipAddress,
    });
    return { status: 401, body: { valid: false, reason: 'INVALID_TIMESTAMP' } };
  }

  // 2. Strict Single-Use Nonce (Anti-Replay 300s)
  const nonce = params.nonceHeader?.trim() ?? '';
  if (nonce.length < 16 || nonce.length > 128) {
    return { status: 401, body: { valid: false, reason: 'INVALID_NONCE' } };
  }
  const nonceFresh = await claimSingleUseKey(db, {
    scope: 'android_validate_nonce',
    key: `${params.deviceKeyId}:${nonce}`,
    actorId: params.deviceKeyId,
    ttlSeconds: 300,
  });
  if (!nonceFresh) {
    await recordSecurityEvent(db, {
      eventType: 'REPLAY_NONCE',
      severity: 'high',
      licenseKey: params.licenseKey,
      deviceKeyId: params.deviceKeyId,
      ipAddress: params.ipAddress,
    });
    return { status: 401, body: { valid: false, reason: 'REPLAYED_NONCE' } };
  }

  // 3. Look up License, Owner, Subscription, Bound Device & Active Revocations
  const lic = await db
    .prepare(
      `SELECT l.*, s.status AS sub_status, s.expires_at AS sub_expires_at, u.status AS user_status, u.telegram_id
       FROM licenses l
       JOIN subscriptions s ON s.id = l.subscription_id
       JOIN users u ON u.id = l.user_id
       WHERE l.license_key = ?`
    )
    .bind(params.licenseKey)
    .first<{
      id: number;
      license_key: string;
      subscription_id: number;
      user_id: number;
      payload_json: string;
      signature_base64: string;
      status: string;
      max_devices: number;
      offline_grace_hours: number;
      expires_at: string;
      sub_status: string;
      sub_expires_at: string;
      user_status: string;
      telegram_id: string;
    }>();

  if (!lic) {
    return { status: 404, body: { valid: false, reason: 'LICENSE_NOT_FOUND' } };
  }

  const device = await db
    .prepare(`SELECT * FROM devices WHERE license_id = ? AND device_key_id = ?`)
    .bind(lic.id, params.deviceKeyId)
    .first<{
      id: number;
      device_key_id: string;
      device_public_key_spki: string;
      attestation_level: string;
      status: string;
    }>();

  if (!device) {
    return { status: 401, body: { valid: false, reason: 'DEVICE_NOT_BOUND' } };
  }

  // 4. Verify Android Keystore ECDSA P-256 request signature (zero shared APK secrets)
  if (!params.deviceSignatureHeader) {
    return { status: 401, body: { valid: false, reason: 'MISSING_DEVICE_SIGNATURE' } };
  }
  const bodySha = await sha256Hex(params.rawBody);
  const canonicalMsg = `POST\n/v1/license/validate\n${params.timestampHeader}\n${nonce}\n${params.licenseKey}\n${params.deviceKeyId}\n${bodySha}`;
  const sigOk = await verifyEcdsaP256Signature(
    canonicalMsg,
    params.deviceSignatureHeader,
    device.device_public_key_spki
  );
  if (!sigOk) {
    await recordSecurityEvent(db, {
      eventType: 'ECDSA_INVALID',
      severity: 'high',
      userId: lic.user_id,
      licenseKey: lic.license_key,
      deviceKeyId: params.deviceKeyId,
      ipAddress: params.ipAddress,
    });
    return { status: 401, body: { valid: false, reason: 'INVALID_DEVICE_SIGNATURE' } };
  }

  // Helper to return RSA-2048 signed online decision
  const buildSignedDecision = async (
    httpStatus: number,
    valid: boolean,
    decisionCode: string,
    extra: Record<string, unknown> = {}
  ) => {
    const revRow = await db
      .prepare(`SELECT COALESCE(MAX(revocation_seq), 0) AS seq FROM revocations WHERE active = 1`)
      .first<{ seq: number }>();
    const nowIso = new Date().toISOString();
    const graceSec = valid
      ? (device.attestation_level === 'software'
          ? Math.min(lic.offline_grace_hours, 24)
          : lic.offline_grace_hours) * 3600
      : 0;
    const receipt = {
      decisionCode,
      deviceKeyId: params.deviceKeyId,
      expiresAt: lic.expires_at,
      keyId: env.RSA_KEY_ID ?? 'edge-rsa-v1',
      licenseKey: lic.license_key,
      nextCheckAfterSec: valid ? 86400 : 0,
      nonce,
      offlineGraceSec: graceSec,
      receiptVersion: 1,
      revocationSeq: revRow?.seq ?? 0,
      serverTimeUtc: nowIso,
      valid,
    };
    const signed = await signRsaSha256(receipt, env.RSA_PRIVATE_KEY_PEM!);
    return {
      status: httpStatus,
      body: {
        valid,
        reason: valid ? undefined : decisionCode,
        licenseStatus: extra.licenseStatus ?? lic.status,
        expiresAt: lic.expires_at,
        signatureValid: extra.signatureValid ?? true,
        nextCheckHours: valid ? 24 : 0,
        receipt,
        receiptSignatureBase64: signed.signatureBase64,
      },
    };
  };

  if (lic.user_status !== 'active') {
    return buildSignedDecision(200, false, `USER_${lic.user_status.toUpperCase()}`);
  }
  if (device.status !== 'active') {
    return buildSignedDecision(200, false, `DEVICE_${device.status.toUpperCase()}`);
  }

  // Check active revocation entries
  const activeRev = await db
    .prepare(
      `SELECT revocation_seq, reason_code FROM revocations
       WHERE active = 1 AND (
         (entity_type = 'license' AND entity_id = ?) OR
         (entity_type = 'device' AND entity_id = ?) OR
         (entity_type = 'user' AND entity_id = ?)
       )
       LIMIT 1`
    )
    .bind(lic.license_key, params.deviceKeyId, lic.telegram_id)
    .first<{ revocation_seq: number; reason_code: string }>();
  if (activeRev) {
    return buildSignedDecision(200, false, `REVOKED:${activeRev.reason_code}`);
  }

  if (lic.sub_status !== 'active') {
    return buildSignedDecision(200, false, `SUBSCRIPTION_${lic.sub_status.toUpperCase()}`);
  }
  if (lic.status !== 'active') {
    return buildSignedDecision(200, false, `LICENSE_${lic.status.toUpperCase()}`);
  }

  const nowMs = Date.now();
  if (
    new Date(lic.expires_at).getTime() <= nowMs ||
    new Date(lic.sub_expires_at).getTime() <= nowMs
  ) {
    const expIso = new Date(nowMs).toISOString();
    await db.batch([
      db.prepare(`UPDATE licenses SET status = 'expired', updated_at = ? WHERE id = ?`).bind(expIso, lic.id),
      db.prepare(`UPDATE subscriptions SET status = 'expired', updated_at = ? WHERE id = ?`).bind(expIso, lic.subscription_id),
    ]);
    return buildSignedDecision(200, false, 'LICENSE_EXPIRED', { licenseStatus: 'expired' });
  }

  const storedSigValid = await verifyRsaSha256(
    lic.payload_json,
    lic.signature_base64,
    env.RSA_PUBLIC_KEY_PEM
  );
  if (!storedSigValid) {
    await recordSecurityEvent(db, {
      eventType: 'SIGNATURE_MISMATCH',
      severity: 'critical',
      userId: lic.user_id,
      licenseKey: lic.license_key,
      deviceKeyId: params.deviceKeyId,
      ipAddress: params.ipAddress,
    });
    return buildSignedDecision(200, false, 'RSA_SIGNATURE_INVALID', { signatureValid: false });
  }

  const nowIso = new Date(nowMs).toISOString();
  const receiptExpIso = new Date(nowMs + lic.offline_grace_hours * 3600_000).toISOString();
  const ipHash = params.ipAddress ? (await sha256Hex(params.ipAddress)).slice(0, 16) : null;

  await db.batch([
    db
      .prepare(`UPDATE devices SET app_version = COALESCE(?, app_version), last_seen_at = ?, updated_at = ? WHERE id = ?`)
      .bind(params.appVersion ?? null, nowIso, nowIso, device.id),
    db
      .prepare(`UPDATE licenses SET last_validated_at = ?, updated_at = ? WHERE id = ?`)
      .bind(nowIso, nowIso, lic.id),
    db
      .prepare(
        `INSERT INTO device_sessions (device_id, license_id, user_id, session_nonce, client_ip_hash, app_version, last_server_time_utc, receipt_expires_at, status)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active')`
      )
      .bind(device.id, lic.id, lic.user_id, nonce, ipHash, params.appVersion ?? null, nowIso, receiptExpIso),
  ]);

  return buildSignedDecision(200, true, 'OK');
}

/**
 * Path B-1 Edge-First Atomic Revocation / Block / Admin Reactivation
 */
export async function updateLicenseStatusD1(
  db: D1Database,
  params: {
    licenseKey: string;
    status: 'active' | 'revoked' | 'blocked';
    reason: string;
    adminActorId: string;
  }
): Promise<{ licenseKey: string; status: string; revocationSeq: number | null; syncState: string }> {
  const lic = await db
    .prepare(`SELECT * FROM licenses WHERE license_key = ?`)
    .bind(params.licenseKey)
    .first<{ id: number; license_key: string; subscription_id: number; status: string; expires_at: string }>();
  if (!lic) throw new DomainError('LICENSE_NOT_FOUND', 'License key not found.', 404);

  const nowIso = new Date().toISOString();
  const nextSubStatus =
    params.status === 'revoked'
      ? 'revoked'
      : params.status === 'blocked'
      ? 'suspended'
      : new Date(lic.expires_at).getTime() <= Date.now()
      ? 'expired'
      : 'active';

  if (params.status === 'active') {
    await db.batch([
      db
        .prepare(
          `UPDATE licenses SET status = 'active', revoked_at = NULL, revoke_reason = NULL,
                              version = version + 1, updated_at = ?
           WHERE id = ?`
        )
        .bind(nowIso, lic.id),
      db
        .prepare(`UPDATE subscriptions SET status = ?, version = version + 1, updated_at = ? WHERE id = ?`)
        .bind(nextSubStatus, nowIso, lic.subscription_id),
      db
        .prepare(`UPDATE revocations SET active = 0, lifted_at = ? WHERE entity_type = 'license' AND entity_id = ? AND active = 1`)
        .bind(nowIso, lic.license_key),
      db
        .prepare(
          `INSERT INTO license_history (license_id, action, previous_status, new_status, actor_type, actor_id, reason)
           VALUES (?, 'STATUS_ACTIVE', ?, 'active', 'admin', ?, ?)`
        )
        .bind(lic.id, lic.status, params.adminActorId, params.reason),
    ]);
    return { licenseKey: lic.license_key, status: 'active', revocationSeq: null, syncState: 'FULLY_SYNCHRONIZED' };
  }

  await db.batch([
    db
      .prepare(
        `UPDATE licenses SET status = ?, revoked_at = ?, revoke_reason = ?,
                            revocation_epoch = revocation_epoch + 1, version = version + 1, updated_at = ?
         WHERE id = ?`
      )
      .bind(params.status, nowIso, params.reason, nowIso, lic.id),
    db
      .prepare(`UPDATE subscriptions SET status = ?, version = version + 1, updated_at = ? WHERE id = ?`)
      .bind(nextSubStatus, nowIso, lic.subscription_id),
    db
      .prepare(`UPDATE device_sessions SET status = 'revoked', updated_at = ? WHERE license_id = ? AND status = 'active'`)
      .bind(nowIso, lic.id),
    db
      .prepare(
        `INSERT INTO revocations (entity_type, entity_id, license_key, reason_code, reason_detail, sync_state, actor_type, actor_id, active)
         VALUES ('license', ?, ?, ?, ?, 'FULLY_SYNCHRONIZED', 'admin', ?, 1)`
      )
      .bind(
        lic.license_key,
        lic.license_key,
        params.status === 'revoked' ? 'ADMIN_REVOKED' : 'ADMIN_BLOCKED',
        params.reason,
        params.adminActorId
      ),
    db
      .prepare(
        `INSERT INTO license_history (license_id, action, previous_status, new_status, actor_type, actor_id, reason)
         VALUES (?, ?, ?, ?, 'admin', ?, ?)`
      )
      .bind(
        lic.id,
        `STATUS_${params.status.toUpperCase()}`,
        lic.status,
        params.status,
        params.adminActorId,
        params.reason
      ),
  ]);

  const rev = await db
    .prepare(`SELECT revocation_seq, sync_state FROM revocations WHERE entity_type = 'license' AND entity_id = ? ORDER BY revocation_seq DESC LIMIT 1`)
    .bind(lic.license_key)
    .first<{ revocation_seq: number; sync_state: string }>();

  return {
    licenseKey: lic.license_key,
    status: params.status,
    revocationSeq: rev?.revocation_seq ?? null,
    syncState: rev?.sync_state ?? 'FULLY_SYNCHRONIZED',
  };
}
