/**
 * Encrypted R2 Backup & Offline-Decryption Verification (Path B-1)
 * - Exports canonical D1 snapshot JSON across all core tables.
 * - Encrypts snapshot with AES-256-GCM + wraps DEK using BACKUP_RSA_PUBLIC_KEY_PEM ONLY.
 * - Decryption RSA private key is NEVER present in Worker, D1, R2, or GitHub.
 */

import {
  canonicalizeJson,
  decryptBackupEnvelope,
  encryptBackupWithOfflinePublicKey,
  sha256Hex,
  type EncryptedBackupEnvelope,
} from './crypto';
import type { D1Database, R2Bucket, WorkerEnv } from './d1Types';
import { recordAuditLog } from './ordersAndPayments';

export interface D1BackupSnapshot {
  schemaVersion: string;
  exportedAtUtc: string;
  environment: string;
  rowCounts: Record<string, number>;
  tables: Record<string, unknown[]>;
}

const BACKUP_TABLES = [
  'users',
  'admins',
  'plans',
  'orders',
  'payments',
  'subscriptions',
  'subscription_events',
  'licenses',
  'license_history',
  'devices',
  'device_sessions',
  'revocations',
  'notifications',
  'support_tickets',
  'audit_logs',
  'security_events',
  'system_settings',
  'sync_outbox',
  'cron_runs',
] as const;

export async function exportD1CanonicalSnapshot(
  db: D1Database,
  environment = 'staging'
): Promise<D1BackupSnapshot> {
  const tables: Record<string, unknown[]> = {};
  const rowCounts: Record<string, number> = {};

  for (const table of BACKUP_TABLES) {
    const res = await db.prepare(`SELECT * FROM ${table}`).all<Record<string, unknown>>();
    const rows = res.results ?? [];
    tables[table] = rows;
    rowCounts[table] = rows.length;
  }

  return {
    schemaVersion: 'path_b1_d1_v1',
    exportedAtUtc: new Date().toISOString(),
    environment,
    rowCounts,
    tables,
  };
}

export async function runEncryptedR2Backup(
  db: D1Database,
  bucket: R2Bucket,
  env: WorkerEnv,
  options?: { dateKey?: string; actorId?: string }
): Promise<{
  skipped: boolean;
  reason?: string;
  r2Key?: string;
  plaintextSha256?: string;
  sizeBytes?: number;
  prunedKeys?: string[];
}> {
  if (!env.BACKUP_RSA_PUBLIC_KEY_PEM || !env.BACKUP_RSA_PUBLIC_KEY_PEM.includes('PUBLIC KEY')) {
    return { skipped: true, reason: 'BACKUP_RSA_PUBLIC_KEY_MISSING' };
  }

  const snapshot = await exportD1CanonicalSnapshot(
    db,
    env.ENVIRONMENT ?? env.GATEWAY_PHASE ?? 'staging'
  );
  const canonical = canonicalizeJson(snapshot);
  const envelope = await encryptBackupWithOfflinePublicKey(canonical, env.BACKUP_RSA_PUBLIC_KEY_PEM);

  const stamp = options?.dateKey ?? new Date().toISOString().replace(/[:.]/g, '-');
  const r2Key = `backups/d1/${stamp}.enc.json`;
  const body = JSON.stringify(envelope);

  await bucket.put(r2Key, body, {
    httpMetadata: { contentType: 'application/json' },
    customMetadata: {
      schemaVersion: snapshot.schemaVersion,
      plaintextSha256: envelope.plaintextSha256,
      algorithm: envelope.algorithm,
    },
  });

  // Retention pruning (keep newest N backups)
  const retentionCount = Math.max(1, Number(env.BACKUP_RETENTION_DAYS ?? 30));
  const listed = await bucket.list({ prefix: 'backups/d1/', limit: 500 });
  const sorted = [...listed.objects].sort((a, b) => a.key.localeCompare(b.key)).reverse();
  const prunedKeys: string[] = [];
  for (const stale of sorted.slice(retentionCount)) {
    if (stale.key === r2Key) continue;
    await bucket.delete(stale.key);
    prunedKeys.push(stale.key);
  }

  await recordAuditLog(db, {
    actorType: 'cron',
    actorId: options?.actorId ?? 'r2_backup',
    action: 'ENCRYPTED_R2_BACKUP_UPLOADED',
    entityType: 'backup',
    entityId: r2Key,
    metadata: {
      plaintextSha256: envelope.plaintextSha256,
      sizeBytes: body.length,
      prunedCount: prunedKeys.length,
      rowCounts: snapshot.rowCounts,
    },
  });

  return {
    skipped: false,
    r2Key,
    plaintextSha256: envelope.plaintextSha256,
    sizeBytes: body.length,
    prunedKeys,
  };
}

/**
 * Offline/Staging verification helper: reads encrypted envelope from R2 and verifies
 * AES-GCM + RSA-OAEP-256 decryption & SHA-256 integrity using an explicitly passed offline key.
 */
export async function verifyAndDecryptR2BackupForTest(
  bucket: R2Bucket,
  r2Key: string,
  offlineBackupPrivateKeyPem: string
): Promise<{ snapshot: D1BackupSnapshot; verifiedSha256: string }> {
  const obj = await bucket.get(r2Key);
  if (!obj) throw new Error('R2_BACKUP_NOT_FOUND');
  const raw = await obj.text();
  const envelope = JSON.parse(raw) as EncryptedBackupEnvelope;
  const plaintext = await decryptBackupEnvelope(envelope, offlineBackupPrivateKeyPem);
  const actualSha = await sha256Hex(plaintext);
  if (actualSha !== envelope.plaintextSha256) {
    throw new Error('BACKUP_SHA256_VERIFICATION_FAILED');
  }
  return {
    snapshot: JSON.parse(plaintext) as D1BackupSnapshot,
    verifiedSha256: actualSha,
  };
}
