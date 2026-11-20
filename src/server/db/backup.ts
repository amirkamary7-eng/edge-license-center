import Database from 'better-sqlite3';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { openDatabase, type SqliteDb } from './connection';

export interface BackupMetadata {
  backupFile: string;
  sha256: string;
  sizeBytes: number;
  createdAt: string;
}

export function computeFileSha256(filePath: string): string {
  const hash = crypto.createHash('sha256');
  hash.update(fs.readFileSync(filePath));
  return hash.digest('hex');
}

/**
 * Performs an online, consistent SQLite WAL backup using better-sqlite3's
 * native SQLite Online Backup API and writes a companion `.sha256` manifest.
 */
export async function createDatabaseBackup(
  db: SqliteDb,
  backupDir: string,
  label = 'edge_backup'
): Promise<BackupMetadata> {
  fs.mkdirSync(backupDir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const backupFile = path.resolve(backupDir, `${label}_${stamp}.sqlite`);
  const tmpBackupFile = `${backupFile}.tmp`;
  const checksumFile = `${backupFile}.sha256`;
  const tmpChecksumFile = `${checksumFile}.tmp`;

  try {
    await db.backup(tmpBackupFile);

    // Verify the newly created backup snapshot in readonly mode BEFORE publishing it
    // (avoids mutating snapshot journal_mode or creating -wal/-shm sidecars)
    const verifyDb = new Database(tmpBackupFile, { readonly: true });
    try {
      const check = verifyDb.prepare('PRAGMA integrity_check').get() as {
        integrity_check: string;
      };
      if (check?.integrity_check !== 'ok') {
        throw new Error(`BACKUP_INTEGRITY_CHECK_FAILED: ${check?.integrity_check}`);
      }
    } finally {
      verifyDb.close();
    }

    // Remove any sidecar WAL/SHM created when opening the verified snapshot
    for (const suffix of ['-wal', '-shm']) {
      const sidecar = `${tmpBackupFile}${suffix}`;
      if (fs.existsSync(sidecar)) {
        fs.unlinkSync(sidecar);
      }
    }

    const sha256 = computeFileSha256(tmpBackupFile);
    const stats = fs.statSync(tmpBackupFile);

    fs.renameSync(tmpBackupFile, backupFile);
    fs.writeFileSync(tmpChecksumFile, `${sha256}  ${path.basename(backupFile)}\n`, 'utf8');
    fs.renameSync(tmpChecksumFile, checksumFile);

    return {
      backupFile,
      sha256,
      sizeBytes: stats.size,
      createdAt: new Date().toISOString(),
    };
  } catch (err) {
    for (const leftover of [
      tmpBackupFile,
      `${tmpBackupFile}-wal`,
      `${tmpBackupFile}-shm`,
      tmpChecksumFile,
    ]) {
      if (fs.existsSync(leftover)) {
        try {
          fs.unlinkSync(leftover);
        } catch {
          // Best-effort cleanup
        }
      }
    }
    throw err;
  }
}

/**
 * Restores a SQLite database from a verified backup file:
 * 1. Verifies companion `.sha256` checksum (if present or required).
 * 2. Runs `PRAGMA integrity_check` on the backup snapshot.
 * 3. Replaces target database file cleanly and removes stale `-wal` / `-shm` journals.
 */
export function restoreDatabaseBackup(
  backupFile: string,
  targetDbPath: string,
  options?: { expectedSha256?: string; requireChecksumFile?: boolean }
): { restoredPath: string; sha256: string; integrityOk: boolean } {
  const resolvedBackup = path.resolve(backupFile);
  const resolvedTarget = path.resolve(targetDbPath);

  if (!fs.existsSync(resolvedBackup)) {
    throw new Error('BACKUP_FILE_NOT_FOUND');
  }

  const actualSha = computeFileSha256(resolvedBackup);
  const checksumPath = `${resolvedBackup}.sha256`;

  if (options?.expectedSha256 && actualSha !== options.expectedSha256.toLowerCase()) {
    throw new Error('BACKUP_CHECKSUM_MISMATCH');
  }

  if (fs.existsSync(checksumPath)) {
    const storedLine = fs.readFileSync(checksumPath, 'utf8').trim();
    const storedHash = storedLine.split(/\s+/)[0]?.toLowerCase();
    if (!storedHash || storedHash !== actualSha) {
      throw new Error('BACKUP_CHECKSUM_MISMATCH');
    }
  } else if (options?.requireChecksumFile) {
    throw new Error('BACKUP_CHECKSUM_FILE_MISSING');
  }

  // Validate backup integrity before overwriting target
  const inspectDb = openDatabase(resolvedBackup);
  try {
    const row = inspectDb.prepare('PRAGMA integrity_check').get() as { integrity_check: string };
    if (row?.integrity_check !== 'ok') {
      throw new Error(`BACKUP_CORRUPTED: ${row?.integrity_check}`);
    }
  } finally {
    inspectDb.close();
  }

  fs.mkdirSync(path.dirname(resolvedTarget), { recursive: true });
  // Remove stale WAL/SHM files before restoring
  for (const suffix of ['-wal', '-shm']) {
    const sidecar = `${resolvedTarget}${suffix}`;
    if (fs.existsSync(sidecar)) {
      fs.unlinkSync(sidecar);
    }
  }

  const tempTarget = `${resolvedTarget}.restoring`;
  fs.copyFileSync(resolvedBackup, tempTarget);
  fs.renameSync(tempTarget, resolvedTarget);

  // Post-restore sanity check
  const restoredDb = openDatabase(resolvedTarget);
  try {
    const row = restoredDb.prepare('PRAGMA integrity_check').get() as { integrity_check: string };
    if (row?.integrity_check !== 'ok') {
      throw new Error('RESTORED_DB_INTEGRITY_FAILED');
    }
  } finally {
    restoredDb.close();
  }

  return {
    restoredPath: resolvedTarget,
    sha256: actualSha,
    integrityOk: true,
  };
}
