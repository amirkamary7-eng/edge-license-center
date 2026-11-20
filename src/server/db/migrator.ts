import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import type { SqliteDb } from './connection';

export interface MigrationResult {
  applied: string[];
  skipped: string[];
  totalAvailable: number;
  verifiedChecksums: number;
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * Resolves the SQL migrations folder cleanly across both:
 * - Development / Vitest (`src/server/db/migrations`)
 * - Bundled Production (`dist-server/migrations` or cwd `src/server/db/migrations`)
 */
export function getMigrationsDir(): string {
  const candidates = [
    path.join(__dirname, 'migrations'),
    path.resolve(process.cwd(), 'dist-server', 'migrations'),
    path.resolve(process.cwd(), 'src', 'server', 'db', 'migrations'),
  ];
  for (const dir of candidates) {
    if (fs.existsSync(dir)) {
      return dir;
    }
  }
  return candidates[0];
}

export function computeMigrationChecksum(sql: string): string {
  return crypto.createHash('sha256').update(sql, 'utf8').digest('hex');
}

function ensureSchemaMigrationsTable(db: SqliteDb): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version TEXT PRIMARY KEY,
      checksum TEXT,
      applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
    );
  `);

  const columns = db.prepare(`PRAGMA table_info(schema_migrations)`).all() as Array<{ name: string }>;
  const hasChecksum = columns.some((c) => c.name === 'checksum');
  if (!hasChecksum) {
    db.exec(`ALTER TABLE schema_migrations ADD COLUMN checksum TEXT;`);
  }
}

export function runMigrations(db: SqliteDb, migrationsDir = getMigrationsDir()): MigrationResult {
  ensureSchemaMigrationsTable(db);

  const files = fs
    .readdirSync(migrationsDir)
    .filter((f) => f.endsWith('.sql'))
    .sort();

  const existingRows = db
    .prepare('SELECT version, checksum FROM schema_migrations')
    .all() as Array<{ version: string; checksum: string | null }>;
  const existingMap = new Map(existingRows.map((r) => [r.version, r.checksum]));

  const applied: string[] = [];
  const skipped: string[] = [];
  let verifiedChecksums = 0;

  for (const file of files) {
    const sql = fs.readFileSync(path.join(migrationsDir, file), 'utf8');
    const checksum = computeMigrationChecksum(sql);

    if (existingMap.has(file)) {
      const storedChecksum = existingMap.get(file);
      if (storedChecksum && storedChecksum !== checksum) {
        throw new Error(
          `MIGRATION_CHECKSUM_MISMATCH: Migration "${file}" was modified after being applied.`
        );
      }
      if (!storedChecksum) {
        db.prepare('UPDATE schema_migrations SET checksum = ? WHERE version = ?').run(
          checksum,
          file
        );
      }
      verifiedChecksums += 1;
      skipped.push(file);
      continue;
    }

    const applyOne = db.transaction(() => {
      db.exec(sql);
      db.prepare('INSERT INTO schema_migrations (version, checksum) VALUES (?, ?)').run(
        file,
        checksum
      );
    });
    applyOne.immediate();
    applied.push(file);
  }

  return {
    applied,
    skipped,
    totalAvailable: files.length,
    verifiedChecksums,
  };
}
