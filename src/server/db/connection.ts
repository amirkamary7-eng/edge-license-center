import Database from 'better-sqlite3';
import fs from 'fs';
import path from 'path';

export type SqliteDb = Database.Database;

/**
 * Opens a SQLite database with strict production pragmas:
 * - WAL journal mode for concurrent readers + atomic writer
 * - Foreign Keys strictly enforced on every connection
 * - 5-second busy_timeout to handle concurrent HTTP/Bot bursts safely
 * - FULL synchronous mode for transactional durability
 */
export function openDatabase(dbPath: string): SqliteDb {
  if (dbPath !== ':memory:') {
    const dir = path.dirname(path.resolve(dbPath));
    fs.mkdirSync(dir, { recursive: true });
  }

  const db = new Database(dbPath);
  if (dbPath !== ':memory:') {
    db.pragma('journal_mode = WAL');
  }
  db.pragma('foreign_keys = ON');
  db.pragma('busy_timeout = 5000');
  db.pragma('synchronous = FULL');
  return db;
}

/**
 * Executes a callback inside an IMMEDIATE SQLite transaction to serialize
 * concurrent write attempts (e.g. duplicate TxID submissions or device binding).
 */
export function runImmediateTransaction<T>(db: SqliteDb, fn: () => T): T {
  const tx = db.transaction(fn);
  return tx.immediate();
}
