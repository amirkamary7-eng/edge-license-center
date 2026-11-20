import fs from 'fs';
import os from 'os';
import path from 'path';
import { describe, expect, it } from 'vitest';
import { createDatabaseBackup, restoreDatabaseBackup } from '../src/server/db/backup';
import { openDatabase } from '../src/server/db/connection';
import { runMigrations } from '../src/server/db/migrator';
import { PAYMENT_NETWORK, TELEGRAM_BOT_HANDLE } from '../src/shared/constants';
import type { PlanRecord, SystemSettingRecord } from '../src/shared/types';

describe('SQLite Schema, Checksums, Immutability Triggers & Backup/Restore (Phase 1)', () => {
  it('creates all 14 domain tables + schema_migrations and verifies SHA-256 migration checksums', () => {
    const db = openDatabase(':memory:');
    try {
      const firstRun = runMigrations(db);
      expect(firstRun.applied).toEqual([
        '001_initial_schema.sql',
        '002_seed_core_data.sql',
        '003_phase1_hardening.sql',
        '004_payment_concurrency_guards.sql',
      ]);
      expect(firstRun.skipped).toEqual([]);

      const secondRun = runMigrations(db);
      expect(secondRun.applied).toEqual([]);
      expect(secondRun.skipped).toEqual([
        '001_initial_schema.sql',
        '002_seed_core_data.sql',
        '003_phase1_hardening.sql',
        '004_payment_concurrency_guards.sql',
      ]);
      expect(secondRun.verifiedChecksums).toBe(4);

      const tables = (
        db
          .prepare(`SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'`)
          .all() as Array<{ name: string }>
      ).map((r) => r.name);

      const requiredTables = [
        'users',
        'admins',
        'plans',
        'orders',
        'payments',
        'subscriptions',
        'licenses',
        'devices',
        'audit_logs',
        'system_settings',
        'support_tickets',
        'notifications',
        'idempotency_records',
        'license_history',
        'schema_migrations',
      ];
      for (const table of requiredTables) {
        expect(tables).toContain(table);
      }
    } finally {
      db.close();
    }
  });

  it('rejects tampered historical migrations via SHA-256 checksum verification', () => {
    const db = openDatabase(':memory:');
    try {
      runMigrations(db);
      db.prepare(`UPDATE schema_migrations SET checksum = 'deadbeef' WHERE version = '001_initial_schema.sql'`).run();

      expect(() => runMigrations(db)).toThrow(/MIGRATION_CHECKSUM_MISMATCH/);
    } finally {
      db.close();
    }
  });

  it('seeds exact immutable commercial prices and enforces SQLite immutability triggers on system_settings', () => {
    const db = openDatabase(':memory:');
    try {
      runMigrations(db);
      const plans = db.prepare('SELECT * FROM plans ORDER BY sort_order ASC').all() as PlanRecord[];
      expect(plans.map((p) => [p.code, p.duration_months, p.price_usd_display, p.price_usdc_micro])).toEqual([
        ['EDGE_1M', 1, '1.99', 1_990_000],
        ['EDGE_3M', 3, '4.99', 4_990_000],
        ['EDGE_6M', 6, '8.99', 8_990_000],
        ['EDGE_12M', 12, '16.99', 16_990_000],
      ]);

      const settingsRows = db.prepare('SELECT * FROM system_settings').all() as SystemSettingRecord[];
      const map = Object.fromEntries(settingsRows.map((s) => [s.key, s.value]));
      expect(map.payment_usdc_contract).toBe(PAYMENT_NETWORK.usdcContractAddress);
      expect(map.payment_destination_wallet).toBe(PAYMENT_NETWORK.destinationWalletAddress);
      expect(map.telegram_bot_handle).toBe(TELEGRAM_BOT_HANDLE);
      expect(map.payment_network).toBe('Polygon PoS');
      expect(map.payment_token_symbol).toBe('USDC');
      expect(map.system_phase).toBe('PHASE_1_HARDENED');

      // Database-level BEFORE UPDATE trigger MUST block mutating immutable payment_destination_wallet
      expect(() =>
        db
          .prepare(`UPDATE system_settings SET value = '0x0000000000000000000000000000000000000000' WHERE key = 'payment_destination_wallet'`)
          .run()
      ).toThrow(/IMMUTABLE_SYSTEM_SETTING/);

      // Database-level BEFORE DELETE trigger MUST block deleting immutable system_settings
      expect(() =>
        db.prepare(`DELETE FROM system_settings WHERE key = 'payment_usdc_contract'`).run()
      ).toThrow(/IMMUTABLE_SYSTEM_SETTING/);

      // Mutable setting (`system_phase`) CAN be updated
      const res = db
        .prepare(`UPDATE system_settings SET value = 'PHASE_1_VERIFIED' WHERE key = 'system_phase'`)
        .run();
      expect(res.changes).toBe(1);
    } finally {
      db.close();
    }
  });

  it('enforces foreign keys and unique constraints at the SQLite engine level', () => {
    const db = openDatabase(':memory:');
    try {
      runMigrations(db);

      expect(() =>
        db
          .prepare(
            `INSERT INTO orders (
               order_code, user_id, plan_id, expected_amount_usdc_micro,
               expected_amount_usd, token_contract, destination_wallet, expires_at
             ) VALUES ('EDGE-ORPHAN', 9999, 1, 1990000, '1.99', '0x3c49', '0xf5fd', '2099-01-01T00:00:00Z')`
          )
          .run()
      ).toThrow(/FOREIGN KEY/i);

      // Verify Migration 004 enforces unique subscription per order_id at SQLite level
      db.prepare(`INSERT INTO users (telegram_id, first_name) VALUES ('444001', 'SubGuard')`).run();
      const userId = (db.prepare(`SELECT id FROM users WHERE telegram_id = '444001'`).get() as { id: number }).id;
      db.prepare(
        `INSERT INTO orders (
           order_code, user_id, plan_id, expected_amount_usdc_micro,
           expected_amount_usd, token_contract, destination_wallet, expires_at
         ) VALUES ('EDGE-UNIQ-SUB', ?, 1, 1990000, '1.99', '0x3c49', '0xf5fd', '2099-01-01T00:00:00Z')`
      ).run(userId);
      const orderId = (db.prepare(`SELECT id FROM orders WHERE order_code = 'EDGE-UNIQ-SUB'`).get() as { id: number }).id;
      db.prepare(
        `INSERT INTO subscriptions (user_id, plan_id, order_id, status, starts_at, expires_at)
         VALUES (?, 1, ?, 'active', '2026-01-01T00:00:00Z', '2026-02-01T00:00:00Z')`
      ).run(userId, orderId);
      expect(() =>
        db
          .prepare(
            `INSERT INTO subscriptions (user_id, plan_id, order_id, status, starts_at, expires_at)
             VALUES (?, 1, ?, 'active', '2026-01-01T00:00:00Z', '2026-02-01T00:00:00Z')`
          )
          .run(userId, orderId)
      ).toThrow(/UNIQUE/i);
    } finally {
      db.close();
    }
  });

  it('performs online SQLite WAL backup with SHA-256 manifest, verified restore, and rejects tampered backups', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'edge-db-backup-test-'));
    const sourcePath = path.join(tmpDir, 'source.sqlite');
    const restoredPath = path.join(tmpDir, 'restored.sqlite');
    const backupDir = path.join(tmpDir, 'backups');

    try {
      const db = openDatabase(sourcePath);
      runMigrations(db);
      db.prepare(
        `INSERT INTO users (telegram_id, username, first_name) VALUES ('888111222', 'backup_user', 'Backup')`
      ).run();

      const meta = await createDatabaseBackup(db, backupDir, 'test_snap');
      db.close();

      expect(fs.existsSync(meta.backupFile)).toBe(true);
      expect(fs.existsSync(`${meta.backupFile}.sha256`)).toBe(true);
      expect(meta.sha256).toMatch(/^[a-f0-9]{64}$/);

      // Verified restore succeeds and preserves user data
      const restored = restoreDatabaseBackup(meta.backupFile, restoredPath, {
        requireChecksumFile: true,
      });
      expect(restored.integrityOk).toBe(true);
      expect(restored.sha256).toBe(meta.sha256);

      const checkDb = openDatabase(restoredPath);
      const user = checkDb
        .prepare(`SELECT telegram_id, username FROM users WHERE telegram_id = '888111222'`)
        .get() as { telegram_id: string; username: string } | undefined;
      checkDb.close();
      expect(user?.username).toBe('backup_user');

      // Tampering with backup file causes restore checksum verification to fail
      fs.appendFileSync(meta.backupFile, 'CORRUPTED_TAIL');
      expect(() =>
        restoreDatabaseBackup(meta.backupFile, path.join(tmpDir, 'tampered.sqlite'), {
          requireChecksumFile: true,
        })
      ).toThrow(/BACKUP_CHECKSUM_MISMATCH/);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});
