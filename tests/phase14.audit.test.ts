import { spawn } from 'child_process';
import fs from 'fs';
import http from 'http';
import os from 'os';
import path from 'path';
import { afterEach, describe, expect, it } from 'vitest';
import worker, { resetWorkerRateLimiterForTests } from '../cloudflare-worker/src/index';
import { createApiApp } from '../src/server/app';
import { loadEnv } from '../src/server/config/env';
import { openDatabase } from '../src/server/db/connection';
import { runMigrations } from '../src/server/db/migrator';
import { acquireSqliteLease, releaseSqliteLease } from '../src/server/jobs/scheduler';
import { LicenseService } from '../src/server/modules/license/licenseService';
import { SupportService } from '../src/server/modules/support/supportService';
import { UserRepository } from '../src/server/modules/users/userRepository';
import { IdempotencyStore } from '../src/server/security/idempotency';
import { generateEphemeralRsaKeyPair } from '../src/server/security/rsaSigner';

function runChildScript(scriptCode: string, envVars: Record<string, string>): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['--input-type=module', '-e', scriptCode], {
      cwd: process.cwd(),
      env: { ...process.env, ...envVars },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => {
      stdout += String(chunk);
    });
    child.stderr.on('data', (chunk) => {
      stderr += String(chunk);
    });
    child.on('close', (code) => {
      resolve({ code: code ?? -1, stdout, stderr });
    });
  });
}

describe('Phase 1.4 Independent Audit — Multi-Process SQLite Leases, Non-Owner Protection & Full Worker-to-Backend Valid License E2E', () => {
  const cleanups: Array<() => Promise<void> | void> = [];

  afterEach(async () => {
    while (cleanups.length > 0) {
      const fn = cleanups.pop()!;
      await fn();
    }
    resetWorkerRateLimiterForTests();
  });

  it('enforces non-owner lease protection, automatic stale-lock crash recovery, and zero interference with API idempotency records', () => {
    const db = openDatabase(':memory:');
    runMigrations(db);
    cleanups.push(() => {
      db.close();
    });

    // 1. Seed a normal API idempotency record to prove leases never collide or delete it
    const idem = new IdempotencyStore(db);
    idem.saveResponse({
      scope: 'create_order',
      key: 'idem-order-key-001',
      actorId: '99112233',
      requestHash: 'abc123',
      status: 201,
      body: { orderCode: 'EDGE-TEST-1' },
      ttlSeconds: 3600,
    });

    // 2. Owner A acquires lease; Owner B cannot acquire and CANNOT prematurely release Owner A's lease
    expect(acquireSqliteLease(db, 'scheduler_job_lock', 'notifications', 'owner_A', 60)).toBe(true);
    expect(acquireSqliteLease(db, 'scheduler_job_lock', 'notifications', 'owner_B', 60)).toBe(false);

    releaseSqliteLease(db, 'scheduler_job_lock', 'notifications', 'owner_B');
    // Still locked by owner_A!
    expect(acquireSqliteLease(db, 'scheduler_job_lock', 'notifications', 'owner_B', 60)).toBe(false);

    // 3. Simulate crashed process (owner_A dies without calling release; lease timestamp expires)
    db.prepare(
      `UPDATE idempotency_records
       SET expires_at = '2020-01-01T00:00:00.000Z'
       WHERE scope = 'scheduler_job_lock' AND idempotency_key = 'notifications'`
    ).run();

    // Owner B automatically reclaims the stale lock without manual intervention
    expect(acquireSqliteLease(db, 'scheduler_job_lock', 'notifications', 'owner_B', 60)).toBe(true);

    // Late release by crashed owner_A must NOT delete owner_B's newly acquired lease
    releaseSqliteLease(db, 'scheduler_job_lock', 'notifications', 'owner_A');
    expect(acquireSqliteLease(db, 'scheduler_job_lock', 'notifications', 'owner_C', 60)).toBe(false);

    // Clean release by owner_B frees the lock
    releaseSqliteLease(db, 'scheduler_job_lock', 'notifications', 'owner_B');
    expect(acquireSqliteLease(db, 'scheduler_job_lock', 'notifications', 'owner_C', 60)).toBe(true);

    // 4. Verify existing API idempotency record is 100% untouched
    const cached = idem.findResponse({
      scope: 'create_order',
      key: 'idem-order-key-001',
      actorId: '99112233',
      requestHash: 'abc123',
    });
    expect(cached).toEqual({ status: 201, body: { orderCode: 'EDGE-TEST-1' } });
  });

  it('serializes lease acquisition across two genuinely independent OS Node.js processes on the same WAL SQLite file (zero duplicate claims)', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'edge-p14-multiproc-'));
    const dbPath = path.join(tmpDir, 'shared_wal.sqlite');
    cleanups.push(() => {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    const db = openDatabase(dbPath);
    runMigrations(db);
    const users = new UserRepository(db);
    const user = users.upsertFromTelegram({
      telegramId: '77998811',
      firstName: 'MultiProcUser',
    });
    const support = new SupportService(db);
    const note = support.queueNotification({
      userId: user.id,
      channel: 'telegram_bot',
      type: 'LICENSE_ISSUED',
      title: 'Multi-Process Test',
      body: 'Only one OS process may claim and mark sent',
    });
    db.close();

    // Child script executes the exact BEGIN IMMEDIATE lease + re-check + mark-sent protocol
    const childCode = `
      import Database from 'better-sqlite3';
      const db = new Database(process.env.TEST_DB_PATH);
      db.pragma('journal_mode = WAL');
      db.pragma('foreign_keys = ON');
      db.pragma('busy_timeout = 5000');

      const workerId = process.env.WORKER_ID;
      const notifId = Number(process.env.NOTIF_ID);
      const leaseKey = 'notif_' + notifId;
      const nowMs = Date.now();
      const nowIso = new Date(nowMs).toISOString();
      const expiresAtIso = new Date(nowMs + 60000).toISOString();

      const acquire = db.transaction(() => {
        db.prepare("DELETE FROM idempotency_records WHERE scope = 'notification_dispatch_lock' AND idempotency_key = ? AND expires_at <= ?").run(leaseKey, nowIso);
        const r = db.prepare("INSERT OR IGNORE INTO idempotency_records (scope, idempotency_key, actor_id, request_hash, response_status, response_body_json, expires_at) VALUES ('notification_dispatch_lock', ?, ?, 'lease', 200, '{}', ?)").run(leaseKey, workerId, expiresAtIso);
        return r.changes === 1;
      });

      const acquired = acquire.immediate();
      let delivered = false;
      if (acquired) {
        try {
          const fresh = db.prepare('SELECT status FROM notifications WHERE id = ?').get(notifId);
          if (fresh && fresh.status === 'pending') {
            await new Promise((r) => setTimeout(r, 80));
            db.prepare("UPDATE notifications SET status = 'sent', attempts = attempts + 1, sent_at = ? WHERE id = ?").run(new Date().toISOString(), notifId);
            delivered = true;
          }
        } finally {
          db.prepare("DELETE FROM idempotency_records WHERE scope = 'notification_dispatch_lock' AND idempotency_key = ? AND actor_id = ?").run(leaseKey, workerId);
        }
      }
      db.close();
      console.log(JSON.stringify({ workerId, acquired, delivered }));
    `;

    const [p1, p2] = await Promise.all([
      runChildScript(childCode, {
        TEST_DB_PATH: dbPath,
        WORKER_ID: 'os_proc_1',
        NOTIF_ID: String(note.id),
      }),
      runChildScript(childCode, {
        TEST_DB_PATH: dbPath,
        WORKER_ID: 'os_proc_2',
        NOTIF_ID: String(note.id),
      }),
    ]);

    expect(p1.code).toBe(0);
    expect(p2.code).toBe(0);

    const r1 = JSON.parse(p1.stdout.trim()) as { acquired: boolean; delivered: boolean };
    const r2 = JSON.parse(p2.stdout.trim()) as { acquired: boolean; delivered: boolean };

    // Strictly ONE independent OS process may deliver the notification
    expect(Number(r1.delivered) + Number(r2.delivered)).toBe(1);

    const verifyDb = openDatabase(dbPath);
    try {
      const row = verifyDb
        .prepare('SELECT status, attempts FROM notifications WHERE id = ?')
        .get(note.id) as { status: string; attempts: number };
      expect(row.status).toBe('sent');
      expect(row.attempts).toBe(1);
    } finally {
      verifyDb.close();
    }
  });

  it('validates full Android -> Cloudflare Worker -> HMAC-SHA256 -> Backend Gateway -> RSA License path and persists across server restart', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'edge-p14-e2e-'));
    const dbPath = path.join(tmpDir, 'persistent.sqlite');
    cleanups.push(() => {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    const { privateKeyPem, publicKeyPem } = generateEphemeralRsaKeyPair();
    const gatewaySecret = 'staging-e2e-gateway-secret-0123456789';
    const superAdminTgId = '99887766';

    const bootServer = async () => {
      const db = openDatabase(dbPath);
      runMigrations(db);
      const env = loadEnv({
        NODE_ENV: 'test',
        PAYMENT_VERIFICATION_MODE: 'DRY_RUN',
        LICENSE_ISSUANCE_MODE: 'LIVE',
        TELEGRAM_BOT_SEND_ENABLED: 'false',
        GATEWAY_SHARED_SECRET: gatewaySecret,
        RSA_PRIVATE_KEY_PEM: privateKeyPem,
        RSA_PUBLIC_KEY_PEM: publicKeyPem,
        RSA_KEY_ID: 'staging-e2e-rsa-v1',
        BOOTSTRAP_SUPER_ADMIN_TELEGRAM_ID: superAdminTgId,
        RATE_LIMIT_ENABLED: 'false',
      });
      const app = createApiApp({ db, env });
      const server = http.createServer(app);
      await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
      const addr = server.address();
      if (!addr || typeof addr === 'string') throw new Error('Bind failed');
      return {
        db,
        baseUrl: `http://127.0.0.1:${addr.port}`,
        close: async () => {
          await new Promise<void>((resolve) => server.close(() => resolve()));
          db.close();
        },
      };
    };

    // Boot #1: Verify super_admin bootstrap + issue active RSA license + validate via Cloudflare Worker
    const srv1 = await bootServer();
    const users = new UserRepository(srv1.db);
    const bootstrappedAdmin = users.findActiveAdminByTelegramId(superAdminTgId);
    expect(bootstrappedAdmin?.role).toBe('super_admin');

    const buyer = users.upsertFromTelegram({
      telegramId: '66554433',
      firstName: 'AndroidBuyer',
    });
    const licSvc = new LicenseService(srv1.db, {
      issuanceMode: 'LIVE',
      rsaPrivateKeyPem: privateKeyPem,
      rsaPublicKeyPem: publicKeyPem,
      rsaKeyId: 'staging-e2e-rsa-v1',
    });
    const issued = licSvc.issueForSubscription({
      userId: buyer.id,
      telegramId: buyer.telegram_id,
      planId: 1,
      planCode: 'EDGE_1M',
      durationDays: 30,
      maxDevices: 1,
      actorId: 'staging_e2e_test',
      requireConfirmedPayment: false,
    });

    const workerEnv = {
      ORIGIN_API_URL: srv1.baseUrl,
      GATEWAY_SHARED_SECRET: gatewaySecret,
      GATEWAY_PHASE: 'PHASE_1_STAGING_DRY_RUN',
      RATE_LIMIT_MAX_PER_MIN: '60',
    };

    const reqBody = JSON.stringify({
      licenseKey: issued.license.license_key,
      deviceFingerprint: 'android-pixel9-fp-e2e-001',
      deviceModel: 'Pixel 9 Pro',
      androidVersion: '15',
      appVersion: '2.1.0',
    });

    const res1 = await worker.fetch(
      new Request('https://gateway-staging.edge.example/v1/license/validate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '203.0.113.50' },
        body: reqBody,
      }),
      workerEnv
    );
    expect(res1.status).toBe(200);
    const json1 = (await res1.json()) as {
      valid: boolean;
      signatureValid: boolean;
      licenseStatus: string;
    };
    expect(json1.valid).toBe(true);
    expect(json1.signatureValid).toBe(true);
    expect(json1.licenseStatus).toBe('active');

    // Shut down server #1 cleanly (simulating container/VPS restart)
    await srv1.close();

    // Boot #2 against same persistent SQLite DB -> verify restart recovery & idempotent super_admin bootstrap
    const srv2 = await bootServer();
    cleanups.push(srv2.close);

    const adminCount = srv2.db
      .prepare(`SELECT COUNT(*) AS cnt FROM admins WHERE telegram_id = ?`)
      .get(superAdminTgId) as { cnt: number };
    expect(adminCount.cnt).toBe(1);

    const res2 = await worker.fetch(
      new Request('https://gateway-staging.edge.example/v1/license/validate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '203.0.113.50' },
        body: reqBody,
      }),
      { ...workerEnv, ORIGIN_API_URL: srv2.baseUrl }
    );
    expect(res2.status).toBe(200);
    const json2 = (await res2.json()) as { valid: boolean; signatureValid: boolean };
    expect(json2.valid).toBe(true);
    expect(json2.signatureValid).toBe(true);
  });

  it('releases scheduler SQLite lease immediately when a job throws an exception mid-execution', async () => {
    const db = openDatabase(':memory:');
    runMigrations(db);
    cleanups.push(() => {
      db.close();
    });

    const users = new UserRepository(db);
    const user = users.upsertFromTelegram({
      telegramId: '88776655',
      firstName: 'ExceptionTestUser',
    });
    const support = new SupportService(db);
    support.queueNotification({
      userId: user.id,
      channel: 'telegram_bot',
      type: 'LICENSE_ISSUED',
      title: 'Exception Recovery',
      body: 'Lease must release on unexpected exception',
    });

    // Inject a Backup path that cannot be created (file-as-dir) to force an exception inside BackgroundScheduler.runBackupOnce
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'edge-p14-exc-'));
    const blockingFile = path.join(tmpDir, 'not_a_dir');
    fs.writeFileSync(blockingFile, 'block', 'utf8');
    cleanups.push(() => {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    const { BackgroundScheduler } = await import('../src/server/jobs/scheduler');
    const { PaymentService } = await import('../src/server/modules/payment/paymentService');
    const paymentService = new PaymentService(db, { verificationMode: 'DRY_RUN' });

    const scheduler = new BackgroundScheduler({
      db,
      paymentService,
      verificationMode: 'DRY_RUN',
      telegramBotSendEnabled: false,
      backupDir: blockingFile,
    });

    await expect(scheduler.runBackupOnce()).rejects.toThrow();

    // Verify scheduler_job_lock for 'backup' was cleanly released in finally (immediate re-acquisition succeeds)
    expect(acquireSqliteLease(db, 'scheduler_job_lock', 'backup', 'next_worker_after_exc', 60)).toBe(
      true
    );
    releaseSqliteLease(db, 'scheduler_job_lock', 'backup', 'next_worker_after_exc');
  });

  it('verifies deploy/backup-to-r2.sh uploads ONLY the verified snapshot+sha256, excludes unverified files, and fails closed on upload error', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'edge-p14-r2test-'));
    const dbPath = path.join(tmpDir, 'staging.sqlite');
    const backupDir = path.join(tmpDir, 'backups');
    const stubBin = path.join(tmpDir, 'bin');
    const rcloneLog = path.join(tmpDir, 'rclone_calls.log');
    fs.mkdirSync(backupDir, { recursive: true });
    fs.mkdirSync(stubBin, { recursive: true });
    cleanups.push(() => {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    const db = openDatabase(dbPath);
    runMigrations(db);
    db.close();

    // Plant an unverified decoy .sqlite file (no checksum) in backupDir BEFORE running backup-to-r2.sh
    const decoyFile = path.join(backupDir, 'incomplete_unverified_decoy.sqlite');
    fs.writeFileSync(decoyFile, 'CORRUPT_INCOMPLETE_DATA', 'utf8');
    // Set decoy mtime slightly in the past so the newly created verified snapshot is newest
    const past = new Date(Date.now() - 60_000);
    fs.utimesSync(decoyFile, past, past);

    // Create mock rclone executable that logs exact args and supports forced failure via MOCK_RCLONE_FAIL=1
    const rcloneStub = path.join(stubBin, 'rclone');
    fs.writeFileSync(
      rcloneStub,
      `#!/usr/bin/env bash
echo "$*" >> "${rcloneLog}"
if [[ "\${MOCK_RCLONE_FAIL:-0}" == "1" ]]; then
  echo "simulated network failure" >&2
  exit 1
fi
exit 0
`,
      { mode: 0o755 }
    );

    const runBackupScript = (extraEnv: Record<string, string>) =>
      new Promise<{ code: number; stdout: string; stderr: string }>((resolve) => {
        const child = spawn('bash', ['deploy/backup-to-r2.sh'], {
          cwd: process.cwd(),
          env: {
            ...process.env,
            PATH: `${stubBin}:${process.env.PATH ?? ''}`,
            APP_DIR: process.cwd(),
            SQLITE_DB_PATH: dbPath,
            SQLITE_BACKUP_DIR: backupDir,
            R2_REMOTE: 'r2:edge-staging-bucket/backups',
            ...extraEnv,
          },
          stdio: ['ignore', 'pipe', 'pipe'],
        });
        let stdout = '';
        let stderr = '';
        child.stdout.on('data', (c) => {
          stdout += String(c);
        });
        child.stderr.on('data', (c) => {
          stderr += String(c);
        });
        child.on('close', (code) => resolve({ code: code ?? -1, stdout, stderr }));
      });

    // 1. Successful verified upload: ONLY the new verified .sqlite and .sqlite.sha256 uploaded; decoy excluded
    const okRun = await runBackupScript({ MOCK_RCLONE_FAIL: '0' });
    expect(okRun.code).toBe(0);
    expect(okRun.stdout).toContain(': OK');
    const calls = fs.readFileSync(rcloneLog, 'utf8').trim().split('\n');
    expect(calls.length).toBe(2);
    expect(calls[0]).toContain('copyto ');
    expect(calls[0]).toContain('.sqlite ');
    expect(calls[1]).toContain('.sqlite.sha256 ');
    expect(calls.join('\n')).not.toContain('incomplete_unverified_decoy.sqlite');

    // 2. Upload error: script must fail closed with non-zero exit code
    const failRun = await runBackupScript({ MOCK_RCLONE_FAIL: '1' });
    expect(failRun.code).not.toBe(0);
    expect(failRun.stdout).not.toContain('Off-site Cloudflare R2 verified upload complete.');
  });
});
