import fs from 'fs';
import path from 'path';
import type { TelegramBotTransport } from '../bot/telegramClient';
import { createDatabaseBackup, type BackupMetadata } from '../db/backup';
import { runImmediateTransaction, type SqliteDb } from '../db/connection';
import { AuditService } from '../modules/audit/auditService';
import type { PaymentService } from '../modules/payment/paymentService';
import { SupportService } from '../modules/support/supportService';

export interface PaymentPollerTickResult {
  skipped: boolean;
  reason?: string;
  checked: number;
  confirmed: number;
  pending: number;
  failed: number;
  errors: number;
}

export interface MaintenanceTickResult {
  expiredOrders: number;
  purgedIdempotencyRecords: number;
  expiredSubscriptions: number;
  expiredLicenses: number;
  renewalRemindersQueued: number;
}

export interface NotificationDispatcherTickResult {
  skipped: boolean;
  reason?: string;
  pendingCount: number;
  sent: number;
  retried: number;
  failed: number;
  skippedLocked: number;
}

export interface ScheduledBackupTickResult {
  backup: BackupMetadata;
  prunedFiles: string[];
}

export interface BackgroundSchedulerOptions {
  db: SqliteDb;
  paymentService: PaymentService;
  verificationMode: 'DRY_RUN' | 'LIVE';
  telegramBotSendEnabled: boolean;
  botClient?: TelegramBotTransport;
  backupDir: string;
  backupRetentionCount?: number;
  paymentPollIntervalMs?: number;
  notificationPollIntervalMs?: number;
  maintenanceIntervalMs?: number;
  backupIntervalMs?: number;
  paymentBatchSize?: number;
  notificationBatchSize?: number;
  maxNotificationAttempts?: number;
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

/**
 * Acquires a cross-process SQLite lease inside an IMMEDIATE transaction using
 * `idempotency_records`. Expired leases are purged first so crashed workers
 * self-heal automatically after `ttlSeconds`.
 */
export function acquireSqliteLease(
  db: SqliteDb,
  scope: string,
  leaseKey: string,
  ownerId: string,
  ttlSeconds = 60
): boolean {
  const nowMs = Date.now();
  const nowIso = new Date(nowMs).toISOString();
  const expiresAtIso = new Date(nowMs + ttlSeconds * 1000).toISOString();

  return runImmediateTransaction(db, () => {
    db.prepare(
      `DELETE FROM idempotency_records
       WHERE scope = ? AND idempotency_key = ? AND expires_at <= ?`
    ).run(scope, leaseKey, nowIso);

    const res = db
      .prepare(
        `INSERT OR IGNORE INTO idempotency_records (
           scope, idempotency_key, actor_id, request_hash, response_status, response_body_json, expires_at
         ) VALUES (?, ?, ?, 'lease', 200, '{}', ?)`
      )
      .run(scope, leaseKey, ownerId, expiresAtIso);

    return res.changes === 1;
  });
}

export function releaseSqliteLease(
  db: SqliteDb,
  scope: string,
  leaseKey: string,
  ownerId: string
): void {
  db.prepare(
    `DELETE FROM idempotency_records
     WHERE scope = ? AND idempotency_key = ? AND actor_id = ?`
  ).run(scope, leaseKey, ownerId);
}

/**
 * Polls submitted (or stale verifying > 90s) Polygon payments and runs full
 * on-chain verification. Strictly no-ops in DRY_RUN mode so external RPC is
 * never contacted unless explicitly running in LIVE mode (or Staging test harness).
 */
export async function runPaymentPollerTick(params: {
  db: SqliteDb;
  paymentService: PaymentService;
  verificationMode: 'DRY_RUN' | 'LIVE';
  batchSize?: number;
}): Promise<PaymentPollerTickResult> {
  if (params.verificationMode !== 'LIVE') {
    return {
      skipped: true,
      reason: 'DRY_RUN_MODE',
      checked: 0,
      confirmed: 0,
      pending: 0,
      failed: 0,
      errors: 0,
    };
  }

  const audit = new AuditService(params.db);
  const batchSize = params.batchSize ?? 20;
  const staleCutoffIso = new Date(Date.now() - 90_000).toISOString();

  const candidates = params.db
    .prepare(
      `SELECT id FROM payments
       WHERE status = 'submitted'
          OR (status = 'verifying' AND updated_at <= ?)
       ORDER BY id ASC
       LIMIT ?`
    )
    .all(staleCutoffIso, batchSize) as Array<{ id: number }>;

  let confirmed = 0;
  let pending = 0;
  let failed = 0;
  let errors = 0;

  for (const row of candidates) {
    try {
      const outcome = await params.paymentService.verifyPaymentOnChain(row.id, {
        actorId: 'background_poller',
      });
      if (outcome.payment.status === 'confirmed') {
        confirmed += 1;
      } else if (outcome.payment.status === 'failed') {
        failed += 1;
      } else {
        pending += 1;
      }
    } catch (err) {
      errors += 1;
      audit.record({
        actorType: 'system',
        actorId: 'background_poller',
        action: 'PAYMENT_POLLER_ERROR',
        entityType: 'payment',
        entityId: String(row.id),
        severity: 'warning',
        metadata: {
          reason: err instanceof Error ? err.message.slice(0, 180) : 'UNKNOWN_ERROR',
        },
      });
    }
  }

  return {
    skipped: false,
    checked: candidates.length,
    confirmed,
    pending,
    failed,
    errors,
  };
}

/**
 * Runs deterministic SQLite maintenance tasks:
 * 1. Expires overdue open orders.
 * 2. Purges expired idempotency / anti-replay rows.
 * 3. Transitions past-due active subscriptions & licenses to `expired` with license_history records.
 * 4. Queues one-time 3-day pre-expiry renewal reminders into `notifications`.
 */
export function runMaintenanceTick(params: {
  db: SqliteDb;
  paymentService: PaymentService;
  nowIso?: string;
  renewalReminderLeadDays?: number;
}): MaintenanceTickResult {
  const nowIso = params.nowIso ?? new Date().toISOString();
  const leadDays = params.renewalReminderLeadDays ?? 3;
  const reminderCutoffIso = new Date(
    new Date(nowIso).getTime() + leadDays * 24 * 60 * 60 * 1000
  ).toISOString();
  const support = new SupportService(params.db);
  const audit = new AuditService(params.db);

  return runImmediateTransaction(params.db, () => {
    const expiredOrders = params.paymentService.expireStaleOrders(nowIso);

    const purgedIdempotencyRecords = params.db
      .prepare('DELETE FROM idempotency_records WHERE expires_at <= ?')
      .run(nowIso).changes;

    const expiredSubscriptions = params.db
      .prepare(
        `UPDATE subscriptions
         SET status = 'expired', updated_at = ?
         WHERE status = 'active' AND expires_at <= ?`
      )
      .run(nowIso, nowIso).changes;

    const expiringLicenses = params.db
      .prepare(
        `SELECT id, license_key FROM licenses
         WHERE status = 'active' AND expires_at <= ?`
      )
      .all(nowIso) as Array<{ id: number; license_key: string }>;

    for (const lic of expiringLicenses) {
      params.db
        .prepare(
          `UPDATE licenses
           SET status = 'expired', updated_at = ?
           WHERE id = ?`
        )
        .run(nowIso, lic.id);

      params.db
        .prepare(
          `INSERT INTO license_history (license_id, action, previous_status, new_status, actor_type, actor_id, reason)
           VALUES (?, 'EXPIRED_AUTO', 'active', 'expired', 'system', 'maintenance_scheduler', 'Subscription period elapsed')`
        )
        .run(lic.id);
    }

    const soonExpiringSubs = params.db
      .prepare(
        `SELECT s.id, s.user_id, s.expires_at, p.name_fa AS plan_name_fa
         FROM subscriptions s
         JOIN plans p ON p.id = s.plan_id
         WHERE s.status = 'active'
           AND s.auto_renew_reminded = 0
           AND s.expires_at > ?
           AND s.expires_at <= ?`
      )
      .all(nowIso, reminderCutoffIso) as Array<{
      id: number;
      user_id: number;
      expires_at: string;
      plan_name_fa: string;
    }>;

    for (const sub of soonExpiringSubs) {
      params.db
        .prepare(
          `UPDATE subscriptions
           SET auto_renew_reminded = 1, updated_at = ?
           WHERE id = ?`
        )
        .run(nowIso, sub.id);

      support.queueNotification({
        userId: sub.user_id,
        channel: 'telegram_bot',
        type: 'SUBSCRIPTION_EXPIRY_REMINDER',
        title: 'یادآوری تمدید اشتراک EDGE',
        body: `اشتراک ${sub.plan_name_fa} شما در تاریخ ${sub.expires_at.slice(0, 10)} منقضی می‌شود. برای تمدید بدون قطعی از دستور /renew یا Mini App اقدام کنید.`,
      });
    }

    if (
      expiredOrders > 0 ||
      expiredSubscriptions > 0 ||
      expiringLicenses.length > 0 ||
      soonExpiringSubs.length > 0
    ) {
      audit.record({
        actorType: 'system',
        actorId: 'maintenance_scheduler',
        action: 'MAINTENANCE_TICK_COMPLETED',
        entityType: 'system',
        metadata: {
          expiredOrders,
          purgedIdempotencyRecords,
          expiredSubscriptions,
          expiredLicenses: expiringLicenses.length,
          renewalRemindersQueued: soonExpiringSubs.length,
        },
      });
    }

    return {
      expiredOrders,
      purgedIdempotencyRecords,
      expiredSubscriptions,
      expiredLicenses: expiringLicenses.length,
      renewalRemindersQueued: soonExpiringSubs.length,
    };
  });
}

/**
 * Dispatches queued `telegram_bot` notifications via TelegramBotApiClient.
 * Respects `TELEGRAM_BOT_SEND_ENABLED=false` strictly and acquires an atomic
 * cross-process SQLite lease per notification row so concurrent schedulers
 * can NEVER send duplicate Telegram messages.
 */
export async function runNotificationDispatcherTick(params: {
  db: SqliteDb;
  telegramBotSendEnabled: boolean;
  botClient?: TelegramBotTransport;
  batchSize?: number;
  maxAttempts?: number;
  workerId?: string;
}): Promise<NotificationDispatcherTickResult> {
  const batchSize = params.batchSize ?? 25;
  const maxAttempts = params.maxAttempts ?? 5;
  const workerId = params.workerId ?? `notif_worker_${process.pid}_${Math.random().toString(36).slice(2, 8)}`;

  const pendingRows = params.db
    .prepare(
      `SELECT n.id, n.user_id, n.title, n.body, n.attempts, u.telegram_id, u.status AS user_status
       FROM notifications n
       JOIN users u ON u.id = n.user_id
       WHERE n.channel = 'telegram_bot'
         AND n.status = 'pending'
         AND n.attempts < ?
       ORDER BY n.id ASC
       LIMIT ?`
    )
    .all(maxAttempts, batchSize) as Array<{
    id: number;
    user_id: number;
    title: string;
    body: string;
    attempts: number;
    telegram_id: string;
    user_status: string;
  }>;

  if (!params.telegramBotSendEnabled) {
    return {
      skipped: true,
      reason: 'TELEGRAM_BOT_SEND_DISABLED',
      pendingCount: pendingRows.length,
      sent: 0,
      retried: 0,
      failed: 0,
      skippedLocked: 0,
    };
  }

  if (!params.botClient) {
    return {
      skipped: true,
      reason: 'TELEGRAM_BOT_CLIENT_NOT_CONFIGURED',
      pendingCount: pendingRows.length,
      sent: 0,
      retried: 0,
      failed: 0,
      skippedLocked: 0,
    };
  }

  let sent = 0;
  let retried = 0;
  let failed = 0;
  let skippedLocked = 0;

  for (const row of pendingRows) {
    const leaseKey = `notif_${row.id}`;
    const leaseAcquired = acquireSqliteLease(
      params.db,
      'notification_dispatch_lock',
      leaseKey,
      workerId,
      60
    );
    if (!leaseAcquired) {
      skippedLocked += 1;
      continue;
    }

    try {
      // Re-verify row is still pending after acquiring the cross-process lock
      const fresh = params.db
        .prepare('SELECT status, attempts FROM notifications WHERE id = ?')
        .get(row.id) as { status: string; attempts: number } | undefined;
      if (!fresh || fresh.status !== 'pending' || fresh.attempts >= maxAttempts) {
        skippedLocked += 1;
        continue;
      }

      const chatId = Number(row.telegram_id);
      const nowIso = new Date().toISOString();

      if (!Number.isSafeInteger(chatId) || chatId <= 0 || row.user_status !== 'active') {
        params.db
          .prepare(
            `UPDATE notifications
             SET status = 'failed', attempts = attempts + 1, last_error = ?
             WHERE id = ?`
          )
          .run(
            row.user_status !== 'active' ? `USER_${row.user_status.toUpperCase()}` : 'INVALID_TELEGRAM_CHAT_ID',
            row.id
          );
        failed += 1;
        continue;
      }

      try {
        await params.botClient.sendMessage({
          chatId,
          parseMode: 'HTML',
          text: `<b>${escapeHtml(row.title)}</b>\n\n${escapeHtml(row.body)}`,
        });

        params.db
          .prepare(
            `UPDATE notifications
             SET status = 'sent', attempts = attempts + 1, sent_at = ?, last_error = NULL
             WHERE id = ?`
          )
          .run(nowIso, row.id);
        sent += 1;
      } catch (err) {
        const nextAttempts = fresh.attempts + 1;
        const nextStatus = nextAttempts >= maxAttempts ? 'failed' : 'pending';
        const sanitizedError =
          err instanceof Error ? err.message.slice(0, 180) : 'TELEGRAM_SEND_ERROR';

        params.db
          .prepare(
            `UPDATE notifications
             SET status = ?, attempts = ?, last_error = ?
             WHERE id = ?`
          )
          .run(nextStatus, nextAttempts, sanitizedError, row.id);

        if (nextStatus === 'failed') {
          failed += 1;
        } else {
          retried += 1;
        }
      }
    } finally {
      releaseSqliteLease(params.db, 'notification_dispatch_lock', leaseKey, workerId);
    }
  }

  return {
    skipped: false,
    pendingCount: pendingRows.length,
    sent,
    retried,
    failed,
    skippedLocked,
  };
}

/**
 * Executes an online SQLite WAL backup with PRAGMA integrity_check + `.sha256` manifest,
 * then safely prunes older backup snapshots beyond `maxRetained`.
 */
export async function runScheduledBackupTick(params: {
  db: SqliteDb;
  backupDir: string;
  label?: string;
  maxRetained?: number;
}): Promise<ScheduledBackupTickResult> {
  const label = params.label ?? 'edge_scheduled';
  const maxRetained = Math.max(1, params.maxRetained ?? 14);
  const backup = await createDatabaseBackup(params.db, params.backupDir, label);

  const resolvedDir = path.resolve(params.backupDir);
  const files = fs
    .readdirSync(resolvedDir)
    .filter((name) => name.startsWith(`${label}_`) && name.endsWith('.sqlite'))
    .map((name) => {
      const fullPath = path.join(resolvedDir, name);
      return { name, fullPath, mtimeMs: fs.statSync(fullPath).mtimeMs };
    })
    .sort((a, b) => b.mtimeMs - a.mtimeMs);

  const prunedFiles: string[] = [];
  for (const stale of files.slice(maxRetained)) {
    if (path.resolve(stale.fullPath) === path.resolve(backup.backupFile)) {
      continue;
    }
    fs.unlinkSync(stale.fullPath);
    const shaFile = `${stale.fullPath}.sha256`;
    if (fs.existsSync(shaFile)) {
      fs.unlinkSync(shaFile);
    }
    prunedFiles.push(stale.name);
  }

  const audit = new AuditService(params.db);
  audit.record({
    actorType: 'system',
    actorId: 'backup_scheduler',
    action: 'SCHEDULED_BACKUP_CREATED',
    entityType: 'backup',
    entityId: path.basename(backup.backupFile),
    metadata: {
      sizeBytes: backup.sizeBytes,
      sha256Prefix: backup.sha256.slice(0, 16),
      prunedCount: prunedFiles.length,
    },
  });

  return { backup, prunedFiles };
}

/**
 * Overlap-safe & cross-process-locked background scheduler managing payment polling,
 * maintenance, Telegram notification dispatch, and verified SQLite WAL backups.
 */
export class BackgroundScheduler {
  private readonly timers: NodeJS.Timeout[] = [];
  private readonly runningJobs = new Set<string>();
  private readonly workerId = `sched_${process.pid}_${Math.random().toString(36).slice(2, 8)}`;
  private started = false;

  constructor(private readonly options: BackgroundSchedulerOptions) {}

  private async runGuarded<T>(jobName: string, task: () => Promise<T>): Promise<T | null> {
    if (this.runningJobs.has(jobName)) {
      return null;
    }
    const leaseAcquired = acquireSqliteLease(
      this.options.db,
      'scheduler_job_lock',
      jobName,
      this.workerId,
      120
    );
    if (!leaseAcquired) {
      return null;
    }
    this.runningJobs.add(jobName);
    try {
      return await task();
    } finally {
      this.runningJobs.delete(jobName);
      releaseSqliteLease(this.options.db, 'scheduler_job_lock', jobName, this.workerId);
    }
  }

  async runPaymentPollOnce(): Promise<PaymentPollerTickResult | null> {
    return this.runGuarded('payment_poller', () =>
      runPaymentPollerTick({
        db: this.options.db,
        paymentService: this.options.paymentService,
        verificationMode: this.options.verificationMode,
        batchSize: this.options.paymentBatchSize,
      })
    );
  }

  async runMaintenanceOnce(nowIso?: string): Promise<MaintenanceTickResult | null> {
    return this.runGuarded('maintenance', async () =>
      runMaintenanceTick({
        db: this.options.db,
        paymentService: this.options.paymentService,
        nowIso,
      })
    );
  }

  async runNotificationsOnce(): Promise<NotificationDispatcherTickResult | null> {
    return this.runGuarded('notifications', () =>
      runNotificationDispatcherTick({
        db: this.options.db,
        telegramBotSendEnabled: this.options.telegramBotSendEnabled,
        botClient: this.options.botClient,
        batchSize: this.options.notificationBatchSize,
        maxAttempts: this.options.maxNotificationAttempts,
        workerId: this.workerId,
      })
    );
  }

  async runBackupOnce(): Promise<ScheduledBackupTickResult | null> {
    return this.runGuarded('backup', () =>
      runScheduledBackupTick({
        db: this.options.db,
        backupDir: this.options.backupDir,
        maxRetained: this.options.backupRetentionCount ?? 14,
      })
    );
  }

  async runAllOnce(options?: { includeBackup?: boolean; nowIso?: string }) {
    const maintenance = await this.runMaintenanceOnce(options?.nowIso);
    const payments = await this.runPaymentPollOnce();
    const notifications = await this.runNotificationsOnce();
    const backup = options?.includeBackup ? await this.runBackupOnce() : null;
    return { maintenance, payments, notifications, backup };
  }

  start(): void {
    if (this.started) return;
    this.started = true;

    const schedule = (intervalMs: number, fn: () => Promise<unknown>) => {
      const handle = setInterval(() => {
        void fn().catch((err) => {
          console.error(
            JSON.stringify({
              event: 'scheduler_tick_error',
              error: err instanceof Error ? err.message : String(err),
            })
          );
        });
      }, intervalMs);
      handle.unref();
      this.timers.push(handle);
    };

    schedule(this.options.maintenanceIntervalMs ?? 60_000, () => this.runMaintenanceOnce());
    schedule(this.options.paymentPollIntervalMs ?? 30_000, () => this.runPaymentPollOnce());
    schedule(this.options.notificationPollIntervalMs ?? 15_000, () => this.runNotificationsOnce());
    schedule(this.options.backupIntervalMs ?? 21_600_000, () => this.runBackupOnce());
  }

  stop(): void {
    for (const handle of this.timers) {
      clearInterval(handle);
    }
    this.timers.length = 0;
    this.started = false;
  }

  getStatus() {
    return {
      started: this.started,
      activeJobs: Array.from(this.runningJobs),
      verificationMode: this.options.verificationMode,
      telegramBotSendEnabled: this.options.telegramBotSendEnabled,
    };
  }
}
