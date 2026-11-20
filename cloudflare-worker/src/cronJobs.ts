/**
 * Path B-1 Cloudflare Worker Daily Cron & Missed-Run Catch-Up Engine
 * - Runs on Cloudflare Cron Triggers (`0 0 * * *`) + opportunistic missed-run catch-up.
 * - Records execution in D1 `cron_runs` table for auditability & idempotency.
 * - Strictly respects DRY_RUN flags (`PAYMENT_VERIFICATION_MODE`, `LICENSE_ISSUANCE_MODE`, `TELEGRAM_BOT_SEND_ENABLED`).
 */

import { runEncryptedR2Backup } from './backupR2';
import type { D1Database, WorkerEnv } from './d1Types';
import {
  recordAuditLog,
  verifyPaymentOnChainD1,
} from './ordersAndPayments';
import type { PolygonRpcProvider } from './polygon';
import { WorkerTelegramBotClient } from './telegramBot';

export interface DailyCronResult {
  runDateUtc: string;
  skipped: boolean;
  reason?: string;
  isCatchUp: boolean;
  expiredOrders: number;
  purgedIdempotency: number;
  purgedChallenges: number;
  expiredSubscriptions: number;
  expiredLicenses: number;
  renewalRemindersQueued: number;
  paymentsPolled: { checked: number; confirmed: number; pending: number; failed: number; skippedReason?: string };
  notificationsDispatched: { pending: number; sent: number; failed: number; skippedReason?: string };
  backupResult: { skipped: boolean; r2Key?: string; reason?: string };
}

function escapeHtml(text: string): string {
  return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

export async function runDailyAuditD1(
  db: D1Database,
  env: WorkerEnv,
  options?: {
    nowIso?: string;
    isCatchUp?: boolean;
    force?: boolean;
    rpcProvider?: PolygonRpcProvider;
  }
): Promise<DailyCronResult> {
  const now = options?.nowIso ? new Date(options.nowIso) : new Date();
  const nowIso = now.toISOString();
  const runDateUtc = nowIso.slice(0, 10);
  const isCatchUp = options?.isCatchUp ?? false;

  if (!options?.force) {
    const existing = await db
      .prepare(`SELECT run_date_utc, status FROM cron_runs WHERE run_date_utc = ?`)
      .bind(runDateUtc)
      .first<{ run_date_utc: string; status: string }>();
    if (existing && (existing.status === 'completed' || existing.status === 'running')) {
      return {
        runDateUtc,
        skipped: true,
        reason: `CRON_ALREADY_${existing.status.toUpperCase()}`,
        isCatchUp,
        expiredOrders: 0,
        purgedIdempotency: 0,
        purgedChallenges: 0,
        expiredSubscriptions: 0,
        expiredLicenses: 0,
        renewalRemindersQueued: 0,
        paymentsPolled: { checked: 0, confirmed: 0, pending: 0, failed: 0, skippedReason: 'ALREADY_RUN' },
        notificationsDispatched: { pending: 0, sent: 0, failed: 0, skippedReason: 'ALREADY_RUN' },
        backupResult: { skipped: true, reason: 'ALREADY_RUN' },
      };
    }
  }

  await db
    .prepare(
      `INSERT INTO cron_runs (run_date_utc, status, is_catch_up, started_at)
       VALUES (?, 'running', ?, ?)
       ON CONFLICT(run_date_utc) DO UPDATE SET status = 'running', is_catch_up = excluded.is_catch_up, started_at = excluded.started_at`
    )
    .bind(runDateUtc, isCatchUp ? 1 : 0, nowIso)
    .run();

  try {
    // 1. Expire overdue open orders
    const expOrdersRes = await db
      .prepare(
        `UPDATE orders SET status = 'expired', updated_at = ?
         WHERE status IN ('draft_phase0', 'pending_payment') AND expires_at <= ?`
      )
      .bind(nowIso, nowIso)
      .run();
    const expiredOrders = expOrdersRes.meta?.changes ?? 0;

    // 2. Purge expired idempotency_records and activation_challenges
    const purgeIdemRes = await db
      .prepare(`DELETE FROM idempotency_records WHERE expires_at <= ?`)
      .bind(nowIso)
      .run();
    const purgedIdempotency = purgeIdemRes.meta?.changes ?? 0;

    const purgeChgRes = await db
      .prepare(`DELETE FROM activation_challenges WHERE expires_at <= ?`)
      .bind(nowIso)
      .run();
    const purgedChallenges = purgeChgRes.meta?.changes ?? 0;

    // 3. Expire overdue subscriptions & licenses + record audit trail
    const expSubsRes = await db
      .prepare(
        `UPDATE subscriptions SET status = 'expired', version = version + 1, updated_at = ?
         WHERE status = 'active' AND expires_at <= ?`
      )
      .bind(nowIso, nowIso)
      .run();
    const expiredSubscriptions = expSubsRes.meta?.changes ?? 0;

    const expLicRows = await db
      .prepare(`SELECT id FROM licenses WHERE status = 'active' AND expires_at <= ?`)
      .bind(nowIso)
      .all<{ id: number }>();
    const expiringIds = (expLicRows.results ?? []).map((r) => r.id);
    if (expiringIds.length > 0) {
      const batchStmts = expiringIds.flatMap((licId) => [
        db
          .prepare(
            `UPDATE licenses SET status = 'expired', version = version + 1, updated_at = ? WHERE id = ? AND status = 'active'`
          )
          .bind(nowIso, licId),
        db
          .prepare(
            `INSERT INTO license_history (license_id, action, previous_status, new_status, actor_type, actor_id, reason)
             VALUES (?, 'EXPIRED_AUTO', 'active', 'expired', 'cron', 'daily_audit', 'Subscription period elapsed')`
          )
          .bind(licId),
      ]);
      await db.batch(batchStmts);
    }

    // 4. Queue 3-day pre-expiry renewal reminders
    const reminderCutoffIso = new Date(now.getTime() + 3 * 86400 * 1000).toISOString();
    const soonSubs = await db
      .prepare(
        `SELECT s.id, s.user_id, s.expires_at, p.name_fa AS plan_name_fa
         FROM subscriptions s
         JOIN plans p ON p.id = s.plan_id
         WHERE s.status = 'active' AND s.auto_renew_reminded = 0
           AND s.expires_at > ? AND s.expires_at <= ?`
      )
      .bind(nowIso, reminderCutoffIso)
      .all<{ id: number; user_id: number; expires_at: string; plan_name_fa: string }>();

    const reminders = soonSubs.results ?? [];
    if (reminders.length > 0) {
      await db.batch(
        reminders.flatMap((sub) => [
          db
            .prepare(`UPDATE subscriptions SET auto_renew_reminded = 1, updated_at = ? WHERE id = ?`)
            .bind(nowIso, sub.id),
          db
            .prepare(
              `INSERT OR IGNORE INTO notifications (user_id, channel, type, dedupe_key, title, body)
               VALUES (?, 'telegram_bot', 'SUBSCRIPTION_EXPIRY_REMINDER', ?, 'یادآوری تمدید اشتراک EDGE', ?)`
            )
            .bind(
              sub.user_id,
              `renew_reminder:${sub.id}:${sub.expires_at.slice(0, 10)}`,
              `اشتراک ${sub.plan_name_fa} شما در تاریخ ${sub.expires_at.slice(0, 10)} منقضی می‌شود. برای تمدید بدون قطعی از دستور /renew یا Mini App اقدام کنید.`
            ),
        ])
      );
    }

    // 5. Payment finality poller (strictly skipped in DRY_RUN)
    let paymentsPolled: DailyCronResult['paymentsPolled'] = {
      checked: 0,
      confirmed: 0,
      pending: 0,
      failed: 0,
    };
    if ((env.PAYMENT_VERIFICATION_MODE ?? 'DRY_RUN') !== 'LIVE') {
      paymentsPolled.skippedReason = 'DRY_RUN_MODE';
    } else {
      const staleIso = new Date(now.getTime() - 90_000).toISOString();
      const pendingPays = await db
        .prepare(
          `SELECT id FROM payments
           WHERE status = 'submitted' OR (status = 'verifying' AND updated_at <= ?)
           ORDER BY id ASC LIMIT 25`
        )
        .bind(staleIso)
        .all<{ id: number }>();
      for (const p of pendingPays.results ?? []) {
        paymentsPolled.checked += 1;
        try {
          const outcome = await verifyPaymentOnChainD1(db, env, p.id, {
            rpcProvider: options?.rpcProvider,
            actorId: 'daily_cron_poller',
          });
          if (outcome.payment.status === 'confirmed') paymentsPolled.confirmed += 1;
          else if (outcome.payment.status === 'failed') paymentsPolled.failed += 1;
          else paymentsPolled.pending += 1;
        } catch {
          paymentsPolled.pending += 1;
        }
      }
    }

    // 6. Notification dispatcher (strictly skipped unless TELEGRAM_BOT_SEND_ENABLED=true)
    const pendingNotifs = await db
      .prepare(
        `SELECT n.id, n.title, n.body, n.attempts, u.telegram_id, u.status AS user_status
         FROM notifications n
         JOIN users u ON u.id = n.user_id
         WHERE n.channel = 'telegram_bot' AND n.status = 'pending' AND n.attempts < 5
         ORDER BY n.id ASC LIMIT 25`
      )
      .all<{
        id: number;
        title: string;
        body: string;
        attempts: number;
        telegram_id: string;
        user_status: string;
      }>();

    const notifRows = pendingNotifs.results ?? [];
    let notificationsDispatched: DailyCronResult['notificationsDispatched'] = {
      pending: notifRows.length,
      sent: 0,
      failed: 0,
    };

    if (env.TELEGRAM_BOT_SEND_ENABLED !== 'true' || !env.TELEGRAM_BOT_TOKEN) {
      notificationsDispatched.skippedReason =
        env.TELEGRAM_BOT_SEND_ENABLED !== 'true'
          ? 'TELEGRAM_BOT_SEND_DISABLED'
          : 'TELEGRAM_BOT_TOKEN_MISSING';
    } else {
      const botClient = new WorkerTelegramBotClient(env.TELEGRAM_BOT_TOKEN, env.FETCH_IMPL ?? fetch);
      for (const n of notifRows) {
        const chatId = Number(n.telegram_id);
        if (!Number.isSafeInteger(chatId) || chatId <= 0 || n.user_status !== 'active') {
          await db
            .prepare(`UPDATE notifications SET status = 'failed', attempts = attempts + 1, last_error = ? WHERE id = ?`)
            .bind('INVALID_RECIPIENT', n.id)
            .run();
          notificationsDispatched.failed += 1;
          continue;
        }
        try {
          await botClient.sendMessage({
            chatId,
            parseMode: 'HTML',
            text: `<b>${escapeHtml(n.title)}</b>\n\n${escapeHtml(n.body)}`,
          });
          await db
            .prepare(`UPDATE notifications SET status = 'sent', attempts = attempts + 1, sent_at = ?, last_error = NULL WHERE id = ?`)
            .bind(nowIso, n.id)
            .run();
          notificationsDispatched.sent += 1;
        } catch (err) {
          const nextAttempts = n.attempts + 1;
          const nextStatus = nextAttempts >= 5 ? 'failed' : 'pending';
          await db
            .prepare(`UPDATE notifications SET status = ?, attempts = ?, last_error = ? WHERE id = ?`)
            .bind(nextStatus, nextAttempts, err instanceof Error ? err.message.slice(0, 180) : 'SEND_ERR', n.id)
            .run();
          if (nextStatus === 'failed') notificationsDispatched.failed += 1;
        }
      }
    }

    // 7. Encrypted R2 daily backup (public key only)
    let backupResult: DailyCronResult['backupResult'] = { skipped: true, reason: 'R2_BUCKET_UNBOUND' };
    if (env.BACKUP_BUCKET) {
      const r2Out = await runEncryptedR2Backup(db, env.BACKUP_BUCKET, env, {
        dateKey: runDateUtc,
        actorId: isCatchUp ? 'cron_catch_up' : 'daily_cron',
      });
      backupResult = { skipped: r2Out.skipped, r2Key: r2Out.r2Key, reason: r2Out.reason };
    }

    const result: DailyCronResult = {
      runDateUtc,
      skipped: false,
      isCatchUp,
      expiredOrders,
      purgedIdempotency,
      purgedChallenges,
      expiredSubscriptions,
      expiredLicenses: expiringIds.length,
      renewalRemindersQueued: reminders.length,
      paymentsPolled,
      notificationsDispatched,
      backupResult,
    };

    await db
      .prepare(
        `UPDATE cron_runs SET status = 'completed', summary_json = ?, completed_at = ?
         WHERE run_date_utc = ?`
      )
      .bind(JSON.stringify(result), new Date().toISOString(), runDateUtc)
      .run();

    await recordAuditLog(db, {
      actorType: 'cron',
      actorId: 'daily_audit',
      action: isCatchUp ? 'DAILY_CRON_CATCHUP_COMPLETED' : 'DAILY_CRON_COMPLETED',
      entityType: 'cron_run',
      entityId: runDateUtc,
      metadata: result as unknown as Record<string, unknown>,
    });

    return result;
  } catch (err) {
    await db
      .prepare(`UPDATE cron_runs SET status = 'failed', summary_json = ?, completed_at = ? WHERE run_date_utc = ?`)
      .bind(
        JSON.stringify({ error: err instanceof Error ? err.message.slice(0, 200) : 'CRON_ERROR' }),
        new Date().toISOString(),
        runDateUtc
      )
      .run();
    throw err;
  }
}

/**
 * Checks whether yesterday's UTC daily audit run was missed and runs catch-up automatically.
 */
export async function checkAndRunMissedCronCatchUp(
  db: D1Database,
  env: WorkerEnv,
  nowIso = new Date().toISOString()
): Promise<DailyCronResult | null> {
  const todayUtc = nowIso.slice(0, 10);
  const yesterdayMs = new Date(nowIso).getTime() - 86400_000;
  const yesterdayUtc = new Date(yesterdayMs).toISOString().slice(0, 10);

  const yesterdayRow = await db
    .prepare(`SELECT status FROM cron_runs WHERE run_date_utc = ?`)
    .bind(yesterdayUtc)
    .first<{ status: string }>();

  if (yesterdayRow?.status === 'completed' || yesterdayRow?.status === 'running') {
    return null;
  }

  // Only catch up if there is at least one prior row or operational record indicating system was active
  const anyHistory = await db
    .prepare(`SELECT 1 AS ok FROM cron_runs WHERE run_date_utc < ? LIMIT 1`)
    .bind(todayUtc)
    .first<{ ok: number }>();
  if (!anyHistory) {
    return null;
  }

  return runDailyAuditD1(db, env, {
    nowIso: `${yesterdayUtc}T23:59:00.000Z`,
    isCatchUp: true,
  });
}
