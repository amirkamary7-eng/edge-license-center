import type {
  AdminDashboardSummary,
  AdminRecord,
  AdminRole,
  AuditLogRecord,
  LicenseRecord,
  OrderRecord,
  OrderStatus,
  PaymentRecord,
  PlanRecord,
  SubscriptionRecord,
  SystemSettingRecord,
  UserRecord,
  UserStatus,
} from '../../../shared/types';
import { runImmediateTransaction, type SqliteDb } from '../../db/connection';
import { AuditService } from '../audit/auditService';
import { UserRepository } from '../users/userRepository';

export class AdminOperationError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly statusCode = 400
  ) {
    super(message);
    this.name = 'AdminOperationError';
  }
}

export class AdminService {
  private readonly audit: AuditService;
  private readonly users: UserRepository;

  constructor(private readonly db: SqliteDb) {
    this.audit = new AuditService(db);
    this.users = new UserRepository(db);
  }

  getDashboardSummary(): AdminDashboardSummary {
    const count = (sql: string): number => {
      const row = this.db.prepare(sql).get() as { cnt: number };
      return row?.cnt ?? 0;
    };

    const revenueRow = this.db
      .prepare(`SELECT COALESCE(SUM(amount_usdc_micro), 0) AS total FROM payments WHERE status = 'confirmed'`)
      .get() as { total: number };

    const confirmedRevenueUsdcMicro = revenueRow?.total ?? 0;

    return {
      totalUsers: count('SELECT COUNT(*) AS cnt FROM users'),
      activeAdmins: count('SELECT COUNT(*) AS cnt FROM admins WHERE is_active = 1'),
      totalOrders: count('SELECT COUNT(*) AS cnt FROM orders'),
      pendingOrders: count(
        `SELECT COUNT(*) AS cnt FROM orders WHERE status IN ('draft_phase0', 'pending_payment', 'tx_submitted', 'verifying')`
      ),
      totalPayments: count('SELECT COUNT(*) AS cnt FROM payments'),
      confirmedRevenueUsdcMicro,
      confirmedRevenueUsd: (confirmedRevenueUsdcMicro / 1_000_000).toFixed(2),
      activeSubscriptions: count(`SELECT COUNT(*) AS cnt FROM subscriptions WHERE status = 'active'`),
      activeLicenses: count(`SELECT COUNT(*) AS cnt FROM licenses WHERE status = 'active'`),
      revokedOrBlockedLicenses: count(
        `SELECT COUNT(*) AS cnt FROM licenses WHERE status IN ('revoked', 'blocked')`
      ),
      boundDevices: count(`SELECT COUNT(*) AS cnt FROM devices WHERE status = 'active'`),
      securityEventsLast24h: count(
        `SELECT COUNT(*) AS cnt FROM audit_logs WHERE severity IN ('warning', 'critical') AND created_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-1 day')`
      ),
      openTickets: count(
        `SELECT COUNT(*) AS cnt FROM support_tickets WHERE status IN ('open', 'in_progress')`
      ),
    };
  }

  listUsers(limit = 100, offset = 0): UserRecord[] {
    return this.db
      .prepare('SELECT * FROM users ORDER BY id DESC LIMIT ? OFFSET ?')
      .all(limit, offset) as UserRecord[];
  }

  updateUserStatus(userId: number, status: UserStatus, adminActorId: string): UserRecord {
    const existing = this.users.findById(userId);
    if (!existing) {
      throw new AdminOperationError('USER_NOT_FOUND', 'User not found.', 404);
    }
    this.db
      .prepare(`UPDATE users SET status = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?`)
      .run(status, userId);

    this.audit.record({
      actorType: 'admin',
      actorId: adminActorId,
      action: 'USER_STATUS_UPDATED',
      entityType: 'user',
      entityId: String(userId),
      severity: status === 'active' ? 'info' : 'warning',
      metadata: { previousStatus: existing.status, newStatus: status },
    });

    return this.users.findById(userId)!;
  }

  listOrders(limit = 100, offset = 0): OrderRecord[] {
    return this.db
      .prepare(
        `SELECT o.*, p.code AS plan_code, p.name_en AS plan_name_en, p.name_fa AS plan_name_fa
         FROM orders o
         JOIN plans p ON p.id = o.plan_id
         ORDER BY o.id DESC
         LIMIT ? OFFSET ?`
      )
      .all(limit, offset) as OrderRecord[];
  }

  updateOrderStatus(params: {
    orderCode: string;
    status: Extract<OrderStatus, 'cancelled' | 'rejected' | 'expired'>;
    reason: string;
    adminActorId: string;
  }): OrderRecord {
    return runImmediateTransaction(this.db, () => {
      const order = this.db
        .prepare('SELECT * FROM orders WHERE order_code = ?')
        .get(params.orderCode) as OrderRecord | undefined;
      if (!order) {
        throw new AdminOperationError('ORDER_NOT_FOUND', 'Order not found.', 404);
      }
      if (order.status === 'confirmed') {
        throw new AdminOperationError(
          'CANNOT_MODIFY_CONFIRMED_ORDER',
          'Confirmed orders cannot be cancelled or rejected.',
          409
        );
      }
      const nowIso = new Date().toISOString();
      this.db
        .prepare('UPDATE orders SET status = ?, updated_at = ? WHERE id = ?')
        .run(params.status, nowIso, order.id);

      this.audit.record({
        actorType: 'admin',
        actorId: params.adminActorId,
        action: 'ORDER_STATUS_UPDATED_BY_ADMIN',
        entityType: 'order',
        entityId: order.order_code,
        severity: 'warning',
        metadata: { previousStatus: order.status, newStatus: params.status, reason: params.reason },
      });

      return this.db
        .prepare(
          `SELECT o.*, p.code AS plan_code, p.name_en AS plan_name_en, p.name_fa AS plan_name_fa
           FROM orders o
           JOIN plans p ON p.id = o.plan_id
           WHERE o.id = ?`
        )
        .get(order.id) as OrderRecord;
    });
  }

  listPayments(limit = 100, offset = 0): PaymentRecord[] {
    return this.db
      .prepare(
        `SELECT pay.*, o.order_code
         FROM payments pay
         JOIN orders o ON o.id = pay.order_id
         ORDER BY pay.id DESC
         LIMIT ? OFFSET ?`
      )
      .all(limit, offset) as PaymentRecord[];
  }

  listSubscriptions(limit = 100, offset = 0): SubscriptionRecord[] {
    return this.db
      .prepare('SELECT * FROM subscriptions ORDER BY id DESC LIMIT ? OFFSET ?')
      .all(limit, offset) as SubscriptionRecord[];
  }

  listLicenses(limit = 100, offset = 0): LicenseRecord[] {
    return this.db
      .prepare('SELECT * FROM licenses ORDER BY id DESC LIMIT ? OFFSET ?')
      .all(limit, offset) as LicenseRecord[];
  }

  listPlans(): PlanRecord[] {
    return this.db.prepare('SELECT * FROM plans ORDER BY sort_order ASC').all() as PlanRecord[];
  }

  /**
   * Allows authorized admin to toggle plan availability or max_devices without altering frozen commercial prices.
   */
  updatePlanControls(params: {
    code: string;
    isActive?: boolean;
    maxDevices?: number;
    adminActorId: string;
  }): PlanRecord {
    return runImmediateTransaction(this.db, () => {
      const plan = this.db
        .prepare('SELECT * FROM plans WHERE code = ?')
        .get(params.code) as PlanRecord | undefined;
      if (!plan) {
        throw new AdminOperationError('PLAN_NOT_FOUND', 'Plan not found.', 404);
      }
      const nextActive = params.isActive === undefined ? plan.is_active : params.isActive ? 1 : 0;
      const nextDevices = params.maxDevices ?? plan.max_devices;

      this.db
        .prepare(
          `UPDATE plans SET is_active = ?, max_devices = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?`
        )
        .run(nextActive, nextDevices, plan.id);

      this.audit.record({
        actorType: 'admin',
        actorId: params.adminActorId,
        action: 'PLAN_CONTROLS_UPDATED',
        entityType: 'plan',
        entityId: plan.code,
        severity: 'warning',
        metadata: { isActive: nextActive, maxDevices: nextDevices },
      });

      return this.db.prepare('SELECT * FROM plans WHERE id = ?').get(plan.id) as PlanRecord;
    });
  }

  listAdmins(): Array<AdminRecord & { username: string | null; first_name: string }> {
    return this.db
      .prepare(
        `SELECT a.*, u.username, u.first_name
         FROM admins a
         JOIN users u ON u.id = a.user_id
         ORDER BY a.id ASC`
      )
      .all() as Array<AdminRecord & { username: string | null; first_name: string }>;
  }

  private countActiveSuperAdmins(): number {
    const row = this.db
      .prepare(`SELECT COUNT(*) AS cnt FROM admins WHERE role = 'super_admin' AND is_active = 1`)
      .get() as { cnt: number };
    return row?.cnt ?? 0;
  }

  assignAdminRole(params: {
    telegramId: string;
    role: AdminRole;
    grantedByAdminId: number;
    actorId: string;
  }): AdminRecord {
    return runImmediateTransaction(this.db, () => {
      const user = this.users.findByTelegramId(params.telegramId);
      if (!user) {
        throw new AdminOperationError('TARGET_USER_NOT_REGISTERED', 'Target user is not registered.', 404);
      }

      // Prevent demoting the last active super_admin
      const existingAdmin = this.db
        .prepare('SELECT * FROM admins WHERE user_id = ?')
        .get(user.id) as AdminRecord | undefined;

      if (
        existingAdmin &&
        existingAdmin.is_active === 1 &&
        existingAdmin.role === 'super_admin' &&
        params.role !== 'super_admin' &&
        this.countActiveSuperAdmins() <= 1
      ) {
        throw new AdminOperationError(
          'CANNOT_REMOVE_LAST_SUPER_ADMIN',
          'Cannot demote the last active super_admin.',
          409
        );
      }

      const record = this.users.ensureAdminRole(
        user.id,
        user.telegram_id,
        params.role,
        params.grantedByAdminId
      );

      this.audit.record({
        actorType: 'admin',
        actorId: params.actorId,
        action: 'ADMIN_ROLE_ASSIGNED',
        entityType: 'admin',
        entityId: String(record.id),
        severity: 'critical',
        metadata: { targetTelegramId: params.telegramId, role: params.role },
      });

      return record;
    });
  }

  deactivateAdmin(params: { adminId: number; actorId: string }): AdminRecord {
    return runImmediateTransaction(this.db, () => {
      const target = this.db
        .prepare('SELECT * FROM admins WHERE id = ?')
        .get(params.adminId) as AdminRecord | undefined;
      if (!target) {
        throw new AdminOperationError('ADMIN_NOT_FOUND', 'Admin record not found.', 404);
      }
      if (target.role === 'super_admin' && target.is_active === 1 && this.countActiveSuperAdmins() <= 1) {
        throw new AdminOperationError(
          'CANNOT_REMOVE_LAST_SUPER_ADMIN',
          'Cannot deactivate the last active super_admin.',
          409
        );
      }

      this.db
        .prepare(`UPDATE admins SET is_active = 0, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?`)
        .run(target.id);

      this.audit.record({
        actorType: 'admin',
        actorId: params.actorId,
        action: 'ADMIN_DEACTIVATED',
        entityType: 'admin',
        entityId: String(target.id),
        severity: 'critical',
        metadata: { targetTelegramId: target.telegram_id, previousRole: target.role },
      });

      return this.db.prepare('SELECT * FROM admins WHERE id = ?').get(target.id) as AdminRecord;
    });
  }

  updateSetting(params: { key: string; value: string; adminActorId: string }): SystemSettingRecord {
    const existing = this.db
      .prepare('SELECT * FROM system_settings WHERE key = ?')
      .get(params.key) as SystemSettingRecord | undefined;
    if (!existing) {
      throw new AdminOperationError('SETTING_NOT_FOUND', 'System setting key not found.', 404);
    }
    if (existing.is_immutable === 1) {
      throw new AdminOperationError(
        'IMMUTABLE_SYSTEM_SETTING',
        'Immutable payment and network settings cannot be modified.',
        403
      );
    }

    this.db
      .prepare(
        `UPDATE system_settings SET value = ?, updated_by = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE key = ?`
      )
      .run(params.value, params.adminActorId, params.key);

    this.audit.record({
      actorType: 'admin',
      actorId: params.adminActorId,
      action: 'SYSTEM_SETTING_UPDATED',
      entityType: 'system_setting',
      entityId: params.key,
      severity: 'critical',
      metadata: { previousValue: existing.value, newValue: params.value },
    });

    return this.db
      .prepare('SELECT * FROM system_settings WHERE key = ?')
      .get(params.key) as SystemSettingRecord;
  }

  getFinancialReport(options?: { fromIso?: string; toIso?: string }): {
    byPlan: Array<{
      plan_code: string;
      name_en: string;
      price_usd_display: string;
      orders_count: number;
      confirmed_payments_count: number;
      confirmed_usdc_micro: number;
    }>;
    totals: {
      totalOrders: number;
      confirmedPayments: number;
      confirmedRevenueUsd: string;
      dryRunSubmissions: number;
    };
  } {
    const fromIso = options?.fromIso ?? '1970-01-01T00:00:00.000Z';
    const toIso = options?.toIso ?? '2999-12-31T23:59:59.999Z';

    const byPlan = this.db
      .prepare(
        `SELECT
           p.code AS plan_code,
           p.name_en,
           p.price_usd_display,
           COUNT(DISTINCT CASE WHEN o.created_at >= ? AND o.created_at <= ? THEN o.id END) AS orders_count,
           COUNT(DISTINCT CASE WHEN pay.status = 'confirmed' AND pay.created_at >= ? AND pay.created_at <= ? THEN pay.id END) AS confirmed_payments_count,
           COALESCE(SUM(CASE WHEN pay.status = 'confirmed' AND pay.created_at >= ? AND pay.created_at <= ? THEN pay.amount_usdc_micro ELSE 0 END), 0) AS confirmed_usdc_micro
         FROM plans p
         LEFT JOIN orders o ON o.plan_id = p.id
         LEFT JOIN payments pay ON pay.order_id = o.id
         GROUP BY p.id
         ORDER BY p.sort_order ASC`
      )
      .all(fromIso, toIso, fromIso, toIso, fromIso, toIso) as Array<{
      plan_code: string;
      name_en: string;
      price_usd_display: string;
      orders_count: number;
      confirmed_payments_count: number;
      confirmed_usdc_micro: number;
    }>;

    const totalOrders = byPlan.reduce((sum, row) => sum + row.orders_count, 0);
    const confirmedPayments = byPlan.reduce((sum, row) => sum + row.confirmed_payments_count, 0);
    const totalMicro = byPlan.reduce((sum, row) => sum + row.confirmed_usdc_micro, 0);
    const dryRunRow = this.db
      .prepare(`SELECT COUNT(*) AS cnt FROM payments WHERE status = 'dry_run_recorded'`)
      .get() as { cnt: number };

    return {
      byPlan,
      totals: {
        totalOrders,
        confirmedPayments,
        confirmedRevenueUsd: (totalMicro / 1_000_000).toFixed(2),
        dryRunSubmissions: dryRunRow?.cnt ?? 0,
      },
    };
  }

  listAuditLogs(limit = 100, severity?: AuditLogRecord['severity']): AuditLogRecord[] {
    return this.audit.listRecent(limit, severity);
  }

  listSettings(): SystemSettingRecord[] {
    return this.db
      .prepare('SELECT * FROM system_settings ORDER BY key ASC')
      .all() as SystemSettingRecord[];
  }
}
