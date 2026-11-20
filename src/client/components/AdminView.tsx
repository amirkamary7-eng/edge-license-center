import { useCallback, useEffect, useState } from 'react';
import type {
  AdminDashboardSummary,
  AdminRecord,
  AdminRole,
  AuditLogRecord,
  LicenseHistoryRecord,
  LicenseRecord,
  OrderRecord,
  PaymentRecord,
  PlanRecord,
  SubscriptionRecord,
  SupportTicketRecord,
  SystemSettingRecord,
  TicketStatus,
  UserRecord,
  UserStatus,
} from '../../shared/types';
import { apiClient, type FinancialReportResponse } from '../api';
import { copy, type Locale } from '../i18n';

type AdminTab =
  | 'overview'
  | 'users'
  | 'orders'
  | 'payments'
  | 'licenses'
  | 'plans'
  | 'finance'
  | 'security'
  | 'tickets'
  | 'admins';

interface AdminViewProps {
  locale: Locale;
  adminRole: AdminRole | null;
}

export function AdminView({ locale, adminRole }: AdminViewProps) {
  const t = copy[locale];
  const [tab, setTab] = useState<AdminTab>('overview');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [summary, setSummary] = useState<AdminDashboardSummary | null>(null);
  const [users, setUsers] = useState<UserRecord[]>([]);
  const [orders, setOrders] = useState<OrderRecord[]>([]);
  const [payments, setPayments] = useState<PaymentRecord[]>([]);
  const [subscriptions, setSubscriptions] = useState<SubscriptionRecord[]>([]);
  const [licenses, setLicenses] = useState<LicenseRecord[]>([]);
  const [selectedHistoryKey, setSelectedHistoryKey] = useState<string | null>(null);
  const [licenseHistory, setLicenseHistory] = useState<LicenseHistoryRecord[]>([]);
  const [plans, setPlans] = useState<PlanRecord[]>([]);
  const [finance, setFinance] = useState<FinancialReportResponse | null>(null);
  const [auditLogs, setAuditLogs] = useState<AuditLogRecord[]>([]);
  const [tickets, setTickets] = useState<SupportTicketRecord[]>([]);
  const [ticketReplies, setTicketReplies] = useState<Record<number, string>>({});
  const [admins, setAdmins] = useState<
    Array<AdminRecord & { username: string | null; first_name: string }>
  >([]);
  const [settings, setSettings] = useState<SystemSettingRecord[]>([]);

  const [newAdminTgId, setNewAdminTgId] = useState('');
  const [newAdminRole, setNewAdminRole] = useState<AdminRole>('support');
  const [actionNotice, setActionNotice] = useState<string | null>(null);

  const loadTabData = useCallback(async (activeTab: AdminTab) => {
    setLoading(true);
    setError(null);
    try {
      if (activeTab === 'overview') {
        const res = await apiClient.admin.getDashboard();
        setSummary(res.summary);
      } else if (activeTab === 'users') {
        const res = await apiClient.admin.listUsers();
        setUsers(res.users);
      } else if (activeTab === 'orders') {
        const res = await apiClient.admin.listOrders();
        setOrders(res.orders);
      } else if (activeTab === 'payments') {
        const res = await apiClient.admin.listPayments();
        setPayments(res.payments);
      } else if (activeTab === 'licenses') {
        const [licRes, subRes] = await Promise.all([
          apiClient.admin.listLicenses(),
          apiClient.admin.listSubscriptions(),
        ]);
        setLicenses(licRes.licenses);
        setSubscriptions(subRes.subscriptions);
      } else if (activeTab === 'plans') {
        const res = await apiClient.admin.listPlans();
        setPlans(res.plans);
      } else if (activeTab === 'finance') {
        const res = await apiClient.admin.getFinancialReport();
        setFinance(res);
      } else if (activeTab === 'security') {
        const res = await apiClient.admin.getSecurityLogs();
        setAuditLogs(res.auditLogs);
      } else if (activeTab === 'tickets') {
        const res = await apiClient.admin.listTickets();
        setTickets(res.tickets);
      } else if (activeTab === 'admins') {
        const res = await apiClient.admin.listAdminsAndSettings();
        setAdmins(res.admins);
        setSettings(res.settings);
      }
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (adminRole) {
      loadTabData(tab);
    }
  }, [adminRole, tab, loadTabData]);

  if (!adminRole) {
    return (
      <div className="bg-[#0E1525] border border-[#1F2C47] rounded-xl p-8 max-w-2xl space-y-2">
        <h1 className="text-xl font-bold text-[#FCA5A5]">{t.admin.deniedTitle}</h1>
        <p className="text-sm text-[#9CA3AF]">{t.admin.deniedDesc}</p>
      </div>
    );
  }

  const handleUserStatusChange = async (userId: number, status: UserStatus) => {
    setError(null);
    setActionNotice(null);
    try {
      await apiClient.admin.updateUserStatus(userId, status);
      setActionNotice(`User #${userId} status updated to ${status}`);
      await loadTabData('users');
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleOrderStatusChange = async (
    orderCode: string,
    status: 'cancelled' | 'rejected'
  ) => {
    setError(null);
    setActionNotice(null);
    try {
      await apiClient.admin.updateOrderStatus(orderCode, status, `Admin marked order ${status}`);
      setActionNotice(`Order ${orderCode} updated to ${status}.`);
      await loadTabData('orders');
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleVerifyPayment = async (paymentId: number) => {
    setError(null);
    setActionNotice(null);
    try {
      const res = await apiClient.admin.verifyPaymentOnChain(paymentId);
      setActionNotice(
        res.verification.valid
          ? `Payment #${paymentId} confirmed on Polygon PoS${res.licenseKey ? ` (License: ${res.licenseKey})` : ''}.`
          : `Payment #${paymentId} not confirmed: ${res.verification.reason ?? 'PENDING'}`
      );
      await loadTabData('payments');
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleLicenseStatusChange = async (
    licenseKey: string,
    status: 'active' | 'revoked' | 'blocked'
  ) => {
    setError(null);
    setActionNotice(null);
    try {
      await apiClient.admin.updateLicenseStatus(
        licenseKey,
        status,
        `Admin changed license status to ${status}`
      );
      setActionNotice(`License ${licenseKey} updated to ${status}.`);
      await loadTabData('licenses');
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleLoadLicenseHistory = async (licenseKey: string) => {
    setError(null);
    try {
      const res = await apiClient.admin.listLicenseHistory(licenseKey);
      setSelectedHistoryKey(licenseKey);
      setLicenseHistory(res.history);
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleTogglePlan = async (plan: PlanRecord) => {
    setError(null);
    setActionNotice(null);
    try {
      await apiClient.admin.updatePlanControls(plan.code, {
        isActive: plan.is_active !== 1,
      });
      setActionNotice(`Plan ${plan.code} visibility updated.`);
      await loadTabData('plans');
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleReplyTicket = async (ticketId: number, status: TicketStatus) => {
    setError(null);
    setActionNotice(null);
    try {
      const reply = ticketReplies[ticketId]?.trim();
      await apiClient.admin.replyTicket(ticketId, status, reply || undefined);
      setActionNotice(`Ticket #${ticketId} updated to ${status}.`);
      await loadTabData('tickets');
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleAssignAdmin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setActionNotice(null);
    try {
      await apiClient.admin.assignAdminRole(newAdminTgId.trim(), newAdminRole);
      setNewAdminTgId('');
      setActionNotice('Admin role updated and recorded in audit_logs.');
      await loadTabData('admins');
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleDeactivateAdmin = async (adminId: number) => {
    setError(null);
    setActionNotice(null);
    try {
      await apiClient.admin.deactivateAdmin(adminId);
      setActionNotice(`Admin #${adminId} deactivated.`);
      await loadTabData('admins');
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const tabs: Array<{ id: AdminTab; label: string }> = [
    { id: 'overview', label: t.admin.tabs.overview },
    { id: 'users', label: t.admin.tabs.users },
    { id: 'orders', label: t.admin.tabs.orders },
    { id: 'payments', label: t.admin.tabs.payments },
    { id: 'licenses', label: t.admin.tabs.licenses },
    { id: 'plans', label: t.admin.tabs.plans },
    { id: 'finance', label: t.admin.tabs.finance },
    { id: 'security', label: t.admin.tabs.security },
    { id: 'tickets', label: t.admin.tabs.tickets },
    { id: 'admins', label: t.admin.tabs.admins },
  ];

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div className="space-y-1.5">
          <h1 className="text-2xl font-bold text-[#F3F4F6] text-balance">{t.admin.heading}</h1>
          <p className="text-sm text-[#9CA3AF]">{t.admin.lead}</p>
        </div>
        <div className="text-xs font-mono text-[#D4AF37]" dir="ltr">
          RBAC Role: {adminRole}
        </div>
      </div>

      {/* Segmented Admin Navigation */}
      <div className="flex flex-wrap items-center gap-1.5 p-1.5 bg-[#0A0F1D] border border-[#1F2C47] rounded-xl">
        {tabs.map((item) => (
          <button
            key={item.id}
            type="button"
            onClick={() => setTab(item.id)}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
              tab === item.id
                ? 'bg-[#131C31] text-[#D4AF37] border border-[#2B3B5E]'
                : 'text-[#9CA3AF] hover:text-[#F3F4F6] border border-transparent'
            }`}
          >
            {item.label}
          </button>
        ))}
      </div>

      {error && (
        <div className="p-4 rounded-lg bg-[#2A1215] border border-[#7F1D1D] text-xs text-[#FCA5A5]">
          {error}
        </div>
      )}

      {actionNotice && (
        <div className="p-4 rounded-lg bg-[#092420] border border-[#14B8A6]/40 text-xs text-[#99F6E4]">
          {actionNotice}
        </div>
      )}

      {loading ? (
        <div className="bg-[#0E1525] border border-[#1F2C47] rounded-xl p-8 text-sm text-[#9CA3AF]">
          {locale === 'fa' ? 'در حال بارگذاری داده‌های SQLite...' : 'Loading SQLite data...'}
        </div>
      ) : (
        <>
          {tab === 'overview' && summary && (
            <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
              {[
                { label: 'Total Users', value: summary.totalUsers, accent: 'text-[#F3F4F6]' },
                { label: 'Active Admins', value: summary.activeAdmins, accent: 'text-[#2DD4BF]' },
                { label: 'Total Orders', value: summary.totalOrders, accent: 'text-[#F3F4F6]' },
                { label: 'Pending / Draft Orders', value: summary.pendingOrders, accent: 'text-[#D4AF37]' },
                { label: 'Confirmed Revenue (USDC)', value: `$${summary.confirmedRevenueUsd}`, accent: 'text-[#D4AF37]' },
                { label: 'Active Subscriptions', value: summary.activeSubscriptions, accent: 'text-[#2DD4BF]' },
                { label: 'Active Licenses', value: summary.activeLicenses, accent: 'text-[#2DD4BF]' },
                { label: 'Open Support Tickets', value: summary.openTickets ?? 0, accent: 'text-[#D4AF37]' },
                { label: 'Security Alerts (24h)', value: summary.securityEventsLast24h, accent: 'text-[#F87171]' },
              ].map((kpi) => (
                <div
                  key={kpi.label}
                  className="bg-[#0E1525] border border-[#1F2C47] rounded-xl p-5"
                >
                  <div className="text-xs text-[#9CA3AF]">{kpi.label}</div>
                  <div className={`mt-2 text-2xl font-bold font-mono tabular-nums ${kpi.accent}`} dir="ltr">
                    {kpi.value}
                  </div>
                </div>
              ))}
            </div>
          )}

          {tab === 'users' && (
            <section className="bg-[#0E1525] border border-[#1F2C47] rounded-xl overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-[#1F2C47] text-xs text-[#9CA3AF] bg-[#0A0F1D]">
                      <th className="px-5 py-3 text-start font-medium">ID</th>
                      <th className="px-5 py-3 text-start font-medium">Telegram ID</th>
                      <th className="px-5 py-3 text-start font-medium">Name / Handle</th>
                      <th className="px-5 py-3 text-start font-medium">Status</th>
                      <th className="px-5 py-3 text-end font-medium">Control</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1F2C47]">
                    {users.map((u) => (
                      <tr key={u.id} className="hover:bg-[#131C31]/60">
                        <td className="px-5 py-3 font-mono tabular-nums text-xs text-[#9CA3AF]">
                          #{u.id}
                        </td>
                        <td className="px-5 py-3 font-mono tabular-nums text-xs text-[#F3F4F6]" dir="ltr">
                          {u.telegram_id}
                        </td>
                        <td className="px-5 py-3 text-[#CBD5E1]">
                          {u.first_name}{' '}
                          {u.username && (
                            <span className="font-mono text-xs text-[#64748B]" dir="ltr">
                              @{u.username}
                            </span>
                          )}
                        </td>
                        <td className="px-5 py-3 font-mono text-xs text-[#2DD4BF]" dir="ltr">
                          {u.status}
                        </td>
                        <td className="px-5 py-3 text-end">
                          <select
                            aria-label={`Change status for ${u.telegram_id}`}
                            value={u.status}
                            onChange={(e) =>
                              handleUserStatusChange(u.id, e.target.value as UserStatus)
                            }
                            className="bg-[#07090F] border border-[#1F2C47] rounded-md px-2 py-1 text-xs font-mono text-[#F3F4F6]"
                          >
                            <option value="active">active</option>
                            <option value="suspended">suspended</option>
                            <option value="banned">banned</option>
                          </select>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}

          {tab === 'orders' && (
            <section className="bg-[#0E1525] border border-[#1F2C47] rounded-xl overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-[#1F2C47] text-xs text-[#9CA3AF] bg-[#0A0F1D]">
                      <th className="px-5 py-3 text-start font-medium">Order Code</th>
                      <th className="px-5 py-3 text-start font-medium">Plan / Type</th>
                      <th className="px-5 py-3 text-end font-medium">Payable USDC</th>
                      <th className="px-5 py-3 text-start font-medium">Status</th>
                      <th className="px-5 py-3 text-end font-medium">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1F2C47]">
                    {orders.length === 0 ? (
                      <tr>
                        <td colSpan={5} className="px-5 py-6 text-sm text-[#9CA3AF]">
                          No orders recorded.
                        </td>
                      </tr>
                    ) : (
                      orders.map((o) => (
                        <tr key={o.id} className="hover:bg-[#131C31]/60">
                          <td className="px-5 py-3 font-mono text-xs text-[#F3F4F6]" dir="ltr">
                            {o.order_code}
                          </td>
                          <td className="px-5 py-3 font-mono text-xs text-[#CBD5E1]" dir="ltr">
                            {o.plan_code} · {o.order_type ?? 'new'}
                          </td>
                          <td className="px-5 py-3 text-end font-mono tabular-nums text-[#D4AF37]" dir="ltr">
                            {((o.payable_amount_usdc_micro ?? o.expected_amount_usdc_micro) / 1_000_000).toFixed(6)}
                          </td>
                          <td className="px-5 py-3 font-mono text-xs text-[#2DD4BF]" dir="ltr">
                            {o.status}
                          </td>
                          <td className="px-5 py-3 text-end">
                            {(o.status === 'pending_payment' ||
                              o.status === 'tx_submitted' ||
                              o.status === 'verifying' ||
                              o.status === 'draft_phase0') && (
                              <div className="inline-flex items-center gap-1.5">
                                <button
                                  type="button"
                                  onClick={() => handleOrderStatusChange(o.order_code, 'cancelled')}
                                  className="px-2 py-1 rounded bg-[#131C31] border border-[#2B3B5E] text-xs text-[#CBD5E1] hover:border-[#D4AF37]"
                                >
                                  Cancel
                                </button>
                                <button
                                  type="button"
                                  onClick={() => handleOrderStatusChange(o.order_code, 'rejected')}
                                  className="px-2 py-1 rounded bg-[#2A1215] border border-[#7F1D1D] text-xs text-[#FCA5A5]"
                                >
                                  Reject
                                </button>
                              </div>
                            )}
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </section>
          )}

          {tab === 'payments' && (
            <section className="bg-[#0E1525] border border-[#1F2C47] rounded-xl overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-[#1F2C47] text-xs text-[#9CA3AF] bg-[#0A0F1D]">
                      <th className="px-5 py-3 text-start font-medium">Order</th>
                      <th className="px-5 py-3 text-start font-medium">TxID</th>
                      <th className="px-5 py-3 text-end font-medium">Amount</th>
                      <th className="px-5 py-3 text-start font-medium">Status</th>
                      <th className="px-5 py-3 text-end font-medium">Verify</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1F2C47]">
                    {payments.length === 0 ? (
                      <tr>
                        <td colSpan={5} className="px-5 py-6 text-sm text-[#9CA3AF]">
                          No payments submitted yet.
                        </td>
                      </tr>
                    ) : (
                      payments.map((p) => (
                        <tr key={p.id} className="hover:bg-[#131C31]/60">
                          <td className="px-5 py-3 font-mono text-xs text-[#F3F4F6]" dir="ltr">
                            {p.order_code ?? `#${p.order_id}`}
                          </td>
                          <td className="px-5 py-3 font-mono text-xs text-[#CBD5E1]" dir="ltr">
                            {p.tx_hash.slice(0, 14)}...{p.tx_hash.slice(-8)}
                          </td>
                          <td className="px-5 py-3 text-end font-mono tabular-nums text-[#D4AF37]" dir="ltr">
                            {(p.amount_usdc_micro / 1_000_000).toFixed(6)}
                          </td>
                          <td className="px-5 py-3 font-mono text-xs text-[#2DD4BF]" dir="ltr">
                            {p.status}
                          </td>
                          <td className="px-5 py-3 text-end">
                            {p.status === 'submitted' || p.status === 'verifying' ? (
                              <button
                                type="button"
                                onClick={() => handleVerifyPayment(p.id)}
                                className="px-2.5 py-1 rounded bg-[#131C31] border border-[#D4AF37] text-xs text-[#D4AF37] whitespace-nowrap"
                              >
                                Verify On-Chain
                              </button>
                            ) : (
                              <span className="text-xs text-[#9CA3AF]">
                                {p.verification_note ?? '-'}
                              </span>
                            )}
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </section>
          )}

          {tab === 'licenses' && (
            <div className="space-y-4">
              <section className="bg-[#0E1525] border border-[#1F2C47] rounded-xl p-6 space-y-4">
                <h2 className="text-base font-semibold text-[#F3F4F6]">
                  Issued Licenses ({licenses.length}) · Subscriptions ({subscriptions.length})
                </h2>
                {licenses.length === 0 ? (
                  <p className="text-sm text-[#9CA3AF]">
                    No live licenses issued while DRY_RUN mode is active. License signing, renewal,
                    revocation, and Android validation are covered by automated tests.
                  </p>
                ) : (
                  <div className="divide-y divide-[#1F2C47]">
                    {licenses.map((l) => (
                      <div
                        key={l.id}
                        className="py-3 flex flex-wrap items-center justify-between gap-3 text-xs font-mono"
                        dir="ltr"
                      >
                        <div className="space-y-0.5">
                          <div className="text-[#D4AF37] font-semibold">{l.license_key}</div>
                          <div className="text-[#9CA3AF]">
                            Status: <span className="text-[#2DD4BF]">{l.status}</span> · Expires{' '}
                            {l.expires_at.slice(0, 10)}
                          </div>
                        </div>
                        <div className="flex flex-wrap items-center gap-1.5">
                          <button
                            type="button"
                            onClick={() => handleLoadLicenseHistory(l.license_key)}
                            className="px-2.5 py-1 rounded bg-[#131C31] border border-[#2B3B5E] text-[#CBD5E1]"
                          >
                            History
                          </button>
                          {l.status !== 'active' && (
                            <button
                              type="button"
                              onClick={() => handleLicenseStatusChange(l.license_key, 'active')}
                              className="px-2.5 py-1 rounded bg-[#092420] border border-[#14B8A6]/40 text-[#99F6E4]"
                            >
                              Activate
                            </button>
                          )}
                          {l.status !== 'blocked' && (
                            <button
                              type="button"
                              onClick={() => handleLicenseStatusChange(l.license_key, 'blocked')}
                              className="px-2.5 py-1 rounded bg-[#131C31] border border-[#D4AF37] text-[#D4AF37]"
                            >
                              Block
                            </button>
                          )}
                          {l.status !== 'revoked' && (
                            <button
                              type="button"
                              onClick={() => handleLicenseStatusChange(l.license_key, 'revoked')}
                              className="px-2.5 py-1 rounded bg-[#2A1215] border border-[#7F1D1D] text-[#FCA5A5]"
                            >
                              Revoke
                            </button>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </section>

              {selectedHistoryKey && (
                <section className="bg-[#0E1525] border border-[#1F2C47] rounded-xl p-6 space-y-3">
                  <div className="flex items-center justify-between">
                    <h3 className="text-sm font-semibold text-[#F3F4F6] font-mono" dir="ltr">
                      Lifecycle History: {selectedHistoryKey}
                    </h3>
                    <button
                      type="button"
                      onClick={() => setSelectedHistoryKey(null)}
                      className="text-xs text-[#9CA3AF] hover:text-[#F3F4F6]"
                    >
                      Close
                    </button>
                  </div>
                  <div className="divide-y divide-[#1F2C47] text-xs font-mono" dir="ltr">
                    {licenseHistory.map((h) => (
                      <div key={h.id} className="py-2 flex flex-wrap justify-between gap-2">
                        <span className="text-[#2DD4BF]">{h.action}</span>
                        <span className="text-[#CBD5E1]">
                          {h.previous_status ?? '-'} → {h.new_status ?? '-'}
                        </span>
                        <span className="text-[#9CA3AF]">{h.reason ?? ''}</span>
                        <span className="text-[#64748B]">{h.created_at.slice(0, 19)}</span>
                      </div>
                    ))}
                  </div>
                </section>
              )}
            </div>
          )}

          {tab === 'plans' && (
            <section className="bg-[#0E1525] border border-[#1F2C47] rounded-xl overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-[#1F2C47] text-xs text-[#9CA3AF] bg-[#0A0F1D]">
                      <th className="px-5 py-3 text-start font-medium">Code</th>
                      <th className="px-5 py-3 text-start font-medium">Name (EN / FA)</th>
                      <th className="px-5 py-3 text-end font-medium">Days</th>
                      <th className="px-5 py-3 text-end font-medium">Devices</th>
                      <th className="px-5 py-3 text-end font-medium">Price (USDC)</th>
                      <th className="px-5 py-3 text-end font-medium">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1F2C47]">
                    {plans.map((p) => (
                      <tr key={p.id}>
                        <td className="px-5 py-3 font-mono text-xs text-[#2DD4BF]" dir="ltr">
                          {p.code}
                        </td>
                        <td className="px-5 py-3 text-[#F3F4F6]">
                          {p.name_en} · {p.name_fa}
                        </td>
                        <td className="px-5 py-3 text-end font-mono tabular-nums text-[#CBD5E1]">
                          {p.duration_days}
                        </td>
                        <td className="px-5 py-3 text-end font-mono tabular-nums text-[#CBD5E1]">
                          {p.max_devices}
                        </td>
                        <td className="px-5 py-3 text-end font-mono tabular-nums font-semibold text-[#D4AF37]" dir="ltr">
                          ${p.price_usd_display}
                        </td>
                        <td className="px-5 py-3 text-end">
                          <button
                            type="button"
                            onClick={() => handleTogglePlan(p)}
                            className={`px-2.5 py-1 rounded text-xs font-mono border ${
                              p.is_active === 1
                                ? 'bg-[#092420] border-[#14B8A6]/40 text-[#99F6E4]'
                                : 'bg-[#2A1215] border-[#7F1D1D] text-[#FCA5A5]'
                            }`}
                          >
                            {p.is_active === 1 ? 'active' : 'paused'}
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}

          {tab === 'finance' && finance && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div className="bg-[#0E1525] border border-[#1F2C47] rounded-xl p-5">
                  <div className="text-xs text-[#9CA3AF]">Confirmed Revenue</div>
                  <div className="mt-2 text-2xl font-bold font-mono tabular-nums text-[#D4AF37]" dir="ltr">
                    ${finance.totals.confirmedRevenueUsd} USDC
                  </div>
                </div>
                <div className="bg-[#0E1525] border border-[#1F2C47] rounded-xl p-5">
                  <div className="text-xs text-[#9CA3AF]">Confirmed Payments</div>
                  <div className="mt-2 text-2xl font-bold font-mono tabular-nums text-[#2DD4BF]">
                    {finance.totals.confirmedPayments}
                  </div>
                </div>
                <div className="bg-[#0E1525] border border-[#1F2C47] rounded-xl p-5">
                  <div className="text-xs text-[#9CA3AF]">Dry-Run Submissions</div>
                  <div className="mt-2 text-2xl font-bold font-mono tabular-nums text-[#F3F4F6]">
                    {finance.totals.dryRunSubmissions}
                  </div>
                </div>
              </div>

              <section className="bg-[#0E1525] border border-[#1F2C47] rounded-xl overflow-hidden">
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-[#1F2C47] text-xs text-[#9CA3AF] bg-[#0A0F1D]">
                        <th className="px-5 py-3 text-start font-medium">Plan</th>
                        <th className="px-5 py-3 text-end font-medium">Unit Price</th>
                        <th className="px-5 py-3 text-end font-medium">Orders</th>
                        <th className="px-5 py-3 text-end font-medium">Confirmed</th>
                        <th className="px-5 py-3 text-end font-medium">Net USDC</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#1F2C47]">
                      {finance.byPlan.map((row) => (
                        <tr key={row.plan_code}>
                          <td className="px-5 py-3 font-mono text-xs text-[#F3F4F6]" dir="ltr">
                            {row.plan_code} ({row.name_en})
                          </td>
                          <td className="px-5 py-3 text-end font-mono tabular-nums text-[#CBD5E1]" dir="ltr">
                            ${row.price_usd_display}
                          </td>
                          <td className="px-5 py-3 text-end font-mono tabular-nums text-[#CBD5E1]">
                            {row.orders_count}
                          </td>
                          <td className="px-5 py-3 text-end font-mono tabular-nums text-[#2DD4BF]">
                            {row.confirmed_payments_count}
                          </td>
                          <td className="px-5 py-3 text-end font-mono tabular-nums text-[#D4AF37]" dir="ltr">
                            ${(row.confirmed_usdc_micro / 1_000_000).toFixed(2)}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>
            </div>
          )}

          {tab === 'security' && (
            <section className="bg-[#0E1525] border border-[#1F2C47] rounded-xl overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-[#1F2C47] text-xs text-[#9CA3AF] bg-[#0A0F1D]">
                      <th className="px-5 py-3 text-start font-medium">Time (UTC)</th>
                      <th className="px-5 py-3 text-start font-medium">Action</th>
                      <th className="px-5 py-3 text-start font-medium">Actor</th>
                      <th className="px-5 py-3 text-start font-medium">Entity</th>
                      <th className="px-5 py-3 text-start font-medium">Severity</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1F2C47]">
                    {auditLogs.length === 0 ? (
                      <tr>
                        <td colSpan={5} className="px-5 py-6 text-sm text-[#9CA3AF]">
                          No audit events recorded yet.
                        </td>
                      </tr>
                    ) : (
                      auditLogs.map((log) => (
                        <tr key={log.id} className="hover:bg-[#131C31]/60">
                          <td className="px-5 py-3 font-mono text-xs text-[#9CA3AF]" dir="ltr">
                            {log.created_at.slice(0, 19).replace('T', ' ')}
                          </td>
                          <td className="px-5 py-3 font-mono text-xs text-[#F3F4F6]" dir="ltr">
                            {log.action}
                          </td>
                          <td className="px-5 py-3 font-mono text-xs text-[#CBD5E1]" dir="ltr">
                            {log.actor_type}:{log.actor_id}
                          </td>
                          <td className="px-5 py-3 font-mono text-xs text-[#9CA3AF]" dir="ltr">
                            {log.entity_type} {log.entity_id ?? ''}
                          </td>
                          <td
                            className={`px-5 py-3 font-mono text-xs ${
                              log.severity === 'critical'
                                ? 'text-[#F87171]'
                                : log.severity === 'warning'
                                ? 'text-[#D4AF37]'
                                : 'text-[#2DD4BF]'
                            }`}
                            dir="ltr"
                          >
                            {log.severity}
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </section>
          )}

          {tab === 'tickets' && (
            <section className="bg-[#0E1525] border border-[#1F2C47] rounded-xl p-6 space-y-4">
              <h2 className="text-base font-semibold text-[#F3F4F6]">
                Support Tickets ({tickets.length})
              </h2>
              {tickets.length === 0 ? (
                <p className="text-sm text-[#9CA3AF]">No support tickets opened yet.</p>
              ) : (
                <div className="divide-y divide-[#1F2C47]">
                  {tickets.map((tk) => (
                    <div key={tk.id} className="py-4 space-y-3">
                      <div className="flex flex-wrap items-center justify-between gap-2 text-xs font-mono" dir="ltr">
                        <span className="text-[#D4AF37] font-semibold">
                          #{tk.id} · {tk.subject}
                        </span>
                        <span className="text-[#2DD4BF]">
                          {tk.status} · priority: {tk.priority}
                        </span>
                      </div>
                      <p className="text-xs text-[#CBD5E1] leading-relaxed">{tk.message}</p>
                      {tk.admin_reply && (
                        <div className="p-2.5 rounded bg-[#07090F] border border-[#1F2C47] text-xs text-[#99F6E4]">
                          Reply: {tk.admin_reply}
                        </div>
                      )}
                      <div className="flex flex-col sm:flex-row gap-2">
                        <input
                          type="text"
                          value={ticketReplies[tk.id] ?? ''}
                          onChange={(e) =>
                            setTicketReplies((prev) => ({ ...prev, [tk.id]: e.target.value }))
                          }
                          placeholder="Admin reply..."
                          className="flex-1 px-3 py-1.5 rounded bg-[#07090F] border border-[#1F2C47] text-xs text-[#F3F4F6]"
                        />
                        <button
                          type="button"
                          onClick={() => handleReplyTicket(tk.id, 'resolved')}
                          className="px-3 py-1.5 rounded bg-[#D4AF37] text-[#07090F] text-xs font-semibold whitespace-nowrap"
                        >
                          Reply & Resolve
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </section>
          )}

          {tab === 'admins' && (
            <div className="space-y-6">
              {/* Role Assignment Form */}
              {adminRole === 'super_admin' && (
                <section className="bg-[#0E1525] border border-[#1F2C47] rounded-xl p-6 space-y-4">
                  <h2 className="text-base font-semibold text-[#F3F4F6]">
                    Assign Admin Role (Audited)
                  </h2>
                  <form
                    onSubmit={handleAssignAdmin}
                    className="flex flex-col sm:flex-row gap-3 items-stretch sm:items-end"
                  >
                    <div className="flex-1 space-y-1">
                      <label className="text-xs text-[#9CA3AF]" htmlFor="adminTgId">
                        Registered Telegram ID
                      </label>
                      <input
                        id="adminTgId"
                        type="text"
                        dir="ltr"
                        value={newAdminTgId}
                        onChange={(e) => setNewAdminTgId(e.target.value)}
                        placeholder="e.g. 900000001"
                        required
                        className="w-full px-3 py-2 rounded-lg bg-[#07090F] border border-[#1F2C47] text-xs font-mono text-[#F3F4F6]"
                      />
                    </div>
                    <div className="w-full sm:w-44 space-y-1">
                      <label className="text-xs text-[#9CA3AF]" htmlFor="adminRoleSelect">
                        Role
                      </label>
                      <select
                        id="adminRoleSelect"
                        value={newAdminRole}
                        onChange={(e) => setNewAdminRole(e.target.value as AdminRole)}
                        className="w-full px-3 py-2 rounded-lg bg-[#07090F] border border-[#1F2C47] text-xs font-mono text-[#F3F4F6]"
                      >
                        <option value="super_admin">super_admin</option>
                        <option value="admin">admin</option>
                        <option value="finance">finance</option>
                        <option value="support">support</option>
                        <option value="auditor">auditor</option>
                      </select>
                    </div>
                    <button
                      type="submit"
                      className="px-4 py-2 rounded-lg bg-[#D4AF37] hover:bg-[#E5C454] text-[#07090F] text-xs font-semibold whitespace-nowrap"
                    >
                      Save Role
                    </button>
                  </form>
                </section>
              )}

              {/* Active Admins Table */}
              <section className="bg-[#0E1525] border border-[#1F2C47] rounded-xl overflow-hidden">
                <div className="px-6 py-4 border-b border-[#1F2C47]">
                  <h2 className="text-base font-semibold text-[#F3F4F6]">Active Admins</h2>
                </div>
                <div className="divide-y divide-[#1F2C47]">
                  {admins.map((a) => (
                    <div
                      key={a.id}
                      className="px-6 py-3.5 flex flex-wrap items-center justify-between gap-3 text-xs font-mono"
                      dir="ltr"
                    >
                      <span className="text-[#F3F4F6]">
                        {a.first_name} ({a.telegram_id})
                      </span>
                      <div className="flex items-center gap-3">
                        <span className="text-[#D4AF37]">
                          {a.role} {a.is_active === 1 ? '' : '(inactive)'}
                        </span>
                        {adminRole === 'super_admin' && a.is_active === 1 && (
                          <button
                            type="button"
                            onClick={() => handleDeactivateAdmin(a.id)}
                            className="px-2 py-1 rounded bg-[#2A1215] border border-[#7F1D1D] text-[#FCA5A5]"
                          >
                            Deactivate
                          </button>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </section>

              {/* System Settings Table */}
              <section className="bg-[#0E1525] border border-[#1F2C47] rounded-xl overflow-hidden">
                <div className="px-6 py-4 border-b border-[#1F2C47]">
                  <h2 className="text-base font-semibold text-[#F3F4F6]">
                    SQLite System Settings
                  </h2>
                </div>
                <div className="divide-y divide-[#1F2C47]">
                  {settings.map((s) => (
                    <div
                      key={s.key}
                      className="px-6 py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs"
                    >
                      <div>
                        <div className="font-mono text-[#F3F4F6]" dir="ltr">
                          {s.key}{' '}
                          {s.is_immutable === 1 && (
                            <span className="text-[#D4AF37]">· immutable (DB Trigger)</span>
                          )}
                        </div>
                        <div className="text-[#9CA3AF]">{s.description}</div>
                      </div>
                      <code className="font-mono text-[#2DD4BF] break-all" dir="ltr">
                        {s.value}
                      </code>
                    </div>
                  ))}
                </div>
              </section>
            </div>
          )}
        </>
      )}
    </div>
  );
}
