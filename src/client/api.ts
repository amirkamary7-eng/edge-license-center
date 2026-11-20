import type {
  AdminDashboardSummary,
  AdminRecord,
  AdminRole,
  AuditLogRecord,
  AuthSessionResponse,
  DeviceRecord,
  LicenseHistoryRecord,
  LicenseRecord,
  OrderRecord,
  OrderType,
  PaymentRecord,
  PlanRecord,
  SubscriptionRecord,
  SupportTicketRecord,
  SystemSettingRecord,
  TicketPriority,
  TicketStatus,
  UserRecord,
  UserStatus,
} from '../shared/types';

declare global {
  interface Window {
    Telegram?: {
      WebApp?: {
        initData?: string;
        ready?: () => void;
        expand?: () => void;
        themeParams?: Record<string, string>;
      };
    };
  }
}

export interface PublicConfigResponse {
  brandName: string;
  brandOwner: string;
  botHandle: string;
  phase: string;
  paymentMode: string;
  licenseMode: string;
  network: {
    name: string;
    chainId: number;
    currencySymbol: string;
    tokenStandard: string;
    usdcContractAddress: string;
    destinationWalletAddress: string;
    minConfirmations: number;
  };
  plans: PlanRecord[];
}

export interface FinancialReportResponse {
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
}

let activeBearerToken: string | null = null;

function getTelegramInitData(): string {
  return window.Telegram?.WebApp?.initData ?? '';
}

function generateIdempotencyKey(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  return `idem-${Date.now()}-${Math.random().toString(16).slice(2, 12)}`;
}

async function requestJson<T>(
  path: string,
  init?: RequestInit & { idempotent?: boolean }
): Promise<T> {
  const headers = new Headers(init?.headers);
  headers.set('Content-Type', 'application/json');

  if (activeBearerToken) {
    headers.set('Authorization', `Bearer ${activeBearerToken}`);
  } else {
    const initData = getTelegramInitData();
    if (initData) {
      headers.set('X-Telegram-Init-Data', initData);
    }
  }

  if (init?.idempotent && !headers.has('Idempotency-Key')) {
    headers.set('Idempotency-Key', generateIdempotencyKey());
  }

  const res = await fetch(path, { ...init, headers });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const message =
      (data as { message?: string; error?: string }).message ??
      (data as { error?: string }).error ??
      `HTTP_${res.status}`;
    const err = new Error(message) as Error & { status?: number; code?: string };
    err.status = res.status;
    err.code = (data as { error?: string }).error;
    throw err;
  }
  return data as T;
}

export const apiClient = {
  getPublicConfig: () => requestJson<PublicConfigResponse>('/api/v1/public/config'),

  exchangeTelegramSession: async (): Promise<boolean> => {
    const initData = getTelegramInitData();
    if (!initData || activeBearerToken) return Boolean(activeBearerToken);
    try {
      const res = await requestJson<{ token: string; expiresAt: string }>('/api/v1/auth/telegram', {
        method: 'POST',
        body: JSON.stringify({ initData }),
      });
      activeBearerToken = res.token;
      return true;
    } catch {
      return false;
    }
  },

  getSession: () => requestJson<AuthSessionResponse>('/api/v1/me'),
  listOrders: () => requestJson<{ orders: OrderRecord[] }>('/api/v1/orders'),
  createOrder: (
    planCode: string,
    opts?: {
      orderType?: OrderType;
      targetSubscriptionId?: number;
      expectedSenderWallet?: string;
    }
  ) =>
    requestJson<{ order: OrderRecord }>('/api/v1/orders', {
      method: 'POST',
      idempotent: true,
      body: JSON.stringify({ planCode, ...opts }),
    }),
  listPayments: () => requestJson<{ payments: PaymentRecord[] }>('/api/v1/payments'),
  submitTx: (orderCode: string, txHash: string) =>
    requestJson<{ payment: PaymentRecord; order: OrderRecord; dryRunBlocked: boolean }>(
      '/api/v1/payments/submit-tx',
      {
        method: 'POST',
        idempotent: true,
        body: JSON.stringify({ orderCode, txHash }),
      }
    ),
  listLicenses: () =>
    requestJson<{
      licenses: Array<LicenseRecord & { devices: DeviceRecord[] }>;
      subscriptions: SubscriptionRecord[];
    }>('/api/v1/licenses'),
  unbindDevice: (licenseKey: string, fingerprint: string) =>
    requestJson<{ unbound: boolean }>(
      `/api/v1/licenses/${encodeURIComponent(licenseKey)}/devices/${encodeURIComponent(fingerprint)}`,
      { method: 'DELETE' }
    ),
  listTickets: () => requestJson<{ tickets: SupportTicketRecord[] }>('/api/v1/support/tickets'),
  createTicket: (payload: {
    subject: string;
    message: string;
    orderId?: number;
    priority?: TicketPriority;
  }) =>
    requestJson<{ ticket: SupportTicketRecord }>('/api/v1/support/tickets', {
      method: 'POST',
      idempotent: true,
      body: JSON.stringify(payload),
    }),

  admin: {
    getDashboard: () => requestJson<{ summary: AdminDashboardSummary }>('/api/v1/admin/dashboard'),
    listUsers: () => requestJson<{ users: UserRecord[] }>('/api/v1/admin/users'),
    updateUserStatus: (userId: number, status: UserStatus) =>
      requestJson<{ user: UserRecord }>(`/api/v1/admin/users/${userId}/status`, {
        method: 'PATCH',
        body: JSON.stringify({ status }),
      }),
    listOrders: () => requestJson<{ orders: OrderRecord[] }>('/api/v1/admin/orders'),
    updateOrderStatus: (
      orderCode: string,
      status: 'cancelled' | 'rejected' | 'expired',
      reason: string
    ) =>
      requestJson<{ order: OrderRecord }>(
        `/api/v1/admin/orders/${encodeURIComponent(orderCode)}/status`,
        {
          method: 'PATCH',
          body: JSON.stringify({ status, reason }),
        }
      ),
    listPayments: () => requestJson<{ payments: PaymentRecord[] }>('/api/v1/admin/payments'),
    verifyPaymentOnChain: (paymentId: number) =>
      requestJson<{
        payment: PaymentRecord;
        order: OrderRecord;
        verification: { valid: boolean; reason?: string };
        licenseKey?: string;
      }>(`/api/v1/admin/payments/${paymentId}/verify`, {
        method: 'POST',
      }),
    listSubscriptions: () =>
      requestJson<{ subscriptions: SubscriptionRecord[] }>('/api/v1/admin/subscriptions'),
    listLicenses: () => requestJson<{ licenses: LicenseRecord[] }>('/api/v1/admin/licenses'),
    listLicenseHistory: (licenseKey: string) =>
      requestJson<{ history: LicenseHistoryRecord[] }>(
        `/api/v1/admin/licenses/${encodeURIComponent(licenseKey)}/history`
      ),
    updateLicenseStatus: (
      licenseKey: string,
      status: 'active' | 'revoked' | 'blocked',
      reason: string
    ) =>
      requestJson<{ license: LicenseRecord }>(
        `/api/v1/admin/licenses/${encodeURIComponent(licenseKey)}/status`,
        {
          method: 'PATCH',
          body: JSON.stringify({ status, reason }),
        }
      ),
    unbindDevice: (licenseKey: string, fingerprint: string) =>
      requestJson<{ unbound: boolean }>(
        `/api/v1/admin/licenses/${encodeURIComponent(licenseKey)}/devices/${encodeURIComponent(fingerprint)}`,
        { method: 'DELETE' }
      ),
    listPlans: () => requestJson<{ plans: PlanRecord[] }>('/api/v1/admin/plans'),
    updatePlanControls: (
      code: string,
      patch: { isActive?: boolean; maxDevices?: number }
    ) =>
      requestJson<{ plan: PlanRecord }>(`/api/v1/admin/plans/${encodeURIComponent(code)}`, {
        method: 'PATCH',
        body: JSON.stringify(patch),
      }),
    getFinancialReport: () => requestJson<FinancialReportResponse>('/api/v1/admin/reports/finance'),
    getSecurityLogs: () =>
      requestJson<{ auditLogs: AuditLogRecord[] }>('/api/v1/admin/reports/security'),
    listTickets: () => requestJson<{ tickets: SupportTicketRecord[] }>('/api/v1/admin/tickets'),
    replyTicket: (ticketId: number, status: TicketStatus, adminReply?: string) =>
      requestJson<{ ticket: SupportTicketRecord }>(`/api/v1/admin/tickets/${ticketId}`, {
        method: 'PATCH',
        body: JSON.stringify({ status, adminReply }),
      }),
    listAdminsAndSettings: () =>
      requestJson<{
        admins: Array<AdminRecord & { username: string | null; first_name: string }>;
        settings: SystemSettingRecord[];
      }>('/api/v1/admin/admins'),
    assignAdminRole: (telegramId: string, role: AdminRole) =>
      requestJson<{ admin: AdminRecord }>('/api/v1/admin/admins', {
        method: 'POST',
        idempotent: true,
        body: JSON.stringify({ telegramId, role }),
      }),
    deactivateAdmin: (adminId: number) =>
      requestJson<{ admin: AdminRecord }>(`/api/v1/admin/admins/${adminId}/deactivate`, {
        method: 'PATCH',
      }),
    updateSetting: (key: string, value: string) =>
      requestJson<{ setting: SystemSettingRecord }>(
        `/api/v1/admin/settings/${encodeURIComponent(key)}`,
        {
          method: 'PATCH',
          body: JSON.stringify({ value }),
        }
      ),
  },
};
