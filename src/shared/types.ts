export type AdminRole = 'super_admin' | 'admin' | 'finance' | 'support' | 'auditor';

export type UserStatus = 'active' | 'suspended' | 'banned';

export type OrderType = 'new' | 'renew' | 'upgrade';

export type OrderStatus =
  | 'draft_phase0'
  | 'pending_payment'
  | 'tx_submitted'
  | 'verifying'
  | 'confirmed'
  | 'expired'
  | 'rejected'
  | 'cancelled';

export type PaymentStatus =
  | 'submitted'
  | 'dry_run_recorded'
  | 'verifying'
  | 'confirmed'
  | 'failed'
  | 'duplicate_rejected';

export type SubscriptionStatus = 'active' | 'expired' | 'revoked' | 'suspended';

export type LicenseStatus = 'active' | 'expired' | 'revoked' | 'blocked';

export type DeviceStatus = 'active' | 'revoked' | 'blocked';

export type TicketStatus = 'open' | 'in_progress' | 'resolved' | 'closed';

export type TicketPriority = 'low' | 'normal' | 'high' | 'urgent';

export type NotificationChannel = 'telegram_bot' | 'mini_app' | 'admin_alert';

export type NotificationStatus = 'pending' | 'sent' | 'failed' | 'read';

export interface UserRecord {
  id: number;
  telegram_id: string;
  username: string | null;
  first_name: string;
  last_name: string | null;
  language_code: string;
  status: UserStatus;
  created_at: string;
  updated_at: string;
  last_seen_at: string | null;
}

export interface AdminRecord {
  id: number;
  user_id: number;
  telegram_id: string;
  role: AdminRole;
  permissions_json: string;
  is_active: number;
  granted_by: number | null;
  created_at: string;
  updated_at: string;
}

export interface PlanRecord {
  id: number;
  code: string;
  name_en: string;
  name_fa: string;
  duration_months: number;
  duration_days: number;
  price_usdc_micro: number;
  price_usd_display: string;
  max_devices: number;
  is_active: number;
  sort_order: number;
  created_at: string;
  updated_at: string;
}

export interface OrderRecord {
  id: number;
  order_code: string;
  user_id: number;
  plan_id: number;
  plan_code?: string;
  plan_name_en?: string;
  plan_name_fa?: string;
  order_type?: OrderType;
  target_subscription_id?: number | null;
  expected_amount_usdc_micro: number;
  unique_offset_micro?: number;
  payable_amount_usdc_micro?: number;
  expected_amount_usd: string;
  expected_sender_wallet?: string | null;
  network: string;
  token_contract: string;
  destination_wallet: string;
  status: OrderStatus;
  expires_at: string;
  created_at: string;
  updated_at: string;
}

export interface PaymentRecord {
  id: number;
  order_id: number;
  order_code?: string;
  user_id: number;
  tx_hash: string;
  network: string;
  token_contract: string;
  sender_address: string | null;
  receiver_address: string;
  amount_usdc_micro: number;
  block_number: number | null;
  confirmations: number;
  status: PaymentStatus;
  verification_note: string | null;
  verified_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface SubscriptionRecord {
  id: number;
  user_id: number;
  plan_id: number;
  order_id: number | null;
  status: SubscriptionStatus;
  starts_at: string;
  expires_at: string;
  auto_renew_reminded: number;
  created_at: string;
  updated_at: string;
}

export interface LicenseRecord {
  id: number;
  license_key: string;
  subscription_id: number;
  user_id: number;
  rsa_key_id: string;
  payload_json: string;
  signature_base64: string;
  status: LicenseStatus;
  max_devices: number;
  issued_at: string;
  expires_at: string;
  revoked_at: string | null;
  revoke_reason: string | null;
  last_validated_at: string | null;
  updated_at?: string | null;
}

export interface LicenseHistoryRecord {
  id: number;
  license_id: number;
  action: string;
  previous_status: string | null;
  new_status: string | null;
  actor_type: 'user' | 'admin' | 'system' | 'bot' | 'gateway';
  actor_id: string;
  reason: string | null;
  metadata_json: string;
  created_at: string;
}

export interface DeviceRecord {
  id: number;
  license_id: number;
  user_id: number;
  device_fingerprint: string;
  device_model: string | null;
  android_version: string | null;
  app_version: string | null;
  status: DeviceStatus;
  first_bound_at: string;
  last_seen_at: string;
}

export interface AuditLogRecord {
  id: number;
  actor_type: 'user' | 'admin' | 'system' | 'bot' | 'gateway';
  actor_id: string;
  action: string;
  entity_type: string;
  entity_id: string | null;
  severity: 'info' | 'warning' | 'critical';
  metadata_json: string;
  ip_address: string | null;
  created_at: string;
}

export interface SystemSettingRecord {
  key: string;
  value: string;
  description: string;
  is_immutable: number;
  updated_by: string | null;
  updated_at: string;
}

export interface SupportTicketRecord {
  id: number;
  ticket_code: string;
  user_id: number;
  order_id: number | null;
  subject: string;
  message: string;
  status: TicketStatus;
  priority: TicketPriority;
  assigned_admin_id: number | null;
  admin_reply: string | null;
  created_at: string;
  updated_at: string;
  closed_at: string | null;
}

export interface NotificationRecord {
  id: number;
  user_id: number;
  channel: NotificationChannel;
  type: string;
  title: string;
  body: string;
  status: NotificationStatus;
  attempts: number;
  last_error: string | null;
  sent_at: string | null;
  created_at: string;
}

export interface IdempotencyRecord {
  scope: string;
  idempotency_key: string;
  actor_id: string;
  request_hash: string;
  response_status: number;
  response_body_json: string;
  created_at: string;
  expires_at: string;
}

export interface AuthSessionResponse {
  authenticated: boolean;
  authMode: 'telegram_init_data' | 'bearer_session' | 'phase0_preview';
  phase: string;
  paymentMode: string;
  licenseMode: string;
  user: UserRecord;
  adminRole: AdminRole | null;
  permissions: string[];
}

export interface AdminDashboardSummary {
  totalUsers: number;
  activeAdmins: number;
  totalOrders: number;
  pendingOrders: number;
  totalPayments: number;
  confirmedRevenueUsdcMicro: number;
  confirmedRevenueUsd: string;
  activeSubscriptions: number;
  activeLicenses: number;
  revokedOrBlockedLicenses: number;
  boundDevices: number;
  securityEventsLast24h: number;
  openTickets?: number;
}
