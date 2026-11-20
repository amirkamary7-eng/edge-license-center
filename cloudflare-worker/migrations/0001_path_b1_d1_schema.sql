-- ============================================================================
-- Cloudflare D1 Migration 0001: Path B-1 Primary Authoritative Schema
-- EDGE LICENSE CENTER by AMIRBTC (@EDGE_LicenceBot)
-- Engine: Cloudflare D1 (SQLite 3 with PRAGMA foreign_keys = ON)
-- Forward-only, auditable migration preserving all Phase 0/1 tables + Path B-1
-- security/audit/device-key/revocation/cron/backup entities.
-- ============================================================================

PRAGMA foreign_keys = ON;

-- 1. users
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  telegram_id TEXT NOT NULL UNIQUE,
  username TEXT,
  first_name TEXT NOT NULL,
  last_name TEXT,
  language_code TEXT NOT NULL DEFAULT 'fa',
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'banned')),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  last_seen_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

-- 2. admins
CREATE TABLE IF NOT EXISTS admins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE RESTRICT,
  telegram_id TEXT NOT NULL UNIQUE,
  role TEXT NOT NULL CHECK (role IN ('super_admin', 'admin', 'finance', 'support', 'auditor')),
  permissions_json TEXT NOT NULL DEFAULT '[]',
  is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
  granted_by INTEGER REFERENCES admins(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_admins_role_active ON admins(role, is_active);

-- 3. plans
CREATE TABLE IF NOT EXISTS plans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT NOT NULL UNIQUE,
  name_en TEXT NOT NULL,
  name_fa TEXT NOT NULL,
  duration_months INTEGER NOT NULL CHECK (duration_months > 0),
  duration_days INTEGER NOT NULL CHECK (duration_days > 0),
  price_usdc_micro INTEGER NOT NULL CHECK (price_usdc_micro > 0),
  price_usd_display TEXT NOT NULL,
  max_devices INTEGER NOT NULL DEFAULT 1 CHECK (max_devices >= 1),
  is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
  sort_order INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_plans_active_sort ON plans(is_active, sort_order);

-- 4. subscriptions (created ahead of orders FK reference compatibility)
CREATE TABLE IF NOT EXISTS subscriptions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  plan_id INTEGER NOT NULL REFERENCES plans(id) ON DELETE RESTRICT,
  order_id INTEGER,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'expired', 'revoked', 'suspended')),
  starts_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  auto_renew_reminded INTEGER NOT NULL DEFAULT 0 CHECK (auto_renew_reminded IN (0, 1)),
  version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  CHECK (expires_at > starts_at)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_subscriptions_unique_order_id
  ON subscriptions(order_id)
  WHERE order_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_subscriptions_user_status ON subscriptions(user_id, status);
CREATE INDEX IF NOT EXISTS idx_subscriptions_expires ON subscriptions(expires_at);

-- 5. orders
CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_code TEXT NOT NULL UNIQUE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  plan_id INTEGER NOT NULL REFERENCES plans(id) ON DELETE RESTRICT,
  order_type TEXT NOT NULL DEFAULT 'new' CHECK (order_type IN ('new', 'renew', 'upgrade')),
  target_subscription_id INTEGER REFERENCES subscriptions(id) ON DELETE SET NULL,
  expected_amount_usdc_micro INTEGER NOT NULL CHECK (expected_amount_usdc_micro > 0),
  unique_offset_micro INTEGER NOT NULL DEFAULT 0 CHECK (unique_offset_micro >= 0 AND unique_offset_micro <= 999),
  payable_amount_usdc_micro INTEGER NOT NULL CHECK (payable_amount_usdc_micro > 0),
  expected_amount_usd TEXT NOT NULL,
  expected_sender_wallet TEXT,
  network TEXT NOT NULL DEFAULT 'polygon_pos',
  token_contract TEXT NOT NULL,
  destination_wallet TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending_payment' CHECK (
    status IN (
      'draft_phase0',
      'pending_payment',
      'tx_submitted',
      'verifying',
      'confirmed',
      'expired',
      'rejected',
      'cancelled'
    )
  ),
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_orders_active_payable_amount
  ON orders(payable_amount_usdc_micro)
  WHERE status IN ('draft_phase0', 'pending_payment', 'tx_submitted', 'verifying');
CREATE INDEX IF NOT EXISTS idx_orders_user_status ON orders(user_id, status);
CREATE INDEX IF NOT EXISTS idx_orders_status_expires ON orders(status, expires_at);

-- 6. payments (DB-level TxID uniqueness + single active payment per order)
CREATE TABLE IF NOT EXISTS payments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id INTEGER NOT NULL REFERENCES orders(id) ON DELETE RESTRICT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  tx_hash TEXT NOT NULL UNIQUE COLLATE NOCASE,
  network TEXT NOT NULL DEFAULT 'polygon_pos',
  token_contract TEXT NOT NULL,
  sender_address TEXT,
  receiver_address TEXT NOT NULL,
  amount_usdc_micro INTEGER NOT NULL CHECK (amount_usdc_micro >= 0),
  block_number INTEGER,
  confirmations INTEGER NOT NULL DEFAULT 0 CHECK (confirmations >= 0),
  status TEXT NOT NULL DEFAULT 'submitted' CHECK (
    status IN (
      'submitted',
      'dry_run_recorded',
      'verifying',
      'confirmed',
      'failed',
      'duplicate_rejected'
    )
  ),
  verification_note TEXT,
  verified_at TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_payments_one_active_per_order
  ON payments(order_id)
  WHERE status IN ('submitted', 'dry_run_recorded', 'verifying', 'confirmed');
CREATE INDEX IF NOT EXISTS idx_payments_order ON payments(order_id);
CREATE INDEX IF NOT EXISTS idx_payments_user_status ON payments(user_id, status);
CREATE INDEX IF NOT EXISTS idx_payments_status ON payments(status);

-- 7. subscription_events
CREATE TABLE IF NOT EXISTS subscription_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  subscription_id INTEGER NOT NULL REFERENCES subscriptions(id) ON DELETE RESTRICT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  event_type TEXT NOT NULL CHECK (
    event_type IN (
      'CREATED',
      'RENEWED',
      'UPGRADED',
      'EXPIRED_AUTO',
      'SUSPENDED',
      'REVOKED',
      'REACTIVATED',
      'AUDIT_ANOMALY'
    )
  ),
  previous_status TEXT,
  new_status TEXT NOT NULL,
  actor_type TEXT NOT NULL CHECK (actor_type IN ('user', 'admin', 'system', 'bot', 'gateway', 'cron')),
  actor_id TEXT NOT NULL,
  reason TEXT,
  metadata_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_subscription_events_sub ON subscription_events(subscription_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_subscription_events_user ON subscription_events(user_id, created_at DESC);

-- 8. licenses
CREATE TABLE IF NOT EXISTS licenses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  license_key TEXT NOT NULL UNIQUE,
  subscription_id INTEGER NOT NULL UNIQUE REFERENCES subscriptions(id) ON DELETE RESTRICT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  rsa_key_id TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  signature_base64 TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'expired', 'revoked', 'blocked')),
  max_devices INTEGER NOT NULL DEFAULT 1 CHECK (max_devices >= 1),
  offline_grace_hours INTEGER NOT NULL DEFAULT 72 CHECK (offline_grace_hours >= 0 AND offline_grace_hours <= 168),
  revocation_epoch INTEGER NOT NULL DEFAULT 0 CHECK (revocation_epoch >= 0),
  version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
  issued_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  expires_at TEXT NOT NULL,
  revoked_at TEXT,
  revoke_reason TEXT,
  last_validated_at TEXT,
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_licenses_user_status ON licenses(user_id, status);
CREATE INDEX IF NOT EXISTS idx_licenses_status_expires ON licenses(status, expires_at);

-- 9. license_history
CREATE TABLE IF NOT EXISTS license_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  license_id INTEGER NOT NULL REFERENCES licenses(id) ON DELETE RESTRICT,
  action TEXT NOT NULL,
  previous_status TEXT,
  new_status TEXT,
  actor_type TEXT NOT NULL CHECK (actor_type IN ('user', 'admin', 'system', 'bot', 'gateway', 'cron')),
  actor_id TEXT NOT NULL,
  reason TEXT,
  metadata_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_license_history_license ON license_history(license_id, id DESC);

-- 10. devices (Android Keystore ECDSA P-256 public-key binding; zero APK HMAC secrets)
CREATE TABLE IF NOT EXISTS devices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  license_id INTEGER NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  device_fingerprint TEXT NOT NULL,
  device_key_id TEXT NOT NULL,
  device_public_key_spki TEXT NOT NULL,
  attestation_level TEXT NOT NULL DEFAULT 'tee' CHECK (attestation_level IN ('strongbox', 'tee', 'software')),
  device_model TEXT,
  android_version TEXT,
  app_version TEXT,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked', 'blocked')),
  first_bound_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  last_seen_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  UNIQUE(license_id, device_fingerprint),
  UNIQUE(license_id, device_key_id)
);

CREATE INDEX IF NOT EXISTS idx_devices_user ON devices(user_id);
CREATE INDEX IF NOT EXISTS idx_devices_fingerprint ON devices(device_fingerprint);
CREATE INDEX IF NOT EXISTS idx_devices_key_id ON devices(device_key_id);

-- 11. device_sessions
CREATE TABLE IF NOT EXISTS device_sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  license_id INTEGER NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  session_nonce TEXT NOT NULL UNIQUE,
  client_ip_hash TEXT,
  app_version TEXT,
  last_server_time_utc TEXT NOT NULL,
  receipt_expires_at TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked', 'expired', 'flagged')),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_device_sessions_license_status ON device_sessions(license_id, status);
CREATE INDEX IF NOT EXISTS idx_device_sessions_device ON device_sessions(device_id, created_at DESC);

-- 12. activation_challenges (short-lived single-use nonces for Android Keystore PoP)
CREATE TABLE IF NOT EXISTS activation_challenges (
  challenge_id TEXT PRIMARY KEY,
  license_key TEXT NOT NULL,
  device_key_id TEXT NOT NULL,
  device_fingerprint TEXT NOT NULL,
  challenge_nonce TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  consumed_at TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_activation_challenges_expires ON activation_challenges(expires_at);

-- 13. revocations (monotonic sequence + state machine tracking)
CREATE TABLE IF NOT EXISTS revocations (
  revocation_seq INTEGER PRIMARY KEY AUTOINCREMENT,
  entity_type TEXT NOT NULL CHECK (entity_type IN ('license', 'device', 'user')),
  entity_id TEXT NOT NULL,
  license_key TEXT,
  reason_code TEXT NOT NULL,
  reason_detail TEXT,
  sync_state TEXT NOT NULL DEFAULT 'REVOCATION_ENFORCED_ONLINE' CHECK (
    sync_state IN (
      'REVOCATION_PENDING',
      'REVOCATION_ENFORCED_ONLINE',
      'TELEGRAM_SYNC_PENDING',
      'FULLY_SYNCHRONIZED'
    )
  ),
  actor_type TEXT NOT NULL CHECK (actor_type IN ('user', 'admin', 'system', 'bot', 'gateway', 'cron')),
  actor_id TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
  revoked_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  lifted_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_revocations_lookup ON revocations(entity_type, entity_id, active);
CREATE INDEX IF NOT EXISTS idx_revocations_active_seq ON revocations(active, revocation_seq DESC);

-- 14. notifications
CREATE TABLE IF NOT EXISTS notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  channel TEXT NOT NULL DEFAULT 'telegram_bot' CHECK (channel IN ('telegram_bot', 'mini_app', 'admin_alert')),
  type TEXT NOT NULL,
  dedupe_key TEXT UNIQUE,
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'sent', 'failed', 'read')),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  last_error TEXT,
  sent_at TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_notifications_user_status ON notifications(user_id, status);
CREATE INDEX IF NOT EXISTS idx_notifications_pending ON notifications(status, created_at);

-- 15. support_tickets
CREATE TABLE IF NOT EXISTS support_tickets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ticket_code TEXT NOT NULL UNIQUE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  order_id INTEGER REFERENCES orders(id) ON DELETE SET NULL,
  subject TEXT NOT NULL,
  message TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'in_progress', 'resolved', 'closed')),
  priority TEXT NOT NULL DEFAULT 'normal' CHECK (priority IN ('low', 'normal', 'high', 'urgent')),
  assigned_admin_id INTEGER REFERENCES admins(id) ON DELETE SET NULL,
  admin_reply TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  closed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_support_tickets_user_status ON support_tickets(user_id, status);
CREATE INDEX IF NOT EXISTS idx_support_tickets_status_priority ON support_tickets(status, priority);

-- 16. audit_logs
CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor_type TEXT NOT NULL CHECK (actor_type IN ('user', 'admin', 'system', 'bot', 'gateway', 'cron')),
  actor_id TEXT NOT NULL,
  action TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  entity_id TEXT,
  severity TEXT NOT NULL DEFAULT 'info' CHECK (severity IN ('info', 'warning', 'critical')),
  metadata_json TEXT NOT NULL DEFAULT '{}',
  ip_address TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_entity ON audit_logs(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_severity ON audit_logs(severity, created_at DESC);

-- 17. security_events
CREATE TABLE IF NOT EXISTS security_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type TEXT NOT NULL CHECK (
    event_type IN (
      'ECDSA_INVALID',
      'REPLAY_NONCE',
      'TIMESTAMP_SKEW',
      'CLOCK_ROLLBACK',
      'LOCAL_TAMPER',
      'SIGNATURE_MISMATCH',
      'DEVICE_LIMIT_ABUSE',
      'DEVICE_CHURN',
      'RATE_LIMITED',
      'UNAUTHORIZED_ADMIN',
      'WEBHOOK_AUTH_FAILED',
      'INIT_DATA_REPLAY',
      'INVALID_TX_ATTEMPT'
    )
  ),
  severity TEXT NOT NULL DEFAULT 'medium' CHECK (severity IN ('low', 'medium', 'high', 'critical')),
  user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  license_key TEXT,
  device_key_id TEXT,
  ip_hash TEXT,
  details_json TEXT NOT NULL DEFAULT '{}',
  source TEXT NOT NULL DEFAULT 'worker_gateway',
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_security_events_severity ON security_events(severity, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_license ON security_events(license_key, created_at DESC);

-- 18. idempotency_records
CREATE TABLE IF NOT EXISTS idempotency_records (
  scope TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  request_hash TEXT NOT NULL,
  response_status INTEGER NOT NULL,
  response_body_json TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  expires_at TEXT NOT NULL,
  PRIMARY KEY (scope, idempotency_key)
);

CREATE INDEX IF NOT EXISTS idx_idempotency_expires ON idempotency_records(expires_at);

-- 19. system_settings (with immutable protection triggers)
CREATE TABLE IF NOT EXISTS system_settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  description TEXT NOT NULL,
  is_immutable INTEGER NOT NULL DEFAULT 0 CHECK (is_immutable IN (0, 1)),
  updated_by TEXT,
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TRIGGER IF NOT EXISTS trg_system_settings_prevent_immutable_update
BEFORE UPDATE ON system_settings
WHEN OLD.is_immutable = 1
BEGIN
  SELECT RAISE(ABORT, 'IMMUTABLE_SYSTEM_SETTING');
END;

CREATE TRIGGER IF NOT EXISTS trg_system_settings_prevent_immutable_delete
BEFORE DELETE ON system_settings
WHEN OLD.is_immutable = 1
BEGIN
  SELECT RAISE(ABORT, 'IMMUTABLE_SYSTEM_SETTING');
END;

-- 20. sync_outbox (outbound Telegram notification / optional projection retries)
CREATE TABLE IF NOT EXISTS sync_outbox (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  aggregate_type TEXT NOT NULL,
  aggregate_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'in_flight', 'acked', 'failed')),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  next_retry_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  last_error TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_sync_outbox_pending ON sync_outbox(status, next_retry_at);

-- 21. cron_runs (tracks daily audit completion for missed-run catch-up)
CREATE TABLE IF NOT EXISTS cron_runs (
  run_date_utc TEXT PRIMARY KEY,
  status TEXT NOT NULL CHECK (status IN ('running', 'completed', 'failed')),
  is_catch_up INTEGER NOT NULL DEFAULT 0 CHECK (is_catch_up IN (0, 1)),
  summary_json TEXT NOT NULL DEFAULT '{}',
  started_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  completed_at TEXT
);
