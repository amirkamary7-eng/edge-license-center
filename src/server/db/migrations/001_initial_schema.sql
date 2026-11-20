-- ============================================================================
-- Migration 001: Initial Core Schema for EDGE LICENSE CENTER by AMIRBTC
-- Database Engine: SQLite 3 (WAL mode, Foreign Keys enforced)
-- Tables: users, admins, plans, orders, payments, subscriptions,
--         licenses, devices, audit_logs, system_settings
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

-- 4. orders
CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_code TEXT NOT NULL UNIQUE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  plan_id INTEGER NOT NULL REFERENCES plans(id) ON DELETE RESTRICT,
  expected_amount_usdc_micro INTEGER NOT NULL CHECK (expected_amount_usdc_micro > 0),
  expected_amount_usd TEXT NOT NULL,
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

CREATE INDEX IF NOT EXISTS idx_orders_user_status ON orders(user_id, status);
CREATE INDEX IF NOT EXISTS idx_orders_status_expires ON orders(status, expires_at);

-- 5. payments
-- UNIQUE(tx_hash) enforces database-level anti-replay & duplicate payment prevention
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

CREATE INDEX IF NOT EXISTS idx_payments_order ON payments(order_id);
CREATE INDEX IF NOT EXISTS idx_payments_user_status ON payments(user_id, status);
CREATE INDEX IF NOT EXISTS idx_payments_status ON payments(status);

-- 6. subscriptions
CREATE TABLE IF NOT EXISTS subscriptions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  plan_id INTEGER NOT NULL REFERENCES plans(id) ON DELETE RESTRICT,
  order_id INTEGER UNIQUE REFERENCES orders(id) ON DELETE RESTRICT,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'expired', 'revoked', 'suspended')),
  starts_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  auto_renew_reminded INTEGER NOT NULL DEFAULT 0 CHECK (auto_renew_reminded IN (0, 1)),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  CHECK (expires_at > starts_at)
);

CREATE INDEX IF NOT EXISTS idx_subscriptions_user_status ON subscriptions(user_id, status);
CREATE INDEX IF NOT EXISTS idx_subscriptions_expires ON subscriptions(expires_at);

-- 7. licenses
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
  issued_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  expires_at TEXT NOT NULL,
  revoked_at TEXT,
  revoke_reason TEXT,
  last_validated_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_licenses_user_status ON licenses(user_id, status);
CREATE INDEX IF NOT EXISTS idx_licenses_status_expires ON licenses(status, expires_at);

-- 8. devices
CREATE TABLE IF NOT EXISTS devices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  license_id INTEGER NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  device_fingerprint TEXT NOT NULL,
  device_model TEXT,
  android_version TEXT,
  app_version TEXT,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked', 'blocked')),
  first_bound_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  last_seen_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  UNIQUE(license_id, device_fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_devices_user ON devices(user_id);
CREATE INDEX IF NOT EXISTS idx_devices_fingerprint ON devices(device_fingerprint);

-- 9. audit_logs
CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor_type TEXT NOT NULL CHECK (actor_type IN ('user', 'admin', 'system', 'bot', 'gateway')),
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

-- 10. system_settings
CREATE TABLE IF NOT EXISTS system_settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  description TEXT NOT NULL,
  is_immutable INTEGER NOT NULL DEFAULT 0 CHECK (is_immutable IN (0, 1)),
  updated_by TEXT,
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
