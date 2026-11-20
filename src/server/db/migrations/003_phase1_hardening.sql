-- ============================================================================
-- Migration 003: Phase 1 Security Hardening, Operational Tables & Triggers
-- Preserves Migrations 001 & 002 untouched.
-- Adds: support_tickets, notifications, idempotency_records, license_history,
--       anti-front-running unique micro-offset on orders, active payment
--       uniqueness per order, and immutable system_settings protection triggers.
-- ============================================================================

PRAGMA foreign_keys = ON;

-- 1. Extend orders for anti-front-running micro-offset, sender wallet binding, and renew/upgrade flows
ALTER TABLE orders ADD COLUMN order_type TEXT NOT NULL DEFAULT 'new'
  CHECK (order_type IN ('new', 'renew', 'upgrade'));
ALTER TABLE orders ADD COLUMN target_subscription_id INTEGER REFERENCES subscriptions(id) ON DELETE SET NULL;
ALTER TABLE orders ADD COLUMN unique_offset_micro INTEGER NOT NULL DEFAULT 0 CHECK (unique_offset_micro >= 0 AND unique_offset_micro <= 999);
ALTER TABLE orders ADD COLUMN payable_amount_usdc_micro INTEGER;
ALTER TABLE orders ADD COLUMN expected_sender_wallet TEXT;

UPDATE orders
SET payable_amount_usdc_micro = expected_amount_usdc_micro + unique_offset_micro
WHERE payable_amount_usdc_micro IS NULL;

-- Enforce that no two simultaneously open orders share the exact same payable micro-USDC amount
CREATE UNIQUE INDEX IF NOT EXISTS idx_orders_active_payable_amount
  ON orders(payable_amount_usdc_micro)
  WHERE status IN ('draft_phase0', 'pending_payment', 'tx_submitted', 'verifying')
    AND payable_amount_usdc_micro IS NOT NULL;

-- Enforce at most ONE active/confirmed payment per order (prevents multi-TxID spam on a single order)
CREATE UNIQUE INDEX IF NOT EXISTS idx_payments_one_active_per_order
  ON payments(order_id)
  WHERE status IN ('submitted', 'dry_run_recorded', 'verifying', 'confirmed');

-- 2. Add updated_at tracking column to licenses
ALTER TABLE licenses ADD COLUMN updated_at TEXT;
UPDATE licenses SET updated_at = issued_at WHERE updated_at IS NULL;

-- 3. support_tickets
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

-- 4. notifications
CREATE TABLE IF NOT EXISTS notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  channel TEXT NOT NULL DEFAULT 'telegram_bot' CHECK (channel IN ('telegram_bot', 'mini_app', 'admin_alert')),
  type TEXT NOT NULL,
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

-- 5. idempotency_records (also supports Bot update_id dedupe and initData anti-replay)
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

-- 6. license_history (complete immutable audit history of license lifecycle changes)
CREATE TABLE IF NOT EXISTS license_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  license_id INTEGER NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
  action TEXT NOT NULL,
  previous_status TEXT,
  new_status TEXT,
  actor_type TEXT NOT NULL CHECK (actor_type IN ('user', 'admin', 'system', 'bot', 'gateway')),
  actor_id TEXT NOT NULL,
  reason TEXT,
  metadata_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_license_history_license ON license_history(license_id, id DESC);

-- 7. Database-level immutability triggers on system_settings
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

-- Record Phase 1 lifecycle state in mutable system_settings key
UPDATE system_settings
SET value = 'PHASE_1_HARDENED', updated_by = 'migration_003', updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE key = 'system_phase' AND is_immutable = 0;
