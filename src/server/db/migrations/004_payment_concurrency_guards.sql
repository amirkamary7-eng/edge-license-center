-- ============================================================================
-- Migration 004: Payment Concurrency & Anti-Duplicate License Guards
-- Preserves Migrations 001, 002 & 003 untouched.
-- Guarantees at the SQLite engine level that a single commercial order can
-- NEVER generate more than one subscription/license under concurrent races.
-- ============================================================================

PRAGMA foreign_keys = ON;

CREATE UNIQUE INDEX IF NOT EXISTS idx_subscriptions_unique_order_id
  ON subscriptions(order_id)
  WHERE order_id IS NOT NULL;
