-- ============================================================================
-- Migration 002: Authoritative Seed Plans & Immutable System Settings
-- Phase 0 Commercial Pricing & Polygon PoS Native USDC Parameters
-- ============================================================================

INSERT OR IGNORE INTO plans (
  code,
  name_en,
  name_fa,
  duration_months,
  duration_days,
  price_usdc_micro,
  price_usd_display,
  max_devices,
  is_active,
  sort_order
) VALUES
  ('EDGE_1M',  '1 Month Access',   'اشتراک ۱ ماهه',  1,  30,  1990000, '1.99',  1, 1, 1),
  ('EDGE_3M',  '3 Months Access',  'اشتراک ۳ ماهه',  3,  90,  4990000, '4.99',  1, 1, 2),
  ('EDGE_6M',  '6 Months Access',  'اشتراک ۶ ماهه',  6,  180, 8990000, '8.99',  2, 1, 3),
  ('EDGE_12M', '12 Months Access', 'اشتراک ۱۲ ماهه', 12, 365, 16990000,'16.99', 2, 1, 4);

INSERT OR IGNORE INTO system_settings (key, value, description, is_immutable, updated_by) VALUES
  ('system_phase', 'PHASE_0_BOOTSTRAP', 'Current deployment lifecycle phase', 0, 'migration_002'),
  ('payment_network', 'Polygon PoS', 'Settlement blockchain network', 1, 'migration_002'),
  ('payment_chain_id', '137', 'Polygon PoS EVM chain ID', 1, 'migration_002'),
  ('payment_token_symbol', 'USDC', 'Official payment token symbol (Native USDC)', 1, 'migration_002'),
  ('payment_usdc_contract', '0x3c499c542cef5e3811e1192ce70d8cc03d5c3359', 'Official Polygon PoS Native USDC ERC-20 contract', 1, 'migration_002'),
  ('payment_destination_wallet', '0xf5fdefb5b02be3b7e16df37859dca111526bcc05', 'Official treasury wallet receiving USDC payments', 1, 'migration_002'),
  ('telegram_bot_handle', '@EDGE_LicenceBot', 'Official Telegram management bot handle', 1, 'migration_002'),
  ('polygon_min_confirmations', '30', 'Minimum block confirmations required for payment finality', 0, 'migration_002'),
  ('order_expiry_minutes', '45', 'Minutes before an unpaid order automatically expires', 0, 'migration_002'),
  ('android_validation_interval_hours', '24', 'Daily online license validation window for EDGE Android', 0, 'migration_002');
