# System Architecture — EDGE LICENSE CENTER by AMIRBTC

## 1. High-Level Topology

```
[Telegram User / Admin]
   ├── @EDGE_LicenceBot (Webhook -> POST /api/v1/bot/webhook)
   └── Telegram Mini App SPA (HTTPS + X-Telegram-Init-Data HMAC)
            │
            ▼
[Primary Backend: Node.js + Express + SQLite (WAL)]
   ├── Auth & RBAC Layer (Telegram HMAC-SHA256 + admins table)
   ├── Payment Engine (Server-priced orders + Polygon PoS Native USDC verifier + Anti-replay)
   ├── License Engine (RSA-2048 SHA-256 signer + Device binding + Revocation)
   ├── Admin Engine (Dashboard, Users, Orders, Payments, Finance, Audit Logs, RBAC)
   └── Audit Logger (Immutable security/operational trail)
            ▲
            │ (HTTPS + X-Edge-Gateway-Secret)
[Cloudflare Worker — Stateless Edge Gateway]
            ▲
            │ (Daily 24h online license validation)
[EDGE by AMIRBTC Android Application]
```

## 2. Backend Module Boundaries

- `src/server/db/`: Connection manager (WAL, `PRAGMA foreign_keys = ON`, `busy_timeout = 5000`, `BEGIN IMMEDIATE`) and versioned idempotent SQL migrator.
- `src/server/security/`:
  - `telegramAuth.ts`: Official WebApp `initData` HMAC-SHA256 verification + `auth_date` replay window.
  - `rsaSigner.ts`: Canonical JSON serialization + RSA-2048 `RSA-SHA256` signing/verification.
  - `rbac.ts`: Least-privilege permission matrix for `super_admin`, `admin`, `finance`, `support`, `auditor`.
- `src/server/modules/payment/`:
  - `polygonVerifier.ts`: Strict ERC-20 `Transfer` log parser pinned exclusively to Native USDC (`0x3c499c542cef5e3811e1192ce70d8cc03d5c3359`) and treasury wallet (`0xf5fdefb5b02be3b7e16df37859dca111526bcc05`), rejecting bridged USDC.e, reverted transactions, underpayments, and <30 confirmations.
  - `paymentService.ts`: Creates orders strictly from server SQLite `plans` prices; records TxID inside an `IMMEDIATE` transaction enforcing `UNIQUE(tx_hash) COLLATE NOCASE`; guarded by `PAYMENT_VERIFICATION_MODE=DRY_RUN` in Phase 0.
- `src/server/modules/license/`:
  - `licenseService.ts`: Generates `EDGE-XXXX-XXXX-XXXX-XXXX` keys, signs payloads with RSA-2048 (blocked in Phase 0 `DRY_RUN`), supports revoke/block, enforces `max_devices` atomic device binding, and serves the daily EDGE Android validation endpoint.
- `src/server/bot/`:
  - `commands.ts` & `webhookHandler.ts`: `@EDGE_LicenceBot` command & inline keyboard skeleton with constant-time `X-Telegram-Bot-Api-Secret-Token` validation.

## 3. SQLite Relational Schema (10 Core Tables)

1. `users`: Canonical Telegram user accounts (`telegram_id` UNIQUE, `status` CHECK).
2. `admins`: RBAC roles bound 1:1 to `users` (`super_admin`, `admin`, `finance`, `support`, `auditor`).
3. `plans`: Authoritative server-side catalog (`EDGE_1M`, `EDGE_3M`, `EDGE_6M`, `EDGE_12M` in micro-USDC integer units to prevent floating-point drift).
4. `orders`: Server-priced purchase intents referencing `users` & `plans` with expiration timestamps.
5. `payments`: Submitted Polygon PoS transactions with `tx_hash TEXT NOT NULL UNIQUE COLLATE NOCASE` preventing replay attacks across orders.
6. `subscriptions`: Active/expired/revoked access periods (`expires_at > starts_at` CHECK, 1:1 `order_id` UNIQUE).
7. `licenses`: RSA-2048 signed license keys referencing `subscriptions` & `users` with `rsa_key_id`, `payload_json`, `signature_base64`, and revocation metadata.
8. `devices`: Bound Android device fingerprints (`UNIQUE(license_id, device_fingerprint)`).
9. `audit_logs`: Tamper-evident operational and security events (`actor_type`, `action`, `severity`, `metadata_json`, `ip_address`).
10. `system_settings`: Core platform parameters with `is_immutable` flag protecting Polygon USDC contract and treasury wallet configuration.
