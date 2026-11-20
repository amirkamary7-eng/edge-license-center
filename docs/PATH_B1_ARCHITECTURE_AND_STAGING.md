# Phase 1.6 — Path B-1 Migration Design, Staging Runbook & Secrets Diagnostic

**Project:** EDGE LICENSE CENTER by AMIRBTC (`@EDGE_LicenceBot`)  
**Approved Architecture:** Path B-1 (Cloudflare D1 Primary Database + Cloudflare Worker Backend + Cloudflare R2 Encrypted Backups + Daily Cron)  
**Current Execution Mode:** STAGING ONLY (`PAYMENT_VERIFICATION_MODE=DRY_RUN`, `LICENSE_ISSUANCE_MODE=DRY_RUN`, `TELEGRAM_BOT_SEND_ENABLED=false`)

---

## 1. Path B-1 System Architecture

```
[Telegram User / Admin]
   ├── @EDGE_LicenceBot Webhook ──► POST /api/v1/bot/webhook
   └── Telegram Mini App SPA    ──► HTTPS + Single-use initData -> Bearer HMAC Session
                                           │
                                           ▼
[Cloudflare Worker — Primary Authoritative Backend (`cloudflare-worker/src/`)]
   ├── Primary Database: Cloudflare D1 (`DB`, SQLite 3, `PRAGMA foreign_keys = ON`, `DB.batch()`)
   ├── Encrypted Backups: Cloudflare R2 (`BACKUP_BUCKET`, AES-256-GCM + RSA-OAEP-256 public-key-only)
   ├── Daily Audit & Catch-Up: Cloudflare Cron Trigger (`0 0 * * *`) + `cron_runs` table
   ├── Polygon PoS Verifier: Native USDC (`0x3c499c542cef5e3811e1192ce70d8cc03d5c3359`), Treasury (`0xf5fdefb5b02be3b7e16df37859dca111526bcc05`), >= 30 confirmations
   ├── Android Keystore ECDSA P-256 PoP: `/v1/license/challenge` -> `/v1/license/activate` -> `/v1/license/validate`
   └── Dual-Layer RSA-2048/SHA-256 Receipts: Offline verification + Edge-First atomic revocation (`revocations`)
```

### Key Security Invariants Preserved in Path B-1
1. **Zero Shared HMAC Secrets in Android APK:** Devices generate hardware-backed ECDSA P-256 keys in Android Keystore (`StrongBox` / `TEE`) and register only their SPKI public key during challenge-response activation.
2. **All Secrets Strictly in Cloudflare Worker Secrets (`wrangler secret put`):**
   - `TELEGRAM_BOT_TOKEN`
   - `TELEGRAM_WEBHOOK_SECRET`
   - `SESSION_SECRET`
   - `RSA_PRIVATE_KEY_PEM`
   - `RSA_PUBLIC_KEY_PEM`
   - `BACKUP_RSA_PUBLIC_KEY_PEM` (**public key only**; backup decryption RSA private key remains strictly offline).
3. **Atomic Financial & Issuance Commits:** `DB.batch()` executes payment confirmation, order completion, subscription creation/extension, RSA-signed license issuance, audit logs, and notification queuing atomically.
4. **Edge-First Revocation & Renewal Lock:** Revoking/blocking a license atomically updates `licenses`, `subscriptions`, `device_sessions`, `revocations` (monotonic `revocation_seq`), and `license_history`. Renewals against revoked/blocked licenses are rejected (`403`).
5. **Dual Compatibility During Migration:** When `env.DB` is unbound, `cloudflare-worker/src/index.ts` preserves the legacy Phase 1 stateless HMAC proxy fallback (`ORIGIN_API_URL`) so existing Express/SQLite tests and environments continue operating without regression.

---

## 2. Why Coding Environment Secrets Do Not Transfer to GitHub or Workflows (Technical Diagnostic)

Based on direct inspection of this workspace runtime environment:

1. **Sandbox / Runtime Isolation (No Secret Sync Channel):**
   - Secrets configured in an interactive coding/AI runtime environment exist only inside that ephemeral container's process environment (or local IDE secret vault) and are **never** written into workspace files or pushed automatically to GitHub.
   - In fact, verified workspace checks confirm `.git/` is not present in this snapshot, `.gitignore` blocks `.env*`, `*.pem`, `*.key`, `data/`, and `*.sqlite`, and none of `GITHUB_TOKEN`, `TGCLOUD_TOKEN`, `CLOUDFLARE_API_TOKEN`, `TELEGRAM_BOT_TOKEN`, or `RSA_PRIVATE_KEY_PEM` are present in the container environment (`env`).
2. **GitHub Actions Reads Exclusively from GitHub's Encrypted Secret Store:**
   - GitHub Actions workflows (`.github/workflows/*.yml`) can **only** read secrets defined in **GitHub Repository Secrets**, **GitHub Environment Secrets** (e.g., `staging` / `production`), or **GitHub Organization Secrets** via `${{ secrets.SECRET_NAME }}`.
   - Local `.env` files, shell exports, or AI Studio coding-environment secrets are completely invisible to GitHub runners.
3. **Workflow Environment Scoping & Fork / Branch Rules:**
   - If a secret is saved inside a GitHub **Environment** (e.g., `staging`), the workflow job must explicitly declare `environment: staging`; otherwise `${{ secrets.NAME }}` evaluates to an empty string (`""`).
   - Workflows triggered by `pull_request` from forks do not receive repository secrets for security reasons.
4. **Required Owner Actions (Never Paste Secrets in Code or Chat):**
   - **For Cloudflare Staging (`wrangler`):**
     1. Create isolated Staging D1 (`wrangler d1 create edge_license_staging`) and Staging R2 (`wrangler r2 bucket create edge-license-backups-staging`).
     2. Replace `REPLACE_WITH_STAGING_D1_DATABASE_ID` in `cloudflare-worker/wrangler.toml`.
     3. Apply migrations: `npx wrangler d1 migrations apply edge_license_staging --env staging --remote`.
     4. Set Worker secrets via Wrangler CLI (interactive prompt): `TELEGRAM_BOT_TOKEN`, `TELEGRAM_WEBHOOK_SECRET`, `SESSION_SECRET`, `RSA_PRIVATE_KEY_PEM`, `RSA_PUBLIC_KEY_PEM`, `BACKUP_RSA_PUBLIC_KEY_PEM`.
     5. Deploy Staging Worker: `npx wrangler deploy --env staging`.
   - **For GitHub Actions CI/CD (Optional):**
     - Add `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` directly in **GitHub → Settings → Secrets and variables → Actions** (or inside the `staging` Environment with `environment: staging` declared on the job).

---

## 3. Staging Verification Matrix

All automated checks verified in `tests/pathB1.staging.test.ts`:
- D1 migrations `0001_path_b1_d1_schema.sql` & `0002_seed_core_data.sql` (`PRAGMA foreign_keys = ON`, frozen plans, immutable settings triggers).
- Single-use Telegram `initData` WebCrypto HMAC-SHA256 verification + Bearer session exchange + anti-replay.
- `DRY_RUN` locks blocking live Polygon verification and live license issuance, plus `TELEGRAM_BOT_SEND_ENABLED=false` blocking outbound Telegram HTTP requests.
- Isolated simulated `LIVE` Polygon PoS Native USDC receipt verification (`>= 30` confirmations, exact treasury + contract check, TxHash uniqueness, atomic `DB.batch()` issuance).
- Android Keystore ECDSA P-256 challenge/activate + signed validation receipts + anti-replay nonce + Edge-First atomic revocation + blocked renewal on revoked subscriptions.
- `@EDGE_LicenceBot` webhook fail-closed secret verification + `update_id` deduplication.
- Daily Cron (`scheduled`) + R2 `AES-256-GCM + RSA-OAEP-256` encrypted backup + offline private-key decryption round-trip.
