# Environment & Telegram Serverless Capabilities Audit (Phase 0)

## 1. Audited Execution Runtime

Verified directly in the local workspace prior to code bootstrap:

| Component | Verified Value |
| :--- | :--- |
| Operating System | Linux x86_64 (`4.19.0-gvisor`) |
| Node.js Runtime | `v22.23.2` |
| npm Version | `10.9.8` |
| SQLite Engine | `better-sqlite3` (SQLite 3, WAL mode, `PRAGMA foreign_keys = ON`, `BEGIN IMMEDIATE`) + native `node:sqlite` available |
| Cryptography | Node.js `node:crypto` (OpenSSL RSA-2048 SHA-256, HMAC-SHA256, `timingSafeEqual`) |
| HTTP Server | Express 4.21 on Port `3000` (with Vite 8 middleware in dev, static `dist/` in prod) |

## 2. Verified Capabilities of Telegram Bot & Mini App Platform

To avoid speculative architecture or unverified APIs, only officially documented Telegram Bot API & WebApp capabilities are used:

1. **Telegram Bot API (`@EDGE_LicenceBot`)**:
   - HTTPS Webhook delivery with `X-Telegram-Bot-Api-Secret-Token` verification.
   - Text commands (`/start`, `/plans`, `/buy`, `/tx`, `/orders`, `/profile`, `/support`, `/admin`) and Inline Keyboard callbacks (`callback_data`).
   - Direct launch of the Mini App via `web_app: { url }`.
2. **Telegram Mini App (WebApp SDK)**:
   - Runs as a responsive HTTPS Single-Page Application inside Telegram WebView (`telegram-web-app.js`).
   - Supplies cryptographically signed `window.Telegram.WebApp.initData`.
   - Server verifies authenticity via `HMAC_SHA256(HMAC_SHA256("WebAppData", BOT_TOKEN), sortedDataCheckString)` and enforces `auth_date` replay window.

## 3. Critical Technical Constraints Discovered (Transparent Report)

1. **Telegram Does Not Host Compute or SQLite Directly**:
   - Telegram provides Bot API routing and the Mini App client WebView, **not** a native serverless compute runtime or SQLite file host.
   - Therefore, the primary Backend (`server.ts` + SQLite file) must execute on a persistent-volume Node.js host or serverless container with durable disk attachment (or zero-cost/low-cost persistent host approved by the project owner before Phase 1).
2. **Ephemeral Serverless Functions vs. Local SQLite File**:
   - Standard stateless serverless functions (e.g., Vercel Functions / AWS Lambda without EFS) reset local disk between cold starts, which would wipe a local SQLite file.
   - **Recommended Production Path (Zero-Extra-Paid-DB)**: Run the single-instance Node.js + SQLite WAL container with a mounted persistent volume + automated encrypted daily SQLite `.backup` snapshots, while keeping Cloudflare Worker strictly as the stateless edge gateway for EDGE Android.
3. **Polygon PoS Public RPC Rate Limits**:
   - Free public RPC endpoints (`https://polygon-rpc.com`) may throttle under high traffic. In Phase 1, a free-tier dedicated RPC key (Alchemy/Infura/QuickNode free tier) should be placed in server secrets for deterministic receipt lookups.

## 4. Estimated Infrastructure Cost (Phase 0 & Initial Launch)

| Component | Tier | Estimated Monthly Cost |
| :--- | :--- | :--- |
| Telegram Bot & Mini App Platform | Official Telegram API | `$0 / month` |
| SQLite Database Engine | Embedded local WAL file | `$0 / month` |
| Cloudflare Worker (Android Gateway) | Cloudflare Workers Free Tier (100,000 req/day) | `$0 / month` |
| Polygon PoS RPC (Read-only receipt checks) | Public / Free RPC Tier | `$0 / month` |
| Backend Runtime (Phase 0 Dev / Preview) | Local / AI Studio container | `$0 / month` |
| **Total Phase 0 Cost** | **Zero paid services activated** | **`$0 / month`** |
