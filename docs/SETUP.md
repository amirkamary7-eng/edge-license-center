# Setup, Testing & Development Roadmap — EDGE LICENSE CENTER

## 1. Local Installation

```bash
# 1. Install dependencies
npm install

# 2. Create local environment file (never commit .env)
cp .env.example .env

# 3. Run SQLite migrations
npm run db:migrate

# 4. Run full unit & integration test suite
npm test

# 5. Typecheck & build frontend bundle
npm run lint
npm run build

# 6. Start local full-stack development server on port 3000
npm run dev
```

## 2. Generating RSA-2048 Keypair (For Phase 1+ Secrets Only)

Never commit `.pem` files into Git (blocked by `.gitignore`). Generate keys locally or in your secret manager:

```bash
openssl genpkey -algorithm RSA -out edge_rsa_private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in edge_rsa_private.pem -out edge_rsa_public.pem
```

Embed the public key in the EDGE Android app for offline cryptographic verification alongside the daily online Cloudflare Worker check, and store the private key exclusively in server secrets (`RSA_PRIVATE_KEY_PEM`).

## 3. Next Phases Roadmap

- **Phase 1 — Live Bot & Payment Worker Activation**:
  - Register `@EDGE_LicenceBot` webhook with Telegram Bot API using `TELEGRAM_WEBHOOK_SECRET`.
  - Wire live Polygon PoS RPC polling/verification job for `tx_submitted` orders with >=30 confirmations.
  - Enable automated subscription issuance and Telegram Bot confirmation notifications after owner sign-off.
- **Phase 2 — Production RSA Key Management & Android Gateway Deployment**:
  - Provision RSA-2048 keypair in Secret Manager and deploy `cloudflare-worker/` via `wrangler deploy`.
  - Configure `ORIGIN_API_URL` and `GATEWAY_SHARED_SECRET` as encrypted Worker secrets.
  - Perform end-to-end validation test with EDGE Android staging build.
- **Phase 3 — Hardening, Backups & Go-Live**:
  - Set `NODE_ENV=production`, `ALLOW_PHASE0_PREVIEW_SESSION=false`, and enable automated encrypted SQLite WAL backups.
  - Conduct rate-limiting, replay-attack, and RBAC penetration review before opening public sales.
