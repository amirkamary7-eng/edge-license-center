# EDGE LICENSE CENTER by AMIRBTC

Commercial license sales, Polygon PoS Native USDC payment verification, RSA-2048 signed license management, Telegram Bot (`@EDGE_LicenceBot`), Telegram Mini App, and RBAC Admin Panel for **EDGE by AMIRBTC**.

## Phase 0 Status

This repository contains the complete **Phase 0 Bootstrap**:
- Modular TypeScript full-stack architecture (Express + SQLite WAL + React Mini App + Admin Panel)
- 10-table SQLite schema with strict Foreign Keys, CHECK constraints, composite indexes, and idempotent SQL migrations
- Official immutable pricing (`$1.99`, `$4.99`, `$8.99`, `$16.99`) and Polygon PoS Native USDC constants
- Real Telegram Mini App `initData` HMAC-SHA256 verification and replay protection
- Polygon PoS Native USDC `Transfer(address,address,uint256)` receipt verifier + anti-replay `UNIQUE(tx_hash)` enforcement
- RSA-2048 (`RSA-SHA256`) license signing & verification engine + Android device binding
- Stateless Cloudflare Worker gateway skeleton (`cloudflare-worker/`) for daily EDGE Android validation
- Comprehensive Vitest unit & integration test suite

> **Phase 0 Safety Guard**: `PAYMENT_VERIFICATION_MODE=DRY_RUN` and `LICENSE_ISSUANCE_MODE=DRY_RUN` are enforced by default. No live on-chain settlement, no real license issuance, and no public deployment occur in Phase 0.

## Official Commercial Specification (Frozen)

| Parameter | Value |
| :--- | :--- |
| Product | EDGE by AMIRBTC |
| Telegram Bot | `@EDGE_LicenceBot` |
| Network | Polygon PoS (Chain ID `137`) |
| Token | Native USDC (6 decimals) |
| Official Contract | `0x3c499c542cef5e3811e1192ce70d8cc03d5c3359` |
| Destination Wallet | `0xf5fdefb5b02be3b7e16df37859dca111526bcc05` |
| Plans | 1M: `$1.99` · 3M: `$4.99` · 6M: `$8.99` · 12M: `$16.99` |

## Quick Start

```bash
cp .env.example .env
npm install
npm run db:migrate
npm test
npm run dev
```

## Documentation

- [Runtime & Telegram Serverless Environment Audit](./docs/ENVIRONMENT_AUDIT.md)
- [System, Database & Security Architecture](./docs/ARCHITECTURE.md)
- [Installation, Migration, RSA Keys & Phase 1 Roadmap](./docs/SETUP.md)
