# ============================================================================
# EDGE LICENSE CENTER by AMIRBTC — Production & Staging Dockerfile
# Node 22 Slim + Native better-sqlite3 + Persistent SQLite Volume (/data)
# ============================================================================

FROM node:22-bookworm-slim AS builder
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 make g++ \
    && rm -rf /var/lib/apt/lists/*

COPY package.json ./
RUN npm install

COPY . .
RUN npm run build

FROM node:22-bookworm-slim AS runtime
WORKDIR /app

ENV NODE_ENV=production
ENV PORT=3000
ENV SQLITE_DB_PATH=/data/edge_license_center.sqlite
ENV SQLITE_BACKUP_DIR=/data/backups
ENV PAYMENT_VERIFICATION_MODE=DRY_RUN
ENV LICENSE_ISSUANCE_MODE=DRY_RUN
ENV TELEGRAM_BOT_SEND_ENABLED=false
ENV ALLOW_PHASE0_PREVIEW_SESSION=false

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /data/backups \
    && chown -R node:node /data

COPY --from=builder /app/package.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/dist-server ./dist-server

USER node
EXPOSE 3000
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -fsS http://127.0.0.1:3000/api/v1/health || exit 1

CMD ["node", "dist-server/server.mjs"]
