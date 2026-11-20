#!/usr/bin/env bash
# ============================================================================
# EDGE LICENSE CENTER — @EDGE_LicenceBot Staging Setup Helper
# Usage (provide secrets strictly via runtime shell environment, never commit):
#   TELEGRAM_BOT_TOKEN="..." \
#   TELEGRAM_WEBHOOK_SECRET="..." \
#   STAGING_APP_URL="https://staging.edge-license.example.com" \
#   bash deploy/setup-staging-bot.sh
# ============================================================================
set -euo pipefail

: "${TELEGRAM_BOT_TOKEN:?TELEGRAM_BOT_TOKEN must be provided in runtime environment}"
: "${TELEGRAM_WEBHOOK_SECRET:?TELEGRAM_WEBHOOK_SECRET must be provided in runtime environment}"
: "${STAGING_APP_URL:?STAGING_APP_URL must be an HTTPS Staging URL}"

if [[ "${STAGING_APP_URL}" != https://* ]]; then
  echo "ERROR: STAGING_APP_URL must use HTTPS for Telegram Webhook & Mini App." >&2
  exit 1
fi

WEBHOOK_URL="${STAGING_APP_URL%/}/api/v1/bot/webhook"
API_BASE="https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}"

tg_call() {
  local method="$1"
  local payload="${2:-}"
  local response
  if [[ -n "${payload}" ]]; then
    response="$(curl -s --max-time 15 -X POST "${API_BASE}/${method}" -H "Content-Type: application/json" -d "${payload}" || true)"
  else
    response="$(curl -s --max-time 15 "${API_BASE}/${method}" || true)"
  fi
  if ! printf '%s' "${response}" | grep -q '"ok":true'; then
    echo "ERROR: Telegram Bot API call '${method}' failed (response sanitized; token never logged)." >&2
    exit 1
  fi
}

echo "[1/3] Verifying bot identity (getMe)..."
tg_call "getMe"

echo "[2/3] Registering Staging webhook with fail-closed secret_token..."
tg_call "setWebhook" "{
  \"url\": \"${WEBHOOK_URL}\",
  \"secret_token\": \"${TELEGRAM_WEBHOOK_SECRET}\",
  \"allowed_updates\": [\"message\", \"callback_query\"],
  \"drop_pending_updates\": false
}"

echo "[3/3] Setting bot slash commands & Mini App menu button..."
tg_call "setMyCommands" '{
  "commands": [
    {"command": "start", "description": "شروع و منوی اصلی EDGE"},
    {"command": "plans", "description": "مشاهده پلن‌های اشتراک EDGE"},
    {"command": "buy", "description": "خرید اشتراک جدید"},
    {"command": "renew", "description": "تمدید اشتراک فعلی"},
    {"command": "upgrade", "description": "ارتقای پلن اشتراک"},
    {"command": "tx", "description": "ثبت هش تراکنش Polygon USDC"},
    {"command": "status", "description": "وضعیت سفارش‌ها و پرداخت‌ها"},
    {"command": "license", "description": "مشاهده کلیدهای لایسنس فعال"},
    {"command": "profile", "description": "پروفایل کاربری و نقش"},
    {"command": "support", "description": "راهنمای پشتیبانی"},
    {"command": "ticket", "description": "ثبت تیکت پشتیبانی"}
  ]
}'

tg_call "setChatMenuButton" "{
  \"menu_button\": {
    \"type\": \"web_app\",
    \"text\": \"EDGE Panel\",
    \"web_app\": {\"url\": \"${STAGING_APP_URL%/}\"}
  }
}"

echo "Staging @EDGE_LicenceBot webhook & Mini App configured successfully (no secrets written to disk)."
