#!/usr/bin/env bash
# ============================================================================
# EDGE LICENSE CENTER — Verified SQLite WAL Backup + Off-Site Cloudflare R2 Sync
# Never hardcode credentials here. Configure R2 credentials via host env / rclone.
# Verifies both SHA-256 checksum and SQLite PRAGMA integrity_check BEFORE R2 upload.
# ============================================================================
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/edge-license-center}"
BACKUP_DIR="${SQLITE_BACKUP_DIR:-/var/lib/edge-license-center/backups}"
R2_REMOTE="${R2_REMOTE:-}" # Example: r2:edge-license-backups/staging

cd "${APP_DIR}"
echo "[EDGE Backup] Running verified SQLite online WAL backup..."
npm run db:backup

LATEST_BACKUP="$(ls -1t "${BACKUP_DIR}"/*.sqlite 2>/dev/null | head -n 1 || true)"
if [[ -z "${LATEST_BACKUP}" || ! -f "${LATEST_BACKUP}" ]]; then
  echo "[EDGE Backup] ERROR: No backup snapshot found in ${BACKUP_DIR}." >&2
  exit 1
fi

CHECKSUM_FILE="${LATEST_BACKUP}.sha256"
if [[ ! -f "${CHECKSUM_FILE}" ]]; then
  echo "[EDGE Backup] ERROR: Missing SHA-256 manifest (${CHECKSUM_FILE}). Aborting upload." >&2
  exit 1
fi

echo "[EDGE Backup] Verifying SHA-256 manifest before off-site transfer..."
(
  cd "${BACKUP_DIR}"
  sha256sum -c "$(basename "${CHECKSUM_FILE}")"
)

echo "[EDGE Backup] Verifying SQLite PRAGMA integrity_check on latest snapshot..."
node --input-type=module -e "
import Database from 'better-sqlite3';
const db = new Database(process.argv[1], { readonly: true });
try {
  const row = db.prepare('PRAGMA integrity_check').get();
  if (!row || row.integrity_check !== 'ok') {
    console.error('INTEGRITY_CHECK_FAILED:', row);
    process.exit(1);
  }
} finally {
  db.close();
}
" "${LATEST_BACKUP}"

if [[ -n "${R2_REMOTE}" ]]; then
  if ! command -v rclone >/dev/null 2>&1; then
    echo "[EDGE Backup] ERROR: rclone is not installed on host." >&2
    exit 1
  fi
  REMOTE_BASE="${R2_REMOTE%/}"
  BACKUP_NAME="$(basename "${LATEST_BACKUP}")"
  CHECKSUM_NAME="$(basename "${CHECKSUM_FILE}")"
  echo "[EDGE Backup] Uploading ONLY verified snapshot (${BACKUP_NAME}) and SHA-256 manifest to R2..."
  rclone copyto "${LATEST_BACKUP}" "${REMOTE_BASE}/${BACKUP_NAME}" --stats-one-line=false --log-level ERROR
  rclone copyto "${CHECKSUM_FILE}" "${REMOTE_BASE}/${CHECKSUM_NAME}" --stats-one-line=false --log-level ERROR
  echo "[EDGE Backup] Off-site Cloudflare R2 verified upload complete."
else
  echo "[EDGE Backup] R2_REMOTE not set — local verified backup only."
fi
