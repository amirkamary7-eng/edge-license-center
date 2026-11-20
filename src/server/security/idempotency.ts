import crypto from 'crypto';
import type { IdempotencyRecord } from '../../shared/types';
import { runImmediateTransaction, type SqliteDb } from '../db/connection';

export function hashRequestPayload(payload: unknown): string {
  const serialized = typeof payload === 'string' ? payload : JSON.stringify(payload ?? {});
  return crypto.createHash('sha256').update(serialized, 'utf8').digest('hex');
}

export class IdempotencyError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly statusCode = 409
  ) {
    super(message);
    this.name = 'IdempotencyError';
  }
}

export class IdempotencyStore {
  constructor(private readonly db: SqliteDb) {}

  /**
   * Atomically claims a one-time key (e.g., Telegram Bot update_id or single-use initData hash).
   * Returns `true` if newly claimed, `false` if already present and unexpired.
   */
  claimOnce(params: {
    scope: string;
    key: string;
    actorId: string;
    ttlSeconds?: number;
    requestHash?: string;
  }): boolean {
    const nowIso = new Date().toISOString();
    const expiresAt = new Date(Date.now() + (params.ttlSeconds ?? 3600) * 1000).toISOString();

    return runImmediateTransaction(this.db, () => {
      // Remove expired record for same key if any
      this.db
        .prepare(
          `DELETE FROM idempotency_records WHERE scope = ? AND idempotency_key = ? AND expires_at <= ?`
        )
        .run(params.scope, params.key, nowIso);

      const existing = this.db
        .prepare(`SELECT 1 FROM idempotency_records WHERE scope = ? AND idempotency_key = ?`)
        .get(params.scope, params.key);

      if (existing) {
        return false;
      }

      this.db
        .prepare(
          `INSERT INTO idempotency_records (
             scope, idempotency_key, actor_id, request_hash, response_status, response_body_json, expires_at
           ) VALUES (?, ?, ?, ?, 200, '{}', ?)`
        )
        .run(
          params.scope,
          params.key,
          params.actorId,
          params.requestHash ?? params.key,
          expiresAt
        );
      return true;
    });
  }

  /**
   * Looks up a previously stored idempotent API response.
   * Throws 409 if the same Idempotency-Key was reused with a different request payload.
   */
  findResponse(params: {
    scope: string;
    key: string;
    actorId: string;
    requestHash: string;
  }): { status: number; body: unknown } | null {
    const nowIso = new Date().toISOString();
    const row = this.db
      .prepare(
        `SELECT * FROM idempotency_records
         WHERE scope = ? AND idempotency_key = ? AND expires_at > ?`
      )
      .get(params.scope, params.key, nowIso) as IdempotencyRecord | undefined;

    if (!row) {
      return null;
    }

    if (row.actor_id !== params.actorId || row.request_hash !== params.requestHash) {
      throw new IdempotencyError(
        'IDEMPOTENCY_KEY_PAYLOAD_MISMATCH',
        'Idempotency-Key was already used with a different request payload or actor.',
        409
      );
    }

    return {
      status: row.response_status,
      body: JSON.parse(row.response_body_json) as unknown,
    };
  }

  saveResponse(params: {
    scope: string;
    key: string;
    actorId: string;
    requestHash: string;
    status: number;
    body: unknown;
    ttlSeconds?: number;
  }): void {
    const expiresAt = new Date(Date.now() + (params.ttlSeconds ?? 86400) * 1000).toISOString();
    this.db
      .prepare(
        `INSERT OR REPLACE INTO idempotency_records (
           scope, idempotency_key, actor_id, request_hash, response_status, response_body_json, expires_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        params.scope,
        params.key,
        params.actorId,
        params.requestHash,
        params.status,
        JSON.stringify(params.body),
        expiresAt
      );
  }

  purgeExpired(): number {
    const res = this.db
      .prepare(`DELETE FROM idempotency_records WHERE expires_at <= ?`)
      .run(new Date().toISOString());
    return res.changes;
  }
}
