import type { SqliteDb } from '../../db/connection';
import type { AuditLogRecord } from '../../../shared/types';

export interface AuditEntryInput {
  actorType: AuditLogRecord['actor_type'];
  actorId: string;
  action: string;
  entityType: string;
  entityId?: string | number | null;
  severity?: AuditLogRecord['severity'];
  metadata?: Record<string, unknown>;
  ipAddress?: string | null;
}

export class AuditService {
  constructor(private readonly db: SqliteDb) {}

  record(entry: AuditEntryInput): number {
    const stmt = this.db.prepare(`
      INSERT INTO audit_logs (
        actor_type,
        actor_id,
        action,
        entity_type,
        entity_id,
        severity,
        metadata_json,
        ip_address
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const result = stmt.run(
      entry.actorType,
      entry.actorId,
      entry.action,
      entry.entityType,
      entry.entityId != null ? String(entry.entityId) : null,
      entry.severity ?? 'info',
      JSON.stringify(entry.metadata ?? {}),
      entry.ipAddress ?? null
    );

    return Number(result.lastInsertRowid);
  }

  listRecent(limit = 50, severity?: AuditLogRecord['severity']): AuditLogRecord[] {
    if (severity) {
      return this.db
        .prepare(
          `SELECT * FROM audit_logs WHERE severity = ? ORDER BY id DESC LIMIT ?`
        )
        .all(severity, limit) as AuditLogRecord[];
    }
    return this.db
      .prepare(`SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?`)
      .all(limit) as AuditLogRecord[];
  }
}
