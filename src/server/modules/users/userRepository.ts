import type { SqliteDb } from '../../db/connection';
import type { AdminRecord, AdminRole, UserRecord } from '../../../shared/types';

export interface TelegramIdentityInput {
  telegramId: string;
  username?: string | null;
  firstName: string;
  lastName?: string | null;
  languageCode?: string;
}

export class UserRepository {
  constructor(private readonly db: SqliteDb) {}

  findById(id: number): UserRecord | undefined {
    return this.db.prepare('SELECT * FROM users WHERE id = ?').get(id) as UserRecord | undefined;
  }

  findByTelegramId(telegramId: string): UserRecord | undefined {
    return this.db
      .prepare('SELECT * FROM users WHERE telegram_id = ?')
      .get(telegramId) as UserRecord | undefined;
  }

  upsertFromTelegram(input: TelegramIdentityInput): UserRecord {
    const existing = this.findByTelegramId(input.telegramId);
    const now = new Date().toISOString();

    if (existing) {
      this.db
        .prepare(
          `UPDATE users
           SET username = ?, first_name = ?, last_name = ?, language_code = ?, last_seen_at = ?, updated_at = ?
           WHERE id = ?`
        )
        .run(
          input.username ?? existing.username,
          input.firstName,
          input.lastName ?? existing.last_name,
          input.languageCode ?? existing.language_code,
          now,
          now,
          existing.id
        );
      return this.findById(existing.id)!;
    }

    const res = this.db
      .prepare(
        `INSERT INTO users (telegram_id, username, first_name, last_name, language_code, last_seen_at)
         VALUES (?, ?, ?, ?, ?, ?)`
      )
      .run(
        input.telegramId,
        input.username ?? null,
        input.firstName,
        input.lastName ?? null,
        input.languageCode ?? 'fa',
        now
      );

    return this.findById(Number(res.lastInsertRowid))!;
  }

  findActiveAdminByTelegramId(telegramId: string): AdminRecord | undefined {
    return this.db
      .prepare('SELECT * FROM admins WHERE telegram_id = ? AND is_active = 1')
      .get(telegramId) as AdminRecord | undefined;
  }

  ensureAdminRole(userId: number, telegramId: string, role: AdminRole, grantedBy?: number | null): AdminRecord {
    const existing = this.db
      .prepare('SELECT * FROM admins WHERE user_id = ?')
      .get(userId) as AdminRecord | undefined;
    const now = new Date().toISOString();

    if (existing) {
      this.db
        .prepare('UPDATE admins SET role = ?, is_active = 1, updated_at = ? WHERE id = ?')
        .run(role, now, existing.id);
      return this.db.prepare('SELECT * FROM admins WHERE id = ?').get(existing.id) as AdminRecord;
    }

    const res = this.db
      .prepare(
        `INSERT INTO admins (user_id, telegram_id, role, permissions_json, is_active, granted_by)
         VALUES (?, ?, ?, '[]', 1, ?)`
      )
      .run(userId, telegramId, role, grantedBy ?? null);

    return this.db
      .prepare('SELECT * FROM admins WHERE id = ?')
      .get(Number(res.lastInsertRowid)) as AdminRecord;
  }
}
