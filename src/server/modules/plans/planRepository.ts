import type { SqliteDb } from '../../db/connection';
import type { PlanRecord } from '../../../shared/types';

export class PlanRepository {
  constructor(private readonly db: SqliteDb) {}

  listActive(): PlanRecord[] {
    return this.db
      .prepare('SELECT * FROM plans WHERE is_active = 1 ORDER BY sort_order ASC')
      .all() as PlanRecord[];
  }

  listAll(): PlanRecord[] {
    return this.db.prepare('SELECT * FROM plans ORDER BY sort_order ASC').all() as PlanRecord[];
  }

  findByCode(code: string): PlanRecord | undefined {
    return this.db.prepare('SELECT * FROM plans WHERE code = ?').get(code) as PlanRecord | undefined;
  }

  findById(id: number): PlanRecord | undefined {
    return this.db.prepare('SELECT * FROM plans WHERE id = ?').get(id) as PlanRecord | undefined;
  }
}
