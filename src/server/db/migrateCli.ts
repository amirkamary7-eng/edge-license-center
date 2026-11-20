import { env } from '../config/env';
import { openDatabase } from './connection';
import { runMigrations } from './migrator';

const db = openDatabase(env.SQLITE_DB_PATH);
try {
  const result = runMigrations(db);
  console.log(
    JSON.stringify({
      event: 'db_migrate_complete',
      dbPath: env.SQLITE_DB_PATH,
      applied: result.applied,
      skipped: result.skipped,
      totalAvailable: result.totalAvailable,
    })
  );
} finally {
  db.close();
}
