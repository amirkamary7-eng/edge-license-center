import { env } from '../config/env';
import { createDatabaseBackup, restoreDatabaseBackup } from './backup';
import { openDatabase } from './connection';

async function main() {
  const mode = process.argv[2] ?? 'backup';

  if (mode === 'backup') {
    const db = openDatabase(env.SQLITE_DB_PATH);
    try {
      const meta = await createDatabaseBackup(db, env.SQLITE_BACKUP_DIR);
      console.log(JSON.stringify({ event: 'db_backup_complete', ...meta }));
    } finally {
      db.close();
    }
    return;
  }

  if (mode === 'restore') {
    const sourceFile = process.argv[3];
    if (!sourceFile) {
      console.error('Usage: tsx src/server/db/backupCli.ts restore <backup_file.sqlite>');
      process.exit(1);
    }
    const result = restoreDatabaseBackup(sourceFile, env.SQLITE_DB_PATH, {
      requireChecksumFile: true,
    });
    console.log(JSON.stringify({ event: 'db_restore_complete', ...result }));
    return;
  }

  console.error(`Unknown mode: ${mode}`);
  process.exit(1);
}

main().catch((err) => {
  console.error('Backup CLI error:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
