import { TelegramBotApiClient } from '../bot/telegramClient';
import { env } from '../config/env';
import { openDatabase } from '../db/connection';
import { runMigrations } from '../db/migrator';
import { LicenseService } from '../modules/license/licenseService';
import { PaymentService } from '../modules/payment/paymentService';
import { PolygonRpcClient } from '../modules/payment/polygonVerifier';
import { BackgroundScheduler } from './scheduler';

async function main() {
  const includeBackup = process.argv.includes('--with-backup');
  const db = openDatabase(env.SQLITE_DB_PATH);
  try {
    runMigrations(db);

    const licenseService = new LicenseService(db, {
      issuanceMode: env.LICENSE_ISSUANCE_MODE,
      rsaPrivateKeyPem: env.RSA_PRIVATE_KEY_PEM,
      rsaPublicKeyPem: env.RSA_PUBLIC_KEY_PEM,
      rsaKeyId: env.RSA_KEY_ID,
    });

    const rpcProvider = new PolygonRpcClient(env.POLYGON_RPC_URL, {
      timeoutMs: env.POLYGON_RPC_TIMEOUT_MS,
    });

    const paymentService = new PaymentService(db, {
      verificationMode: env.PAYMENT_VERIFICATION_MODE,
      minConfirmations: env.POLYGON_MIN_CONFIRMATIONS,
      requireSenderWalletInLive: env.REQUIRE_SENDER_WALLET_IN_LIVE,
      rpcProvider,
      licenseService,
    });

    const botClient = env.TELEGRAM_BOT_TOKEN
      ? new TelegramBotApiClient(env.TELEGRAM_BOT_TOKEN)
      : undefined;

    const scheduler = new BackgroundScheduler({
      db,
      paymentService,
      verificationMode: env.PAYMENT_VERIFICATION_MODE,
      telegramBotSendEnabled: env.TELEGRAM_BOT_SEND_ENABLED,
      botClient,
      backupDir: env.SQLITE_BACKUP_DIR,
      backupRetentionCount: env.BACKUP_RETENTION_COUNT,
    });

    const result = await scheduler.runAllOnce({ includeBackup });
    console.log(
      JSON.stringify(
        {
          event: 'edge_jobs_run_once_complete',
          paymentMode: env.PAYMENT_VERIFICATION_MODE,
          licenseMode: env.LICENSE_ISSUANCE_MODE,
          telegramBotSendEnabled: env.TELEGRAM_BOT_SEND_ENABLED,
          result,
        },
        null,
        2
      )
    );
  } finally {
    db.close();
  }
}

main().catch((err) => {
  console.error('Worker CLI failed:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
