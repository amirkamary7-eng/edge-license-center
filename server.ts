import express from 'express';
import fs from 'fs';
import path from 'path';
import { createApiApp } from './src/server/app';
import { TelegramBotApiClient } from './src/server/bot/telegramClient';
import { env } from './src/server/config/env';
import { openDatabase } from './src/server/db/connection';
import { runMigrations } from './src/server/db/migrator';
import { BackgroundScheduler } from './src/server/jobs/scheduler';
import { LicenseService } from './src/server/modules/license/licenseService';
import { PaymentService } from './src/server/modules/payment/paymentService';
import { PolygonRpcClient } from './src/server/modules/payment/polygonVerifier';

async function startServer() {
  const db = openDatabase(env.SQLITE_DB_PATH);
  const migrationResult = runMigrations(db);
  console.log(
    JSON.stringify({
      event: 'edge_license_center_boot',
      nodeEnv: env.NODE_ENV,
      sqlitePath: env.SQLITE_DB_PATH,
      migrationsApplied: migrationResult.applied.length,
      migrationsTotal: migrationResult.totalAvailable,
      verifiedChecksums: migrationResult.verifiedChecksums,
      paymentMode: env.PAYMENT_VERIFICATION_MODE,
      licenseMode: env.LICENSE_ISSUANCE_MODE,
      schedulerEnabled: env.SCHEDULER_ENABLED,
    })
  );

  const app = createApiApp({ db, env });

  let scheduler: BackgroundScheduler | null = null;
  if (env.SCHEDULER_ENABLED) {
    const licenseService = new LicenseService(db, {
      issuanceMode: env.LICENSE_ISSUANCE_MODE,
      rsaPrivateKeyPem: env.RSA_PRIVATE_KEY_PEM,
      rsaPublicKeyPem: env.RSA_PUBLIC_KEY_PEM,
      rsaKeyId: env.RSA_KEY_ID,
    });
    const paymentService = new PaymentService(db, {
      verificationMode: env.PAYMENT_VERIFICATION_MODE,
      minConfirmations: env.POLYGON_MIN_CONFIRMATIONS,
      requireSenderWalletInLive: env.REQUIRE_SENDER_WALLET_IN_LIVE,
      rpcProvider: new PolygonRpcClient(env.POLYGON_RPC_URL, {
        timeoutMs: env.POLYGON_RPC_TIMEOUT_MS,
      }),
      licenseService,
    });
    const botClient = env.TELEGRAM_BOT_TOKEN
      ? new TelegramBotApiClient(env.TELEGRAM_BOT_TOKEN)
      : undefined;

    scheduler = new BackgroundScheduler({
      db,
      paymentService,
      verificationMode: env.PAYMENT_VERIFICATION_MODE,
      telegramBotSendEnabled: env.TELEGRAM_BOT_SEND_ENABLED,
      botClient,
      backupDir: env.SQLITE_BACKUP_DIR,
      backupRetentionCount: env.BACKUP_RETENTION_COUNT,
      paymentPollIntervalMs: env.PAYMENT_POLL_INTERVAL_MS,
      notificationPollIntervalMs: env.NOTIFICATION_POLL_INTERVAL_MS,
      maintenanceIntervalMs: env.MAINTENANCE_INTERVAL_MS,
      backupIntervalMs: env.BACKUP_INTERVAL_MS,
    });
    scheduler.start();
  }

  const distDir = path.resolve(process.cwd(), 'dist');
  const isProd = env.NODE_ENV === 'production' && fs.existsSync(distDir);

  if (!isProd) {
    // Dynamic import so bundled production runtime never loads Vite
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(distDir));
    app.get('*', (req, res, next) => {
      if (req.path.startsWith('/api/')) {
        next();
        return;
      }
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  const server = app.listen(env.PORT, '0.0.0.0', () => {
    console.log(`EDGE LICENSE CENTER listening on http://0.0.0.0:${env.PORT}`);
  });

  const shutdown = () => {
    scheduler?.stop();
    server.close(() => {
      db.close();
      process.exit(0);
    });
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

startServer().catch((err) => {
  console.error('Fatal startup error:', err instanceof Error ? err.message : String(err));
  process.exit(1);
});
