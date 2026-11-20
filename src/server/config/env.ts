import 'dotenv/config';
import { z } from 'zod';

const EnvSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  APP_URL: z.string().default('http://localhost:3000'),
  PAYMENT_VERIFICATION_MODE: z.enum(['DRY_RUN', 'LIVE']).default('DRY_RUN'),
  LICENSE_ISSUANCE_MODE: z.enum(['DRY_RUN', 'LIVE']).default('DRY_RUN'),
  SQLITE_DB_PATH: z.string().default('./data/edge_license_center.sqlite'),
  SQLITE_BACKUP_DIR: z.string().default('./data/backups'),
  TELEGRAM_BOT_TOKEN: z.string().default(''),
  TELEGRAM_BOT_USERNAME: z.string().default('EDGE_LicenceBot'),
  TELEGRAM_WEBHOOK_SECRET: z.string().default(''),
  TELEGRAM_BOT_SEND_ENABLED: z
    .string()
    .default('false')
    .transform((v) => v === 'true'),
  TELEGRAM_INIT_DATA_MAX_AGE_SECONDS: z.coerce.number().int().min(30).max(86400).default(300),
  SESSION_SECRET: z.string().default(''),
  SESSION_TTL_SECONDS: z.coerce.number().int().min(60).max(86400).default(900),
  BOOTSTRAP_SUPER_ADMIN_TELEGRAM_ID: z.string().default(''),
  POLYGON_RPC_URL: z.string().url().default('https://polygon-rpc.com'),
  POLYGON_MIN_CONFIRMATIONS: z.coerce.number().int().min(1).max(256).default(30),
  POLYGON_RPC_TIMEOUT_MS: z.coerce.number().int().min(1000).max(30000).default(10000),
  REQUIRE_SENDER_WALLET_IN_LIVE: z
    .string()
    .default('true')
    .transform((v) => v !== 'false'),
  RSA_PRIVATE_KEY_PEM: z.string().default(''),
  RSA_PUBLIC_KEY_PEM: z.string().default(''),
  RSA_KEY_ID: z.string().default('edge-rsa-v1'),
  GATEWAY_SHARED_SECRET: z.string().default(''),
  RATE_LIMIT_ENABLED: z
    .string()
    .default('true')
    .transform((v) => v === 'true'),
  ALLOW_PHASE0_PREVIEW_SESSION: z
    .string()
    .default('false')
    .transform((v) => v === 'true'),
  SCHEDULER_ENABLED: z
    .string()
    .default('false')
    .transform((v) => v === 'true'),
  PAYMENT_POLL_INTERVAL_MS: z.coerce.number().int().min(5000).max(3600000).default(30000),
  NOTIFICATION_POLL_INTERVAL_MS: z.coerce.number().int().min(5000).max(3600000).default(15000),
  MAINTENANCE_INTERVAL_MS: z.coerce.number().int().min(10000).max(3600000).default(60000),
  BACKUP_INTERVAL_MS: z.coerce.number().int().min(60000).max(86400000).default(21600000),
  BACKUP_RETENTION_COUNT: z.coerce.number().int().min(2).max(100).default(14),
});

export type ServerEnv = z.infer<typeof EnvSchema>;

export function loadEnv(overrides?: Partial<Record<keyof NodeJS.ProcessEnv, string>>): ServerEnv {
  const merged = { ...process.env, ...overrides };
  return EnvSchema.parse(merged);
}

export const env: ServerEnv = loadEnv();
