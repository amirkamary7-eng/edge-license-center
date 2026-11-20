/**
 * Minimal portable Cloudflare D1 & R2 interfaces compatible with Wrangler/Workers runtime
 * and Node-based SQLite Staging test harnesses.
 */

export interface D1Meta {
  changes: number;
  last_row_id: number;
  duration?: number;
}

export interface D1Result<T = Record<string, unknown>> {
  results: T[];
  success: boolean;
  meta: D1Meta;
}

export interface D1PreparedStatement {
  bind(...values: unknown[]): D1PreparedStatement;
  first<T = Record<string, unknown>>(colName?: string): Promise<T | null>;
  all<T = Record<string, unknown>>(): Promise<D1Result<T>>;
  run(): Promise<D1Result>;
}

export interface D1Database {
  prepare(query: string): D1PreparedStatement;
  batch<T = Record<string, unknown>>(statements: D1PreparedStatement[]): Promise<Array<D1Result<T>>>;
  exec?(query: string): Promise<{ count: number; duration: number }>;
}

export interface R2PutOptions {
  customMetadata?: Record<string, string>;
  httpMetadata?: { contentType?: string };
}

export interface R2ObjectBody {
  key: string;
  size: number;
  customMetadata?: Record<string, string>;
  arrayBuffer(): Promise<ArrayBuffer>;
  text(): Promise<string>;
}

export interface R2ListResult {
  objects: Array<{ key: string; size: number; uploaded: Date }>;
  truncated: boolean;
  cursor?: string;
}

export interface R2Bucket {
  put(
    key: string,
    value: ArrayBuffer | ArrayBufferView | string,
    options?: R2PutOptions
  ): Promise<{ key: string } | null>;
  get(key: string): Promise<R2ObjectBody | null>;
  list(options?: { prefix?: string; cursor?: string; limit?: number }): Promise<R2ListResult>;
  delete(keys: string | string[]): Promise<void>;
}

export interface WorkerEnv {
  DB?: D1Database;
  BACKUP_BUCKET?: R2Bucket;

  // Non-secret runtime configuration (vars)
  GATEWAY_PHASE?: string;
  ENVIRONMENT?: string;
  PAYMENT_VERIFICATION_MODE?: 'DRY_RUN' | 'LIVE';
  LICENSE_ISSUANCE_MODE?: 'DRY_RUN' | 'LIVE';
  TELEGRAM_BOT_SEND_ENABLED?: string;
  POLYGON_MIN_CONFIRMATIONS?: string;
  POLYGON_RPC_URL?: string;
  RSA_KEY_ID?: string;
  RATE_LIMIT_MAX_PER_MIN?: string;
  MINI_APP_URL?: string;
  BOOTSTRAP_SUPER_ADMIN_TELEGRAM_ID?: string;
  TELEGRAM_INIT_DATA_MAX_AGE_SECONDS?: string;
  SESSION_TTL_SECONDS?: string;
  HEARTBEAT_MAX_LAG_SECONDS?: string;
  BACKUP_RETENTION_DAYS?: string;
  ALLOW_PHASE0_PREVIEW_SESSION?: string;

  // Optional legacy Phase 1 proxy origin (used only when DB is unbound)
  ORIGIN_API_URL?: string;
  GATEWAY_SHARED_SECRET?: string;

  // Cloudflare Workers Secrets ONLY (never stored in Git, D1, R2, or tgcloud)
  TELEGRAM_BOT_TOKEN?: string;
  TELEGRAM_WEBHOOK_SECRET?: string;
  SESSION_SECRET?: string;
  RSA_PRIVATE_KEY_PEM?: string;
  RSA_PUBLIC_KEY_PEM?: string;
  BACKUP_RSA_PUBLIC_KEY_PEM?: string;

  // Test-only injectable fetch transport
  FETCH_IMPL?: typeof fetch;
}

export const DOMAIN_CONSTANTS = {
  brandName: 'EDGE LICENSE CENTER',
  brandOwner: 'AMIRBTC',
  productName: 'EDGE by AMIRBTC',
  botHandle: '@EDGE_LicenceBot',
  botUsername: 'EDGE_LicenceBot',
  networkName: 'Polygon PoS',
  chainId: 137,
  usdcContractAddress: '0x3c499c542cef5e3811e1192ce70d8cc03d5c3359',
  destinationWalletAddress: '0xf5fdefb5b02be3b7e16df37859dca111526bcc05',
  erc20TransferTopic: '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef',
  minConfirmations: 30,
  orderExpiryMinutes: 45,
} as const;
