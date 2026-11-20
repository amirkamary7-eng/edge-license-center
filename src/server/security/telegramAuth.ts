import crypto from 'crypto';

export interface TelegramWebAppUser {
  id: number;
  first_name: string;
  last_name?: string;
  username?: string;
  language_code?: string;
}

export interface VerifiedTelegramInitData {
  user: TelegramWebAppUser;
  authDate: number;
  queryId?: string;
  hash: string;
}

/**
 * Validates Telegram Mini App `window.Telegram.WebApp.initData` according to
 * the official Telegram Bot API specification:
 * 1. Parse URL-encoded query string.
 * 2. Sort all keys except `hash` alphabetically and join as `key=value\n`.
 * 3. Derive secret key = HMAC_SHA256("WebAppData", botToken).
 * 4. Compute expectedHash = HEX(HMAC_SHA256(secretKey, dataCheckString)).
 * 5. Compare using constant-time `crypto.timingSafeEqual`.
 * 6. Reject stale `auth_date` timestamps beyond `maxAgeSeconds` (anti-replay).
 */
export function verifyTelegramInitData(
  initDataRaw: string,
  botToken: string,
  options?: { maxAgeSeconds?: number; nowEpochSeconds?: number }
): VerifiedTelegramInitData {
  if (!initDataRaw || !initDataRaw.trim()) {
    throw new Error('TELEGRAM_INIT_DATA_MISSING');
  }
  if (!botToken || !botToken.trim()) {
    throw new Error('TELEGRAM_BOT_TOKEN_NOT_CONFIGURED');
  }

  const params = new URLSearchParams(initDataRaw);
  const providedHash = params.get('hash');
  if (!providedHash || !/^[a-f0-9]{64}$/i.test(providedHash)) {
    throw new Error('TELEGRAM_HASH_INVALID_FORMAT');
  }

  const pairs: string[] = [];
  for (const [key, value] of params.entries()) {
    if (key === 'hash') continue;
    pairs.push(`${key}=${value}`);
  }
  pairs.sort();
  const dataCheckString = pairs.join('\n');

  const secretKey = crypto.createHmac('sha256', 'WebAppData').update(botToken).digest();
  const computedHash = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest('hex');

  const providedBuf = Buffer.from(providedHash.toLowerCase(), 'hex');
  const computedBuf = Buffer.from(computedHash.toLowerCase(), 'hex');
  if (providedBuf.length !== computedBuf.length || !crypto.timingSafeEqual(providedBuf, computedBuf)) {
    throw new Error('TELEGRAM_SIGNATURE_MISMATCH');
  }

  const authDateRaw = params.get('auth_date');
  const authDate = Number(authDateRaw);
  if (!Number.isInteger(authDate) || authDate <= 0) {
    throw new Error('TELEGRAM_AUTH_DATE_INVALID');
  }

  const maxAge = options?.maxAgeSeconds ?? 300;
  const nowSec = options?.nowEpochSeconds ?? Math.floor(Date.now() / 1000);
  if (nowSec - authDate > maxAge) {
    throw new Error('TELEGRAM_INIT_DATA_EXPIRED');
  }
  if (authDate - nowSec > 60) {
    throw new Error('TELEGRAM_AUTH_DATE_IN_FUTURE');
  }

  const userRaw = params.get('user');
  if (!userRaw) {
    throw new Error('TELEGRAM_USER_PAYLOAD_MISSING');
  }

  let parsedUser: TelegramWebAppUser;
  try {
    parsedUser = JSON.parse(userRaw) as TelegramWebAppUser;
  } catch {
    throw new Error('TELEGRAM_USER_JSON_INVALID');
  }

  if (!parsedUser || typeof parsedUser.id !== 'number' || !parsedUser.first_name) {
    throw new Error('TELEGRAM_USER_FIELDS_INVALID');
  }

  return {
    user: parsedUser,
    authDate,
    queryId: params.get('query_id') ?? undefined,
    hash: providedHash.toLowerCase(),
  };
}

/**
 * Helper used strictly in automated tests to produce spec-compliant signed initData.
 */
export function createSignedTelegramInitData(
  user: TelegramWebAppUser,
  botToken: string,
  authDate = Math.floor(Date.now() / 1000)
): string {
  const params = new URLSearchParams();
  params.set('auth_date', String(authDate));
  params.set('query_id', 'AAHdF6IQAAAAAN0XohDhrOrc');
  params.set('user', JSON.stringify(user));

  const pairs: string[] = [];
  for (const [key, value] of params.entries()) {
    pairs.push(`${key}=${value}`);
  }
  pairs.sort();

  const secretKey = crypto.createHmac('sha256', 'WebAppData').update(botToken).digest();
  const hash = crypto.createHmac('sha256', secretKey).update(pairs.join('\n')).digest('hex');
  params.set('hash', hash);
  return params.toString();
}
