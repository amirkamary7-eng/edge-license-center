/**
 * Pure WebCrypto Cryptography for Cloudflare Worker (Zero Node built-in dependencies)
 * - Deterministic Canonical JSON
 * - RSA-2048 / SHA-256 signing & verification (PKCS#8 / SPKI PEM)
 * - Android Keystore ECDSA P-256 / SHA-256 proof-of-possession verification
 * - Telegram Mini App initData HMAC-SHA256 verification
 * - AES-256-GCM + RSA-OAEP-256 backup encryption (decryption private key strictly offline)
 */

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export function canonicalizeJson(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalizeJson(item)).join(',')}]`;
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalizeJson(obj[k])}`).join(',')}}`;
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function base64ToBytes(b64: string): Uint8Array {
  const normalized = b64.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
}

export function bytesToBase64Url(bytes: Uint8Array): string {
  return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.trim().toLowerCase();
  if (!/^[0-9a-f]*$/.test(clean) || clean.length % 2 !== 0) {
    throw new Error('INVALID_HEX_STRING');
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function pemToDerBytes(pem: string): Uint8Array {
  const body = pem
    .replace(/-----BEGIN [A-Z0-9 ]+-----/g, '')
    .replace(/-----END [A-Z0-9 ]+-----/g, '')
    .replace(/\s+/g, '');
  return base64ToBytes(body);
}

export async function sha256Hex(input: string | Uint8Array): Promise<string> {
  const data = typeof input === 'string' ? textEncoder.encode(input) : input;
  const digest = await crypto.subtle.digest('SHA-256', data as BufferSource);
  return bytesToHex(new Uint8Array(digest));
}

export function randomHex(byteLength = 16): string {
  const buf = new Uint8Array(byteLength);
  crypto.getRandomValues(buf);
  return bytesToHex(buf);
}

/**
 * Constant-time string comparison by comparing fixed-length SHA-256 digests.
 */
export async function timingSafeEqualStrings(a: string, b: string): Promise<boolean> {
  const [da, db] = await Promise.all([
    crypto.subtle.digest('SHA-256', textEncoder.encode(a)),
    crypto.subtle.digest('SHA-256', textEncoder.encode(b)),
  ]);
  const va = new Uint8Array(da);
  const vb = new Uint8Array(db);
  let diff = a.length === b.length ? 0 : 1;
  for (let i = 0; i < va.length; i++) {
    diff |= va[i] ^ vb[i];
  }
  return diff === 0;
}

export async function signRsaSha256(
  payload: Record<string, unknown>,
  privateKeyPem: string
): Promise<{ canonicalJson: string; signatureBase64: string }> {
  if (!privateKeyPem || !privateKeyPem.includes('PRIVATE KEY')) {
    throw new Error('RSA_PRIVATE_KEY_MISSING');
  }
  const canonicalJson = canonicalizeJson(payload);
  const key = await crypto.subtle.importKey(
    'pkcs8',
    pemToDerBytes(privateKeyPem) as BufferSource,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sigBuf = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    key,
    textEncoder.encode(canonicalJson)
  );
  return {
    canonicalJson,
    signatureBase64: bytesToBase64Url(new Uint8Array(sigBuf)),
  };
}

export async function verifyRsaSha256(
  canonicalJson: string,
  signatureBase64: string,
  publicKeyPem: string
): Promise<boolean> {
  if (!publicKeyPem || !publicKeyPem.includes('PUBLIC KEY')) {
    return false;
  }
  try {
    const key = await crypto.subtle.importKey(
      'spki',
      pemToDerBytes(publicKeyPem) as BufferSource,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['verify']
    );
    const sigBytes = base64ToBytes(signatureBase64);
    return await crypto.subtle.verify(
      'RSASSA-PKCS1-v1_5',
      key,
      sigBytes as BufferSource,
      textEncoder.encode(canonicalJson)
    );
  } catch {
    return false;
  }
}

/**
 * Converts an ASN.1 DER-encoded ECDSA P-256 signature (Android Keystore `SHA256withECDSA`)
 * into IEEE P1363 raw 64-byte `(r || s)` format required by WebCrypto `crypto.subtle.verify`.
 * Passes through if already 64 bytes raw P1363.
 */
export function normalizeEcdsaP256Signature(sigBytes: Uint8Array): Uint8Array | null {
  if (sigBytes.length === 64) {
    return sigBytes;
  }
  if (sigBytes.length < 8 || sigBytes[0] !== 0x30) {
    return null;
  }
  let offset = 2;
  if (sigBytes[1] & 0x80) {
    const lenBytes = sigBytes[1] & 0x7f;
    offset = 2 + lenBytes;
  }
  if (offset >= sigBytes.length || sigBytes[offset] !== 0x02) return null;
  const rLen = sigBytes[offset + 1];
  const rStart = offset + 2;
  const rEnd = rStart + rLen;
  if (rEnd >= sigBytes.length || sigBytes[rEnd] !== 0x02) return null;
  const sLen = sigBytes[rEnd + 1];
  const sStart = rEnd + 2;
  const sEnd = sStart + sLen;
  if (sEnd > sigBytes.length) return null;

  const rRaw = sigBytes.slice(rStart, rEnd);
  const sRaw = sigBytes.slice(sStart, sEnd);

  const trimPad32 = (part: Uint8Array): Uint8Array | null => {
    let i = 0;
    while (i < part.length - 1 && part[i] === 0) i++;
    const trimmed = part.slice(i);
    if (trimmed.length > 32) return null;
    const out = new Uint8Array(32);
    out.set(trimmed, 32 - trimmed.length);
    return out;
  };

  const r32 = trimPad32(rRaw);
  const s32 = trimPad32(sRaw);
  if (!r32 || !s32) return null;

  const out = new Uint8Array(64);
  out.set(r32, 0);
  out.set(s32, 32);
  return out;
}

export async function verifyEcdsaP256Signature(
  message: string,
  signatureBase64: string,
  devicePublicKeySpkiBase64: string
): Promise<boolean> {
  try {
    const spkiBytes = base64ToBytes(
      devicePublicKeySpkiBase64.includes('PUBLIC KEY')
        ? bytesToBase64(pemToDerBytes(devicePublicKeySpkiBase64))
        : devicePublicKeySpkiBase64
    );
    const sigRaw = base64ToBytes(signatureBase64);
    const p1363 = normalizeEcdsaP256Signature(sigRaw);
    if (!p1363) return false;

    const key = await crypto.subtle.importKey(
      'spki',
      spkiBytes as BufferSource,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify']
    );
    return await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      key,
      p1363 as BufferSource,
      textEncoder.encode(message)
    );
  } catch {
    return false;
  }
}

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

export async function verifyTelegramInitDataWebCrypto(
  initDataRaw: string,
  botToken: string,
  options?: { maxAgeSeconds?: number; nowEpochSeconds?: number }
): Promise<VerifiedTelegramInitData> {
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

  const webAppKey = await crypto.subtle.importKey(
    'raw',
    textEncoder.encode('WebAppData'),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const secretKeyBytes = await crypto.subtle.sign(
    'HMAC',
    webAppKey,
    textEncoder.encode(botToken)
  );
  const secretHmacKey = await crypto.subtle.importKey(
    'raw',
    secretKeyBytes,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const computedBuf = await crypto.subtle.sign(
    'HMAC',
    secretHmacKey,
    textEncoder.encode(dataCheckString)
  );
  const computedHex = bytesToHex(new Uint8Array(computedBuf));

  const validSig = await timingSafeEqualStrings(providedHash.toLowerCase(), computedHex);
  if (!validSig) {
    throw new Error('TELEGRAM_SIGNATURE_MISMATCH');
  }

  const authDate = Number(params.get('auth_date'));
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
 * Envelope encryption for R2 backups:
 * - Generates an ephemeral 256-bit AES-GCM Data Encryption Key (DEK).
 * - Encrypts the canonical backup archive JSON with AES-256-GCM.
 * - Wraps the DEK with the Backup RSA-OAEP-256 PUBLIC key ONLY.
 * - The corresponding RSA-OAEP PRIVATE key stays strictly offline (never in Worker/D1/R2/GitHub).
 */
export interface EncryptedBackupEnvelope {
  version: 1;
  algorithm: 'AES-256-GCM+RSA-OAEP-256';
  wrappedDekBase64: string;
  ivBase64: string;
  ciphertextBase64: string;
  plaintextSha256: string;
  createdAtUtc: string;
}

export async function encryptBackupWithOfflinePublicKey(
  plaintextUtf8: string,
  backupPublicKeyPem: string
): Promise<EncryptedBackupEnvelope> {
  if (!backupPublicKeyPem || !backupPublicKeyPem.includes('PUBLIC KEY')) {
    throw new Error('BACKUP_PUBLIC_KEY_MISSING');
  }
  const plainBytes = textEncoder.encode(plaintextUtf8);
  const plaintextSha256 = await sha256Hex(plainBytes);

  const dek = new Uint8Array(32);
  const iv = new Uint8Array(12);
  crypto.getRandomValues(dek);
  crypto.getRandomValues(iv);

  const aesKey = await crypto.subtle.importKey('raw', dek, { name: 'AES-GCM' }, false, ['encrypt']);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, plainBytes);

  const rsaPub = await crypto.subtle.importKey(
    'spki',
    pemToDerBytes(backupPublicKeyPem) as BufferSource,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['encrypt']
  );
  const wrappedDek = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, rsaPub, dek);

  return {
    version: 1,
    algorithm: 'AES-256-GCM+RSA-OAEP-256',
    wrappedDekBase64: bytesToBase64(new Uint8Array(wrappedDek)),
    ivBase64: bytesToBase64(iv),
    ciphertextBase64: bytesToBase64(new Uint8Array(ciphertext)),
    plaintextSha256,
    createdAtUtc: new Date().toISOString(),
  };
}

/**
 * Used strictly in offline recovery tools or Staging round-trip tests where the
 * test-only offline decryption key is explicitly supplied.
 */
export async function decryptBackupEnvelope(
  envelope: EncryptedBackupEnvelope,
  backupPrivateKeyPem: string
): Promise<string> {
  const rsaPriv = await crypto.subtle.importKey(
    'pkcs8',
    pemToDerBytes(backupPrivateKeyPem) as BufferSource,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['decrypt']
  );
  const dekBuf = await crypto.subtle.decrypt(
    { name: 'RSA-OAEP' },
    rsaPriv,
    base64ToBytes(envelope.wrappedDekBase64) as BufferSource
  );
  const aesKey = await crypto.subtle.importKey('raw', dekBuf, { name: 'AES-GCM' }, false, ['decrypt']);
  const plainBuf = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: base64ToBytes(envelope.ivBase64) as BufferSource },
    aesKey,
    base64ToBytes(envelope.ciphertextBase64) as BufferSource
  );
  const plainBytes = new Uint8Array(plainBuf);
  const actualSha = await sha256Hex(plainBytes);
  if (actualSha !== envelope.plaintextSha256) {
    throw new Error('BACKUP_PLAINTEXT_CHECKSUM_MISMATCH');
  }
  return textDecoder.decode(plainBytes);
}
