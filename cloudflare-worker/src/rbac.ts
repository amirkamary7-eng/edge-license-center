/**
 * Cloudflare Worker RBAC Matrix & WebCrypto Bearer Session Tokens
 * Zero Node.js built-ins. Compatible with Workers & Vitest.
 */

import {
  base64ToBytes,
  bytesToBase64Url,
  sha256Hex,
  timingSafeEqualStrings,
} from './crypto';

export type AdminRole = 'super_admin' | 'admin' | 'finance' | 'support' | 'auditor';

export type AdminPermission =
  | 'dashboard:read'
  | 'users:read'
  | 'users:write'
  | 'orders:read'
  | 'orders:write'
  | 'payments:read'
  | 'payments:verify'
  | 'subscriptions:read'
  | 'subscriptions:write'
  | 'licenses:read'
  | 'licenses:write'
  | 'plans:read'
  | 'plans:write'
  | 'reports:finance'
  | 'reports:security'
  | 'admins:read'
  | 'admins:write'
  | 'settings:read'
  | 'settings:write';

export const ROLE_PERMISSIONS: Record<AdminRole, readonly AdminPermission[]> = {
  super_admin: [
    'dashboard:read',
    'users:read',
    'users:write',
    'orders:read',
    'orders:write',
    'payments:read',
    'payments:verify',
    'subscriptions:read',
    'subscriptions:write',
    'licenses:read',
    'licenses:write',
    'plans:read',
    'plans:write',
    'reports:finance',
    'reports:security',
    'admins:read',
    'admins:write',
    'settings:read',
    'settings:write',
  ],
  admin: [
    'dashboard:read',
    'users:read',
    'users:write',
    'orders:read',
    'orders:write',
    'payments:read',
    'subscriptions:read',
    'subscriptions:write',
    'licenses:read',
    'licenses:write',
    'plans:read',
    'reports:finance',
    'reports:security',
    'admins:read',
    'settings:read',
  ],
  finance: [
    'dashboard:read',
    'orders:read',
    'payments:read',
    'payments:verify',
    'subscriptions:read',
    'plans:read',
    'reports:finance',
  ],
  support: [
    'dashboard:read',
    'users:read',
    'orders:read',
    'payments:read',
    'subscriptions:read',
    'licenses:read',
    'plans:read',
  ],
  auditor: [
    'dashboard:read',
    'users:read',
    'orders:read',
    'payments:read',
    'subscriptions:read',
    'licenses:read',
    'plans:read',
    'reports:finance',
    'reports:security',
    'admins:read',
    'settings:read',
  ],
};

export function hasAdminPermission(
  role: AdminRole | null | undefined,
  permission: AdminPermission,
  extraPermissions: string[] = []
): boolean {
  if (!role) return false;
  if (ROLE_PERMISSIONS[role]?.includes(permission)) return true;
  return extraPermissions.includes(permission);
}

export function getEffectivePermissions(
  role: AdminRole | null | undefined,
  extraPermissions: string[] = []
): string[] {
  if (!role) return [];
  return Array.from(new Set([...ROLE_PERMISSIONS[role], ...extraPermissions]));
}

export interface SessionTokenPayload {
  v: 1;
  sub: string;
  uid: number;
  iat: number;
  exp: number;
}

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export async function deriveWorkerSessionSigningKey(
  explicitSessionSecret?: string,
  telegramBotToken?: string
): Promise<string> {
  if (explicitSessionSecret && explicitSessionSecret.trim().length >= 16) {
    return explicitSessionSecret.trim();
  }
  if (!telegramBotToken || !telegramBotToken.trim()) {
    throw new Error('SESSION_SIGNING_SECRET_NOT_CONFIGURED');
  }
  return sha256Hex(`edge-session-v1:${telegramBotToken.trim()}`);
}

async function signHmacBase64Url(secret: string, input: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    textEncoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, textEncoder.encode(input));
  return bytesToBase64Url(new Uint8Array(sig));
}

export async function signWorkerSessionToken(
  params: { telegramId: string; userId: number; ttlSeconds?: number; nowEpochSec?: number },
  signingKey: string
): Promise<{ token: string; expiresAt: string; payload: SessionTokenPayload }> {
  if (!signingKey || signingKey.trim().length < 16) {
    throw new Error('SESSION_SIGNING_KEY_TOO_SHORT');
  }
  const iat = params.nowEpochSec ?? Math.floor(Date.now() / 1000);
  const ttl = Math.max(60, Math.min(params.ttlSeconds ?? 900, 86400));
  const payload: SessionTokenPayload = {
    v: 1,
    sub: params.telegramId,
    uid: params.userId,
    iat,
    exp: iat + ttl,
  };
  const encodedPayload = bytesToBase64Url(textEncoder.encode(JSON.stringify(payload)));
  const sig = await signHmacBase64Url(signingKey, encodedPayload);
  return {
    token: `edge1.${encodedPayload}.${sig}`,
    expiresAt: new Date(payload.exp * 1000).toISOString(),
    payload,
  };
}

export async function verifyWorkerSessionToken(
  token: string,
  signingKey: string,
  nowEpochSec = Math.floor(Date.now() / 1000)
): Promise<SessionTokenPayload> {
  if (!signingKey || signingKey.trim().length < 16) {
    throw new Error('SESSION_SIGNING_KEY_MISSING');
  }
  const parts = token.trim().split('.');
  if (parts.length !== 3 || parts[0] !== 'edge1') {
    throw new Error('SESSION_TOKEN_MALFORMED');
  }
  const [, encodedPayload, providedSig] = parts;
  const expectedSig = await signHmacBase64Url(signingKey, encodedPayload);
  const valid = await timingSafeEqualStrings(providedSig, expectedSig);
  if (!valid) {
    throw new Error('SESSION_TOKEN_SIGNATURE_INVALID');
  }
  const decoded = JSON.parse(textDecoder.decode(base64ToBytes(encodedPayload))) as SessionTokenPayload;
  if (
    !decoded ||
    decoded.v !== 1 ||
    typeof decoded.sub !== 'string' ||
    typeof decoded.uid !== 'number' ||
    typeof decoded.exp !== 'number'
  ) {
    throw new Error('SESSION_TOKEN_CLAIMS_INVALID');
  }
  if (decoded.exp <= nowEpochSec) {
    throw new Error('SESSION_TOKEN_EXPIRED');
  }
  return decoded;
}
