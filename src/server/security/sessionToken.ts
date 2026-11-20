import crypto from 'crypto';

export interface SessionTokenPayload {
  sub: string; // telegram_id
  uid: number; // internal user id
  iat: number; // epoch seconds
  exp: number; // epoch seconds
  jti: string; // unique token id
}

function base64UrlEncode(input: Buffer | string): string {
  return Buffer.from(input).toString('base64url');
}

function base64UrlDecode(input: string): string {
  return Buffer.from(input, 'base64url').toString('utf8');
}

export function deriveSessionSigningKey(sessionSecret: string, botToken: string): string {
  const material = sessionSecret.trim() || botToken.trim();
  if (!material) {
    throw new Error('SESSION_SIGNING_SECRET_NOT_CONFIGURED');
  }
  return crypto.createHmac('sha256', 'EDGE_SESSION_V1').update(material).digest('hex');
}

export function signSessionToken(
  params: { telegramId: string; userId: number; ttlSeconds: number },
  signingKey: string
): { token: string; expiresAt: string } {
  const now = Math.floor(Date.now() / 1000);
  const payload: SessionTokenPayload = {
    sub: params.telegramId,
    uid: params.userId,
    iat: now,
    exp: now + params.ttlSeconds,
    jti: crypto.randomBytes(12).toString('hex'),
  };

  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const signature = crypto
    .createHmac('sha256', signingKey)
    .update(encodedPayload)
    .digest('base64url');

  return {
    token: `edge1.${encodedPayload}.${signature}`,
    expiresAt: new Date(payload.exp * 1000).toISOString(),
  };
}

export function verifySessionToken(
  token: string,
  signingKey: string,
  nowEpochSeconds = Math.floor(Date.now() / 1000)
): SessionTokenPayload {
  const parts = token.trim().split('.');
  if (parts.length !== 3 || parts[0] !== 'edge1') {
    throw new Error('SESSION_TOKEN_MALFORMED');
  }

  const [, encodedPayload, providedSig] = parts;
  const expectedSig = crypto
    .createHmac('sha256', signingKey)
    .update(encodedPayload)
    .digest('base64url');

  const a = Buffer.from(providedSig, 'utf8');
  const b = Buffer.from(expectedSig, 'utf8');
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    throw new Error('SESSION_TOKEN_INVALID_SIGNATURE');
  }

  const parsed = JSON.parse(base64UrlDecode(encodedPayload)) as SessionTokenPayload;
  if (!parsed?.sub || typeof parsed.uid !== 'number' || typeof parsed.exp !== 'number') {
    throw new Error('SESSION_TOKEN_INVALID_PAYLOAD');
  }
  if (nowEpochSeconds >= parsed.exp) {
    throw new Error('SESSION_TOKEN_EXPIRED');
  }

  return parsed;
}
