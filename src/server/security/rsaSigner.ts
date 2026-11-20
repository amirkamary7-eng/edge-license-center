import crypto from 'crypto';

export interface LicenseSignaturePayload {
  licenseKey: string;
  product: 'EDGE by AMIRBTC';
  telegramId: string;
  planCode: string;
  maxDevices: number;
  issuedAt: string;
  expiresAt: string;
  keyId: string;
}

/**
 * Canonicalizes a payload with deterministically sorted object keys
 * so RSA signatures remain verifiable across Node.js and Android (Kotlin/Java).
 */
export function canonicalizePayload(payload: LicenseSignaturePayload): string {
  const sorted: Record<string, unknown> = {};
  for (const key of Object.keys(payload).sort()) {
    sorted[key] = payload[key as keyof LicenseSignaturePayload];
  }
  return JSON.stringify(sorted);
}

export function normalizePemFromEnv(pem: string): string {
  return pem.replace(/\\n/g, '\n').trim();
}

export function signLicensePayload(payload: LicenseSignaturePayload, privateKeyPem: string): {
  canonicalJson: string;
  signatureBase64: string;
} {
  const cleanKey = normalizePemFromEnv(privateKeyPem);
  if (!cleanKey.includes('PRIVATE KEY')) {
    throw new Error('RSA_PRIVATE_KEY_INVALID');
  }
  const canonicalJson = canonicalizePayload(payload);
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(canonicalJson, 'utf8');
  signer.end();
  const signatureBase64 = signer.sign(cleanKey, 'base64');
  return { canonicalJson, signatureBase64 };
}

export function verifyLicenseSignature(
  canonicalJson: string,
  signatureBase64: string,
  publicKeyPem: string
): boolean {
  const cleanKey = normalizePemFromEnv(publicKeyPem);
  if (!cleanKey.includes('PUBLIC KEY')) {
    return false;
  }
  try {
    const verifier = crypto.createVerify('RSA-SHA256');
    verifier.update(canonicalJson, 'utf8');
    verifier.end();
    return verifier.verify(cleanKey, signatureBase64, 'base64');
  } catch {
    return false;
  }
}

export function generateEphemeralRsaKeyPair(): {
  privateKeyPem: string;
  publicKeyPem: string;
} {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  return { privateKeyPem: privateKey, publicKeyPem: publicKey };
}
