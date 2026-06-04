import { createRemoteJWKSet, jwtVerify } from 'jose';
import { config } from '../config';
import { checkAndStoreJti } from './replay';

export interface IdJagResult {
  ok: boolean;
  error?: string;
  email?: string;
  jti?: string;
}

export async function verifyIdJag(assertion: string): Promise<IdJagResult> {
  const header = parseJwtHeader(assertion);
  if (!header) return { ok: false, error: 'invalid_signature' };

  // Find the matching issuer from the payload (decode without verify first to get iss)
  const payload = parseJwtPayload(assertion);
  if (!payload) return { ok: false, error: 'invalid_signature' };

  const issuerConfig = config.trustedIssuers.find(i => i.iss === payload.iss);
  if (!issuerConfig) return { ok: false, error: 'issuer_not_enabled' };

  const resource = config.resourceHost.endsWith('/') ? config.resourceHost : config.resourceHost + '/';

  try {
    const JWKS = createRemoteJWKSet(new URL(issuerConfig.jwks_uri));
    const { payload: verified } = await jwtVerify(assertion, JWKS, {
      audience: resource,
      clockTolerance: 30,
    });

    const now = Math.floor(Date.now() / 1000);

    if (!verified.jti) return { ok: false, error: 'invalid_signature' };

    // Enforce near-term exp: must expire within 10 minutes from now
    if (!verified.exp || verified.exp > now + 600) return { ok: false, error: 'credential_expired' };

    // Check replay
    const stored = checkAndStoreJti(verified.jti, verified.exp * 1000);
    if (!stored) return { ok: false, error: 'replay_detected' };

    return {
      ok: true,
      email: verified['email'] as string | undefined,
      jti: verified.jti,
    };
  } catch (err: any) {
    if (err?.code === 'ERR_JWT_EXPIRED') return { ok: false, error: 'credential_expired' };
    if (err?.code === 'ERR_JWS_INVALID' || err?.code === 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED') {
      return { ok: false, error: 'invalid_signature' };
    }
    if (err?.code === 'ERR_JWT_CLAIM_VALIDATION_FAILED' && err?.claim === 'aud') {
      return { ok: false, error: 'audience_mismatch' };
    }
    return { ok: false, error: 'invalid_signature' };
  }
}

function parseJwtHeader(jwt: string): Record<string, unknown> | null {
  try {
    const [headerB64] = jwt.split('.');
    return JSON.parse(Buffer.from(headerB64, 'base64url').toString());
  } catch {
    return null;
  }
}

function parseJwtPayload(jwt: string): Record<string, unknown> | null {
  try {
    const [, payloadB64] = jwt.split('.');
    return JSON.parse(Buffer.from(payloadB64, 'base64url').toString());
  } catch {
    return null;
  }
}
