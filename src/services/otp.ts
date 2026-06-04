import { getDb } from '../db';
import { sha256, generateToken, generateOtp } from '../crypto';
import { config } from '../config';

export interface ClaimSession {
  claim_token_hash: string;
  credential_id: string | null;
  email: string | null;
  otp_hash: string | null;
  flow: 'anonymous' | 'verified_email';
  created_at: number;
  expires_at: number;
  used: boolean;
}

export function createClaimSession(opts: {
  flow: 'anonymous' | 'verified_email';
  credentialId?: string;
  email?: string;
}): { claimToken: string; otp: string } {
  const db = getDb();
  const claimToken = generateToken();
  const otp = generateOtp();
  const now = Date.now();

  db.prepare(`
    INSERT INTO claim_sessions
      (claim_token_hash, credential_id, email, otp_hash, flow, created_at, expires_at, used)
    VALUES (?, ?, ?, ?, ?, ?, ?, 0)
  `).run(
    sha256(claimToken),
    opts.credentialId ?? null,
    opts.email ?? null,
    sha256(otp),
    opts.flow,
    now,
    now + config.claimTokenTtlMs
  );

  return { claimToken, otp };
}

export function attachOtpToSession(claimTokenHash: string, email: string): string | null {
  const db = getDb();
  const session = db.prepare(
    'SELECT * FROM claim_sessions WHERE claim_token_hash = ? AND used = 0 AND expires_at > ?'
  ).get(claimTokenHash, Date.now()) as any;

  if (!session) return null;

  const otp = generateOtp();
  db.prepare(
    'UPDATE claim_sessions SET otp_hash = ?, email = ?, expires_at = ? WHERE claim_token_hash = ?'
  ).run(sha256(otp), email, Date.now() + config.otpTtlMs, claimTokenHash);

  return otp;
}

export function verifyOtp(claimToken: string, otp: string): ClaimSession | null {
  const db = getDb();
  const now = Date.now();
  const session = db.prepare(
    'SELECT * FROM claim_sessions WHERE claim_token_hash = ? AND used = 0 AND expires_at > ?'
  ).get(sha256(claimToken), now) as any;

  if (!session) return null;
  if (session.otp_hash !== sha256(otp)) return null;

  db.prepare('UPDATE claim_sessions SET used = 1 WHERE claim_token_hash = ?').run(sha256(claimToken));

  return {
    claim_token_hash: session.claim_token_hash,
    credential_id: session.credential_id,
    email: session.email,
    otp_hash: session.otp_hash,
    flow: session.flow,
    created_at: session.created_at,
    expires_at: session.expires_at,
    used: true,
  };
}

export function getClaimSession(claimToken: string): ClaimSession | null {
  const db = getDb();
  const session = db.prepare(
    'SELECT * FROM claim_sessions WHERE claim_token_hash = ? AND used = 0 AND expires_at > ?'
  ).get(sha256(claimToken), Date.now()) as any;
  if (!session) return null;
  return {
    claim_token_hash: session.claim_token_hash,
    credential_id: session.credential_id,
    email: session.email,
    otp_hash: session.otp_hash,
    flow: session.flow,
    created_at: session.created_at,
    expires_at: session.expires_at,
    used: session.used === 1,
  };
}
