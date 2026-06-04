import { getDb } from '../db';
import { sha256, generateToken } from '../crypto';
import { config } from '../config';

export interface Credential {
  id: string;
  agent_id: string;
  type: string;
  email: string | null;
  scopes: string[];
  created_at: number;
  expires_at: number;
  revoked: boolean;
  claimed: boolean;
}

export function issueCredential(opts: {
  type: string;
  email?: string;
  scopes?: string[];
  claimed?: boolean;
}): { raw: string; credential: Credential } {
  const db = getDb();
  const raw = generateToken();
  const id = sha256(raw);
  const now = Date.now();
  const scopes = opts.scopes ?? config.scopes;
  const agentId = generateToken(16);

  db.prepare(`
    INSERT INTO credentials (id, agent_id, type, email, scopes, created_at, expires_at, revoked, claimed)
    VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)
  `).run(
    id,
    agentId,
    opts.type,
    opts.email ?? null,
    JSON.stringify(scopes),
    now,
    now + config.credentialTtlMs,
    opts.claimed ? 1 : 0
  );

  const row = db.prepare('SELECT * FROM credentials WHERE id = ?').get(id) as any;
  return { raw, credential: rowToCredential(row) };
}

export function findCredentialByRaw(raw: string): Credential | null {
  const db = getDb();
  const id = sha256(raw);
  const row = db.prepare('SELECT * FROM credentials WHERE id = ?').get(id) as any;
  if (!row) return null;
  return rowToCredential(row);
}

export function revokeCredential(id: string): boolean {
  const db = getDb();
  const result = db.prepare('UPDATE credentials SET revoked = 1 WHERE id = ?').run(id);
  return result.changes > 0;
}

export function claimCredential(id: string, email: string): boolean {
  const db = getDb();
  const result = db.prepare(
    'UPDATE credentials SET claimed = 1, email = ?, scopes = ? WHERE id = ?'
  ).run(email, JSON.stringify(config.scopes), id);
  return result.changes > 0;
}

export function findCredentialById(id: string): Credential | null {
  const db = getDb();
  const row = db.prepare('SELECT * FROM credentials WHERE id = ?').get(id) as any;
  if (!row) return null;
  return rowToCredential(row);
}

function rowToCredential(row: any): Credential {
  return {
    id: row.id,
    agent_id: row.agent_id,
    type: row.type,
    email: row.email,
    scopes: JSON.parse(row.scopes),
    created_at: row.created_at,
    expires_at: row.expires_at,
    revoked: row.revoked === 1,
    claimed: row.claimed === 1,
  };
}
