import { getDb } from '../db';
import { sha256 } from '../crypto';

export function checkAndStoreJti(jti: string, exp: number): boolean {
  const db = getDb();
  const hash = sha256(jti);
  const now = Date.now();

  // Purge expired entries
  db.prepare('DELETE FROM jti_replay WHERE exp < ?').run(now);

  const existing = db.prepare('SELECT jti_hash FROM jti_replay WHERE jti_hash = ?').get(hash);
  if (existing) return false;

  db.prepare('INSERT INTO jti_replay (jti_hash, exp) VALUES (?, ?)').run(hash, exp);
  return true;
}
