import Database from 'better-sqlite3';
import { config } from './config';

let _db: Database.Database | null = null;

export function getDb(): Database.Database {
  if (!_db) {
    _db = new Database(config.dbPath);
    migrate(_db);
  }
  return _db;
}

export function resetDb(): void {
  if (_db) {
    _db.close();
    _db = null;
  }
}

function migrate(db: Database.Database): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS credentials (
      id TEXT PRIMARY KEY,
      agent_id TEXT NOT NULL,
      type TEXT NOT NULL,
      email TEXT,
      scopes TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      revoked INTEGER NOT NULL DEFAULT 0,
      claimed INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS jti_replay (
      jti_hash TEXT PRIMARY KEY,
      exp INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS claim_sessions (
      claim_token_hash TEXT PRIMARY KEY,
      credential_id TEXT,
      email TEXT,
      otp_hash TEXT,
      flow TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      used INTEGER NOT NULL DEFAULT 0
    );

    CREATE INDEX IF NOT EXISTS idx_credentials_agent ON credentials(agent_id);
    CREATE INDEX IF NOT EXISTS idx_claim_sessions_expires ON claim_sessions(expires_at);
  `);
}
