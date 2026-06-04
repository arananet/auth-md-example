import { Request, Response, NextFunction } from 'express';
import { findCredentialByRaw } from '../services/credentials';

export interface AuthenticatedRequest extends Request {
  credential?: ReturnType<typeof findCredentialByRaw> extends null ? never : NonNullable<ReturnType<typeof findCredentialByRaw>>;
}

export function authenticate(req: Request, res: Response, next: NextFunction): void {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.set(
      'WWW-Authenticate',
      `Bearer resource_metadata="${process.env.RESOURCE_HOST || 'https://api.auth-md-example.com'}/.well-known/oauth-protected-resource"`
    );
    res.status(401).json({ error: 'unauthorized' });
    return;
  }

  const raw = authHeader.slice(7);
  const credential = findCredentialByRaw(raw);

  if (!credential) {
    res.status(401).json({ error: 'invalid_token' });
    return;
  }

  if (credential.revoked) {
    res.status(401).json({ error: 'token_revoked' });
    return;
  }

  if (Date.now() > credential.expires_at) {
    res.status(401).json({ error: 'token_expired' });
    return;
  }

  (req as any).credential = credential;
  next();
}
