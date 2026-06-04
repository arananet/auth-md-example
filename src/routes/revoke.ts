import { Router, Request, Response } from 'express';
import { revokeCredential, findCredentialByRaw } from '../services/credentials';
import { unauthenticatedLimiter } from '../middleware/rateLimit';

const router = Router();

// Provider-pushed logout+jwt revocation
router.post('/agent/auth/revoke', unauthenticatedLimiter, (req: Request, res: Response): void => {
  const { token, token_type_hint, credential } = req.body;

  const raw = token || credential;
  if (!raw) {
    res.status(400).json({ error: 'invalid_request', description: 'Missing token or credential' });
    return;
  }

  const cred = findCredentialByRaw(raw);
  if (!cred) {
    // RFC 7009 says to return 200 even for unknown tokens
    res.json({ revoked: true });
    return;
  }

  revokeCredential(cred.id);
  res.json({ revoked: true });
});

export default router;
