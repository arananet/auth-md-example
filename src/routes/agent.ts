import { Router, Request, Response } from 'express';
import { verifyIdJag } from '../services/idJag';
import { issueCredential } from '../services/credentials';
import { createClaimSession, attachOtpToSession, verifyOtp, getClaimSession } from '../services/otp';
import { sendOtp } from '../services/email';
import { sha256 } from '../crypto';
import { config } from '../config';
import { unauthenticatedLimiter } from '../middleware/rateLimit';

const router = Router();

router.post('/agent/auth', unauthenticatedLimiter, async (req: Request, res: Response): Promise<void> => {
  const { type, assertion_type, assertion, requested_credential_type } = req.body;

  if (!type) {
    res.status(400).json({ error: 'invalid_request', description: 'Missing type' });
    return;
  }

  if (requested_credential_type && requested_credential_type !== 'api_key') {
    res.status(400).json({ error: 'unsupported_credential_type' });
    return;
  }

  if (type === 'anonymous') {
    const { raw, credential } = issueCredential({
      type: 'anonymous',
      scopes: config.preClaimScopes,
      claimed: false,
    });

    const { claimToken } = createClaimSession({
      flow: 'anonymous',
      credentialId: credential.id,
    });

    res.json({
      credential: raw,
      scopes: credential.scopes,
      claim_token: claimToken,
    });
    return;
  }

  if (type === 'identity_assertion') {
    if (!assertion_type || !assertion) {
      res.status(400).json({ error: 'invalid_request', description: 'Missing assertion_type or assertion' });
      return;
    }

    if (assertion_type === 'urn:ietf:params:oauth:token-type:id-jag') {
      const result = await verifyIdJag(assertion);
      if (!result.ok) {
        res.status(401).json({ error: result.error });
        return;
      }

      const { raw, credential } = issueCredential({
        type: 'identity_assertion',
        email: result.email,
        scopes: config.scopes,
        claimed: true,
      });

      res.json({ credential: raw, scopes: credential.scopes });
      return;
    }

    if (assertion_type === 'verified_email') {
      const email = assertion as string;
      if (!email || !email.includes('@')) {
        res.status(400).json({ error: 'invalid_request', description: 'Invalid email' });
        return;
      }

      const { claimToken, otp } = createClaimSession({
        flow: 'verified_email',
        email,
      });

      await sendOtp(email, otp);

      res.status(202).json({
        claim_token: claimToken,
        message: 'OTP sent to email. Use /agent/auth/claim/complete to complete registration.',
      });
      return;
    }

    res.status(400).json({ error: 'unsupported_assertion_type' });
    return;
  }

  res.status(400).json({ error: 'unsupported_type' });
});

router.post('/agent/auth/claim', unauthenticatedLimiter, async (req: Request, res: Response): Promise<void> => {
  const { claim_token, email } = req.body;

  if (!claim_token || !email) {
    res.status(400).json({ error: 'invalid_request', description: 'Missing claim_token or email' });
    return;
  }

  const session = getClaimSession(claim_token);
  if (!session) {
    res.status(401).json({ error: 'invalid_claim_token' });
    return;
  }

  if (session.flow !== 'anonymous') {
    res.status(400).json({ error: 'invalid_request', description: 'Claim endpoint is for anonymous flow only' });
    return;
  }

  const otp = attachOtpToSession(sha256(claim_token), email);
  if (!otp) {
    res.status(401).json({ error: 'invalid_claim_token' });
    return;
  }

  await sendOtp(email, otp);

  res.json({ message: 'OTP sent to email. Use /agent/auth/claim/complete to complete.' });
});

router.post('/agent/auth/claim/complete', unauthenticatedLimiter, async (req: Request, res: Response): Promise<void> => {
  const { claim_token, otp } = req.body;

  if (!claim_token || !otp) {
    res.status(400).json({ error: 'invalid_request', description: 'Missing claim_token or otp' });
    return;
  }

  const session = verifyOtp(claim_token, otp);
  if (!session) {
    // Could be expired or wrong OTP — check if session exists at all to differentiate
    const rawSession = getClaimSession(claim_token);
    if (!rawSession) {
      res.status(401).json({ error: 'otp_expired' });
    } else {
      res.status(401).json({ error: 'otp_invalid' });
    }
    return;
  }

  if (session.flow === 'anonymous' && session.credential_id) {
    const { claimCredential, findCredentialById } = await import('../services/credentials');
    claimCredential(session.credential_id, session.email!);
    const updated = findCredentialById(session.credential_id);
    res.json({
      message: 'Credential claimed and upgraded.',
      scopes: updated?.scopes ?? config.scopes,
    });
    return;
  }

  if (session.flow === 'verified_email') {
    const { issueCredential } = await import('../services/credentials');
    const { raw, credential } = issueCredential({
      type: 'identity_assertion',
      email: session.email!,
      scopes: config.scopes,
      claimed: true,
    });
    res.json({ credential: raw, scopes: credential.scopes });
    return;
  }

  res.status(500).json({ error: 'internal_error' });
});

export default router;
