import rateLimit from 'express-rate-limit';

export const unauthenticatedLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'rate_limited', retry_after: 60 },
});

export const authenticatedLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 1000,
  keyGenerator: (req) => {
    const cred = (req as any).credential;
    return cred?.agent_id ?? req.ip ?? 'unknown';
  },
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'rate_limited', retry_after: 3600 },
});
