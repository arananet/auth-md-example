import request from 'supertest';
import app from '../app';
import { resetDb } from '../db';
import { config } from '../config';

// Mock crypto to use a predictable OTP
jest.mock('../crypto', () => ({
  ...jest.requireActual('../crypto'),
  generateOtp: jest.fn().mockReturnValue('123456'),
}));

// Mock verifyIdJag so tests don't need outbound network calls
jest.mock('../services/idJag', () => {
  const actual = jest.requireActual('../services/idJag');
  return {
    ...actual,
    verifyIdJag: jest.fn(),
  };
});

import { verifyIdJag } from '../services/idJag';
const mockVerifyIdJag = verifyIdJag as jest.MockedFunction<typeof verifyIdJag>;

// Reset DB before each test for isolation
beforeEach(() => {
  resetDb();
  jest.clearAllMocks();
});

afterAll(() => {
  resetDb();
});

// ─── Anonymous happy path ───────────────────────────────────────────────────
describe('POST /agent/auth - anonymous', () => {
  it('issues credential and claim_token immediately', async () => {
    const res = await request(app)
      .post('/agent/auth')
      .send({ type: 'anonymous', requested_credential_type: 'api_key' });

    expect(res.status).toBe(200);
    expect(res.body.credential).toBeDefined();
    expect(res.body.claim_token).toBeDefined();
    expect(res.body.scopes).toEqual(config.preClaimScopes);
  });
});

// ─── ID-JAG happy path ──────────────────────────────────────────────────────
describe('POST /agent/auth - id-jag', () => {
  it('returns api_key on valid ID-JAG', async () => {
    mockVerifyIdJag.mockResolvedValueOnce({ ok: true, email: 'agent@example.com', jti: 'jti-1' });

    const res = await request(app)
      .post('/agent/auth')
      .send({
        type: 'identity_assertion',
        assertion_type: 'urn:ietf:params:oauth:token-type:id-jag',
        assertion: 'fake.jwt.token',
        requested_credential_type: 'api_key',
      });

    expect(res.status).toBe(200);
    expect(res.body.credential).toBeDefined();
    expect(res.body.scopes).toEqual(config.scopes);
  });

  it('returns 401 invalid_signature on bad JWT', async () => {
    mockVerifyIdJag.mockResolvedValueOnce({ ok: false, error: 'invalid_signature' });

    const res = await request(app)
      .post('/agent/auth')
      .send({
        type: 'identity_assertion',
        assertion_type: 'urn:ietf:params:oauth:token-type:id-jag',
        assertion: 'bad.jwt.token',
        requested_credential_type: 'api_key',
      });

    expect(res.status).toBe(401);
    expect(res.body.error).toBe('invalid_signature');
  });

  it('returns 401 replay_detected on replayed jti', async () => {
    mockVerifyIdJag.mockResolvedValueOnce({ ok: false, error: 'replay_detected' });

    const res = await request(app)
      .post('/agent/auth')
      .send({
        type: 'identity_assertion',
        assertion_type: 'urn:ietf:params:oauth:token-type:id-jag',
        assertion: 'replayed.jwt.token',
      });

    expect(res.status).toBe(401);
    expect(res.body.error).toBe('replay_detected');
  });

  it('returns 401 audience_mismatch on wrong aud', async () => {
    mockVerifyIdJag.mockResolvedValueOnce({ ok: false, error: 'audience_mismatch' });

    const res = await request(app)
      .post('/agent/auth')
      .send({
        type: 'identity_assertion',
        assertion_type: 'urn:ietf:params:oauth:token-type:id-jag',
        assertion: 'wrong-aud.jwt.token',
      });

    expect(res.status).toBe(401);
    expect(res.body.error).toBe('audience_mismatch');
  });

  it('returns 401 credential_expired on expired JWT', async () => {
    mockVerifyIdJag.mockResolvedValueOnce({ ok: false, error: 'credential_expired' });

    const res = await request(app)
      .post('/agent/auth')
      .send({
        type: 'identity_assertion',
        assertion_type: 'urn:ietf:params:oauth:token-type:id-jag',
        assertion: 'expired.jwt.token',
      });

    expect(res.status).toBe(401);
    expect(res.body.error).toBe('credential_expired');
  });
});

// ─── verified_email happy path ──────────────────────────────────────────────
describe('POST /agent/auth - verified_email', () => {
  it('returns 202 and claim_token, no credential yet', async () => {
    const res = await request(app)
      .post('/agent/auth')
      .send({
        type: 'identity_assertion',
        assertion_type: 'verified_email',
        assertion: 'user@example.com',
        requested_credential_type: 'api_key',
      });

    expect(res.status).toBe(202);
    expect(res.body.claim_token).toBeDefined();
    expect(res.body.credential).toBeUndefined();
  });
});

// ─── Claim ceremony ─────────────────────────────────────────────────────────
describe('POST /agent/auth/claim/complete', () => {
  it('completes verified_email flow with correct OTP', async () => {
    // Register and capture the claim_token
    const regRes = await request(app)
      .post('/agent/auth')
      .send({
        type: 'identity_assertion',
        assertion_type: 'verified_email',
        assertion: 'user@example.com',
      });
    expect(regRes.status).toBe(202);
    const claimToken = regRes.body.claim_token;

    // generateOtp is mocked to return '123456'
    const res = await request(app)
      .post('/agent/auth/claim/complete')
      .send({ claim_token: claimToken, otp: '123456' });

    expect(res.status).toBe(200);
    expect(res.body.credential).toBeDefined();
    expect(res.body.scopes).toEqual(config.scopes);
  });

  it('returns 401 otp_invalid on wrong OTP', async () => {
    const regRes = await request(app)
      .post('/agent/auth')
      .send({
        type: 'identity_assertion',
        assertion_type: 'verified_email',
        assertion: 'user@example.com',
      });
    const claimToken = regRes.body.claim_token;

    const res = await request(app)
      .post('/agent/auth/claim/complete')
      .send({ claim_token: claimToken, otp: '999999' });

    expect(res.status).toBe(401);
    expect(res.body.error).toBe('otp_invalid');
  });
});

// ─── Bearer validation & 401-then-rediscover cycle ──────────────────────────
describe('Bearer middleware & 401 rediscover', () => {
  it('returns 401 with WWW-Authenticate resource_metadata on unauthenticated GET', async () => {
    const res = await request(app).get('/api/resource');
    expect(res.status).toBe(401);
    expect(res.headers['www-authenticate']).toMatch(/resource_metadata=/);
  });

  it('returns 200 on authenticated GET with valid credential', async () => {
    mockVerifyIdJag.mockResolvedValueOnce({ ok: true, email: 'agent@example.com', jti: 'jti-2' });
    const regRes = await request(app)
      .post('/agent/auth')
      .send({
        type: 'identity_assertion',
        assertion_type: 'urn:ietf:params:oauth:token-type:id-jag',
        assertion: 'valid.jwt.token',
      });
    const credential = regRes.body.credential;

    const res = await request(app)
      .get('/api/resource')
      .set('Authorization', `Bearer ${credential}`);
    expect(res.status).toBe(200);
  });

  it('returns 401 after revocation', async () => {
    mockVerifyIdJag.mockResolvedValueOnce({ ok: true, email: 'agent@example.com', jti: 'jti-3' });
    const regRes = await request(app)
      .post('/agent/auth')
      .send({
        type: 'identity_assertion',
        assertion_type: 'urn:ietf:params:oauth:token-type:id-jag',
        assertion: 'valid.jwt.token2',
      });
    const credential = regRes.body.credential;

    // Revoke
    await request(app).post('/agent/auth/revoke').send({ token: credential });

    // Use revoked credential
    const res = await request(app)
      .get('/api/resource')
      .set('Authorization', `Bearer ${credential}`);
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('token_revoked');
  });
});

// ─── Anonymous claim flow ────────────────────────────────────────────────────
describe('Anonymous claim flow', () => {
  it('POST /agent/auth/claim triggers OTP for anonymous credential', async () => {
    const regRes = await request(app)
      .post('/agent/auth')
      .send({ type: 'anonymous' });
    const claimToken = regRes.body.claim_token;

    const claimRes = await request(app)
      .post('/agent/auth/claim')
      .send({ claim_token: claimToken, email: 'owner@example.com' });
    expect(claimRes.status).toBe(200);
    expect(claimRes.body.message).toBeDefined();
  });

  it('completes anonymous claim with correct OTP', async () => {
    const regRes = await request(app)
      .post('/agent/auth')
      .send({ type: 'anonymous' });
    const claimToken = regRes.body.claim_token;
    const rawCredential = regRes.body.credential;

    // Trigger OTP
    await request(app)
      .post('/agent/auth/claim')
      .send({ claim_token: claimToken, email: 'owner@example.com' });

    // Complete with mocked OTP
    const completeRes = await request(app)
      .post('/agent/auth/claim/complete')
      .send({ claim_token: claimToken, otp: '123456' });

    expect(completeRes.status).toBe(200);
    expect(completeRes.body.message).toMatch(/claimed/i);
    expect(completeRes.body.scopes).toEqual(config.scopes);

    // Verify credential now has full scopes
    const apiRes = await request(app)
      .get('/api/resource')
      .set('Authorization', `Bearer ${rawCredential}`);
    expect(apiRes.status).toBe(200);
  });

  it('returns 401 on invalid claim_token', async () => {
    const res = await request(app)
      .post('/agent/auth/claim')
      .send({ claim_token: 'invalid', email: 'x@example.com' });
    expect(res.status).toBe(401);
  });
});
