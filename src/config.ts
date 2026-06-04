export interface IssuerConfig {
  iss: string;
  jwks_uri: string;
}

export const config = {
  resourceHost: process.env.RESOURCE_HOST || 'https://api.auth-md-example.com',
  authHost: process.env.AUTH_HOST || 'https://auth.auth-md-example.com',
  port: parseInt(process.env.PORT || '3000', 10),
  trustedIssuers: JSON.parse(process.env.TRUSTED_ISSUERS || '[]') as IssuerConfig[],
  credentialTtlMs: parseInt(process.env.CREDENTIAL_TTL_MS || String(30 * 24 * 60 * 60 * 1000), 10),
  otpTtlMs: parseInt(process.env.OTP_TTL_MS || String(10 * 60 * 1000), 10),
  claimTokenTtlMs: parseInt(process.env.CLAIM_TOKEN_TTL_MS || String(24 * 60 * 60 * 1000), 10),
  dbPath: process.env.DB_PATH || ':memory:',
  scopes: ['auth-md-example:read', 'auth-md-example:write'],
  preClaimScopes: ['auth-md-example:read'],
};
