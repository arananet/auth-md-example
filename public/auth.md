# auth.md

You are an agent acting on behalf of a user. This service supports agentic
registration. Work the steps in order: discover, pick a method, register,
claim if needed, call the API, handle revocation. Do not skip ahead.

Hosts:
- Resource server: `https://api.auth-md-example.com`  — the API you will call.
- Authorization server: `https://auth.auth-md-example.com`  — handles registration.

## Step 1 — Discover

Discovery is two hops, following RFC 9728.

A 401 from the resource server carries the pointer:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://api.auth-md-example.com/.well-known/oauth-protected-resource"
```

Fetch the Protected Resource Metadata, then the Authorization Server metadata.
The AS metadata carries an `agent_auth` block describing what this service
accepts. Read it in full and only use methods it lists.

```
GET https://api.auth-md-example.com/.well-known/oauth-protected-resource
GET https://auth.auth-md-example.com/.well-known/oauth-authorization-server
```

## Step 2 — Pick a method

1. You hold a user session you can exchange for an ID-JAG bound to this
   service  →  `identity_assertion` + `id-jag`.
2. You have only the user's email  →  `identity_assertion` + `verified_email`
   (claim ceremony required).
3. You have neither  →  `anonymous` (claim optional, deferred until a human
   takes ownership).

Cross-check your choice against the `agent_auth` block. If the matching
`*_supported` array does not list your method, this service will not accept it.

## Step 3 — Register

All variants POST to the `register_uri`. For any `identity_assertion`, surface
`resource_name`, `resource_logo_uri`, and the scope set to the user and confirm
before asserting their identity. This is the user's only consent gate. Anonymous
has no identity to assert, so skip consent.

### identity_assertion + id-jag

Confirm your provider's issuer is on this service's trust list, then mint:

- `aud` = `https://api.auth-md-example.com/` (from the Protected Resource Metadata)
- `iss` = your provider's issuer URL (must be on the trust list)
- `typ` = `oauth-id-jag+jwt`, `alg` = `RS256`
- `email_verified: true`
- fresh `jti`, `iat` = now, near-term `exp` (≤5 minutes)

```http
POST /agent/auth
Content-Type: application/json

{
  "type": "identity_assertion",
  "assertion_type": "urn:ietf:params:oauth:token-type:id-jag",
  "assertion": "<ID-JAG JWT>",
  "requested_credential_type": "api_key"
}
```

On success (200) you receive:

```json
{ "credential": "<api_key>", "scopes": ["auth-md-example:read", "auth-md-example:write"] }
```

Go to Step 5.

### identity_assertion + verified_email

```http
POST /agent/auth
Content-Type: application/json

{
  "type": "identity_assertion",
  "assertion_type": "verified_email",
  "assertion": "user@example.com",
  "requested_credential_type": "api_key"
}
```

Returns 202. No credential yet. The service emails the user a 6-digit OTP. Keep
the returned `claim_token` in memory and go to Step 4. It is returned exactly
once; do not persist it.

### anonymous

```http
POST /agent/auth
Content-Type: application/json

{ "type": "anonymous", "requested_credential_type": "api_key" }
```

Returns 200. You get a usable credential immediately at pre-claim scopes, plus a
`claim_token`. To let a human take ownership, go to Step 4. Otherwise go to
Step 5. An unclaimed credential is unowned; claim before doing anything that
matters.

## Step 4 — Claim ceremony

Goal: a human reads a 6-digit code back to you.

```http
# Anonymous only — trigger the OTP
POST /agent/auth/claim
{ "claim_token": "...", "email": "user@example.com" }

# Both flows — complete with the OTP
POST /agent/auth/claim/complete
{ "claim_token": "...", "otp": "123456" }
```

On success the credential is bound to the user. For anonymous, the existing key
is upgraded in place. For verified_email, the same key is activated with full
scopes.

## Step 5 — Use the credential

```http
GET /api/<resource>
Authorization: Bearer <credential>
```

There is no refresh. When a credential expires, re-register. On a 401 for a
previously working credential, drop it and restart at Step 1.

## Errors

| Code | Where | Action |
|---|---|---|
| `invalid_signature` | register (id-jag) | mint a fresh ID-JAG |
| `replay_detected` | register (id-jag) | new `jti`, mint again |
| `audience_mismatch` | register (id-jag) | set `aud` to the PRM `resource` |
| `credential_expired` | register (id-jag) | mint with a near-term `exp` |
| `issuer_not_enabled` | register (id-jag) | issuer not trusted; pick another method |
| `anonymous_not_enabled` | register | service rejects anonymous; pick another |
| `otp_invalid` | claim/complete | re-read or re-trigger the code |
| `otp_expired` | claim/complete | re-trigger the OTP |
| `rate_limited` (429) | any | back off, honor `Retry-After` |

## Revocation

You do not initiate revocation. A provider may push a `logout+jwt` to the
service's `revocation_uri`, or a user may revoke from the dashboard. You learn
of it as a 401 on a working credential. Drop it and restart at Step 1.
