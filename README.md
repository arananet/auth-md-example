# auth-md-example

![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?logo=typescript&logoColor=white) ![Node.js](https://img.shields.io/badge/Node.js-339933?logo=nodedotjs&logoColor=white) ![Express](https://img.shields.io/badge/Express-000000?logo=express&logoColor=white) ![SQLite](https://img.shields.io/badge/SQLite-003B57?logo=sqlite&logoColor=white) ![OpenSpec](https://img.shields.io/badge/OpenSpec-enforced-blueviolet) ![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

> Reference implementation of auth.md agentic registration (RFC 9728 + agent_auth)

---

## Quick start

```bash
git clone https://github.com/arananet/auth-md-example.git
cd auth-md-example
npm install
npm test          # run the test suite
npm run dev       # start the dev server on :3000
```

---

## What this is

This repo is a reference implementation of [auth.md](https://auth.md) — the
agentic registration protocol that lets AI agents self-register with a service
using one of three methods:

| Method | Flow |
|---|---|
| `identity_assertion` + `id-jag` | Agent presents a JWT signed by a trusted IdP; credential issued immediately |
| `identity_assertion` + `verified_email` | Agent asserts an email; user completes a 6-digit OTP claim ceremony |
| `anonymous` | Credential issued immediately at pre-claim scopes; optionally claimed later |

All three methods produce an `api_key` credential returned **once**, stored as
a SHA-256 hash, and validated on every subsequent request as a `Bearer` token.

---

## Usage

### 1 — Discover

```bash
curl https://api.auth-md-example.com/.well-known/oauth-protected-resource
curl https://auth.auth-md-example.com/.well-known/oauth-authorization-server
```

Or read [`public/auth.md`](public/auth.md) — the agent-facing recipe that
describes every step.

### 2 — Register (anonymous example)

```bash
curl -X POST http://localhost:3000/agent/auth \
  -H 'Content-Type: application/json' \
  -d '{"type":"anonymous","requested_credential_type":"api_key"}'
# → {"credential":"<api_key>","scopes":["auth-md-example:read"],"claim_token":"..."}
```

### 3 — Use the credential

```bash
curl http://localhost:3000/api/resource \
  -H 'Authorization: Bearer <api_key>'
# → {"data":"protected resource"}
```

### 4 — Revoke

```bash
curl -X POST http://localhost:3000/agent/auth/revoke \
  -H 'Content-Type: application/json' \
  -d '{"token":"<api_key>"}'
```

---

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `PORT` | `3000` | Server port |
| `RESOURCE_HOST` | `https://api.auth-md-example.com` | Resource server base URL |
| `AUTH_HOST` | `https://auth.auth-md-example.com` | Auth server base URL |
| `TRUSTED_ISSUERS` | `[]` | JSON array of `{iss, jwks_uri}` for id-jag |
| `DB_PATH` | `:memory:` | SQLite path (use a file path for persistence) |
| `CREDENTIAL_TTL_MS` | `2592000000` (30 days) | Credential lifetime |
| `OTP_TTL_MS` | `600000` (10 min) | OTP lifetime |

---

## Project layout

```
src/
  app.ts                  Express app
  server.ts               Entry point
  config.ts               Config with env overrides
  db.ts                   SQLite init and migrations
  crypto.ts               SHA-256, token generation, CSPRNG OTP
  middleware/
    authenticate.ts       Bearer token validation → 401 with WWW-Authenticate
    rateLimit.ts          Per-IP (unauthenticated) + per-tenant (authenticated)
  routes/
    agent.ts              POST /agent/auth, /claim, /claim/complete
    revoke.ts             POST /agent/auth/revoke
    wellKnown.ts          GET /.well-known/* and /auth.md
  services/
    credentials.ts        CRUD for hashed credentials
    idJag.ts              ID-JAG JWT verification via JWKS
    otp.ts                Claim session + OTP lifecycle
    replay.ts             JTI replay detection (persistent)
    email.ts              Email stub (replace in production)
  __tests__/
    agentAuth.test.ts     Happy paths + all negative cases
    replay.test.ts        JTI replay unit tests
public/
  auth.md                 Agent-facing recipe
  .well-known/
    oauth-protected-resource
    oauth-authorization-server
```

---

## Security notes

- Credentials are stored as SHA-256 hashes; the raw value is returned once.
- ID-JAG JWTs are verified against a configurable issuer trust list (JWKS).
- JTI values are stored (hashed) to prevent replay within the credential lifetime window.
- OTPs are 6 digits from `crypto.randomInt` (CSPRNG), single-use, ~10 min TTL.
- Rate limits: 20 req/min per IP on unauthenticated endpoints; 1000 req/hr per agent on authenticated ones.
- Tokens, OTPs, and raw assertions are never logged.

---

## Contributing

This project uses **OpenSpec** for spec-driven development. See
[`docs/OPENSPEC.md`](docs/OPENSPEC.md) for the full workflow.

---

## Documentation

| Topic | Where |
|---|---|
| Agent-facing recipe | [`public/auth.md`](public/auth.md) |
| Spec-driven workflow | [`docs/OPENSPEC.md`](docs/OPENSPEC.md) |
| Security policy | [`SECURITY.md`](SECURITY.md) |
| Release history | [`CHANGELOG.md`](CHANGELOG.md) |

---

## License

[MIT](LICENSE)
