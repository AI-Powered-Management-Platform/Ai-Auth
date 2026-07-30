# Ai-Auth

AI-assisted identity provider. Passkey-first authentication, OIDC provider,
multi-tenant session control, and risk scoring on every login.

| Item | Value |
| --- | --- |
| Identity core | Go |
| Control plane | Python / FastAPI |
| Console | Next.js |
| Store | Postgres + Redis |
| Status | Design stage |

⚠️ Security-first rule: never weaken auth for convenience. The passkey
fast-path is the UX answer, not a lowered bar.

| Document | Contents |
| --- | --- |
| [SECURITY.md](SECURITY.md) | Hardening backlog, prioritised |
| [docs/threat-model.md](docs/threat-model.md) | T1–T8 attacks and controls |

⚠️ Read T1 first. Passkeys do not stop session theft after login.

---

## Architecture

| Service | Language | Job |
| --- | --- | --- |
| `core` | Go | Tokens, sessions, WebAuthn |
| `oidc` | Go | OAuth 2.1 / OIDC endpoints |
| `api` | Python | Tenants, policy, admin |
| `worker` | Python | Webhooks, risk jobs, audit |
| `console` | TypeScript | Admin and self-service UI |

---

## Features A–Z

### A — Account linking

Bind multiple identities to one account. Enforce required-provider sets.

### B — Brute-force protection

Per-IP, per-account, and per-tenant throttles. Credential-stuffing detection.

### C — Consent and scopes

Explicit scope grants, consent screen, revocable per client.

### D — Device-bound sessions

DBSC cookie binding to TPM, trusted-device list, per-device revoke.

### E — Email OTP and magic links

Single-use, short-TTL, bound to originating browser.

### F — Federation

Upstream OIDC and SAML. Facebook, Google, Apple, Microsoft connectors.

### G — Granular authorization

Roles, permissions, and attribute-based policy evaluation.

### H — Hashing

Argon2id with tuned parameters. Transparent rehash on login.

### I — Identity lifecycle

Invite, activate, suspend, deactivate, delete with retention rules.

### J — JWT and PASETO issuance

Short-lived access tokens, asymmetric signing, published JWKS. DPoP
sender-constrained by default, so a stolen token is unusable.

### K — Key management

KMS envelope encryption for secrets. Scheduled signing-key rotation.

### L — Login risk scoring

Impossible travel, new device, velocity, and reputation signals.

### M — Multi-factor authentication

TOTP, WebAuthn second factor, single-use recovery codes. Fallback strength must
equal primary strength — see T2 in the threat model.

### N — Notification of attempts

Alert the account owner on failed and unusual login attempts.

### O — OAuth 2.1 / OIDC provider

Authorization code with mandatory PKCE. Client credentials. Discovery document.

### P — Passkeys

Platform and roaming WebAuthn credentials. Full attestation verification.

### Q — Quotas and rate limits

Per-tenant request budgets on every auth endpoint.

### R — Refresh token rotation

One-time-use refresh tokens with reuse detection and family revoke.

### S — Session management

List active sessions, revoke one or all, absolute and idle timeouts. Continuous
evaluation via CAEP, so revocation is pushed, not awaited.

### T — Tenant isolation

Row-level security per organization. No shared session namespace.

### U — User self-service

Profile, credential management, account recovery without support tickets.

### V — Verification

Email and phone verification. Hooks for KYC providers.

### W — Webhook events

`login`, `logout`, `lockout`, `mfa_enrolled`, `grant`, `revoke`. HMAC-signed.

### X — XSS, CSRF, and clickjacking defense

Nonce-based CSP, `X-Frame-Options: DENY`, double-submit CSRF, `SameSite` cookies.

### Y — Yubikey and hardware tokens

FIDO2 security keys as primary or step-up factor.

### Z — Zero-trust policy engine

Every request re-evaluated. No implicit trust from network position.

---

## AI features

| Feature | What it does |
| --- | --- |
| Risk scoring | Rates each login attempt |
| Anomaly detection | Learns per-user login patterns |
| Bot classification | Separates humans from scripts |
| Policy suggestion | Proposes rules from real traffic |
| Audit summarizer | Explains incidents in plain words |

---

## Authentication policy

| Actor | Requirement |
| --- | --- |
| Operator setup | Facebook + Google + passkey |
| Operator daily | Passkey, or both socials |
| Shopper | Facebook, passkey optional |
| Staff | Console-managed, no self-signup |

---

## Non-goals

| Not building | Reason |
| --- | --- |
| Password-only login | Rejected by design |
| SMS as primary factor | SIM-swap risk |
| Directory sync (SCIM) v1 | Later, if demanded |
