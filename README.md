# Ai-Auth

AI-assisted identity provider. Passkey-first authentication, OIDC provider,
multi-tenant session control, and risk scoring on every login.

> **Status: design stage.** No code has been written yet. This repository is the
> architecture, the threat model, and the compliance map.

> **The risk model cannot authorise.** It emits an advisory score and nothing
> else. Authorisation is decided by the Go gateway from a cryptographic verdict
> and tenant policy. A CI schema guard fails the build if an `allow`, `deny`, or
> `decision` field is ever added to `RiskAssessment` — the rule is enforced by
> the build, not by memory.

Ai-Auth is an independent service package: API-based, containerized, and with
every internal hop authenticated by certificates. Infrastructure security
builds on a single tunneled ingress, privileged-access management, and
confidential computing. The goal is a high-performance, tri-language identity
provider shipped as a production-grade, globally compliant package — the same
security level for every user on the planet, with regional law handled by
configuration, not by forks.

| Item | Value |
| --- | --- |
| Edge gateway | Go |
| Crypto core | Rust |
| Risk worker | Python |
| Control plane | Python / FastAPI |
| Console | Next.js |
| Store | Postgres + Redis |
| Status | Design stage |

⚠️ Security-first rule: never weaken auth for convenience. The passkey
fast-path is the UX answer, not a lowered bar.

| Document | Contents |
| --- | --- |
| [SECURITY.md](SECURITY.md) | How to report a vulnerability |
| [docs/threat-model.md](docs/threat-model.md) | T1–T8 attacks and controls |
| [docs/hardening-backlog.md](docs/hardening-backlog.md) | Prioritised build backlog |
| [docs/compliance.md](docs/compliance.md) | FAPI 2.0, NIST, PSD2, DORA, SOC 2 — mapped, with gaps |
| [docs/key-custody.md](docs/key-custody.md) | HSM, FIPS 140-3, key ceremony |
| [docs/trust-package.md](docs/trust-package.md) | Evidence a regulated buyer asks for |
| [docs/mobile-integration.md](docs/mobile-integration.md) | iOS, Android, Flutter, React Native — client-side security |
| [docs/development-lifecycle.md](docs/development-lifecycle.md) | How code gets built — agents propose, humans decide, CI enforces |

⚠️ Read T1 first. Passkeys do not stop session theft after login.

---

## Architecture

Six services in two planes, three languages, one public door. One container
per service — the boundary follows the language, the skill, and the blast
radius.

```text
                      [ Mobile / Web Client ]
                               │
                               ▼  Ingress adapter — the only public entry
 ┌─────────────────────────────────────────────────────────────┐
 │                GO EDGE API GATEWAY (Master)                 │
 │   Multi-tenant boundary · OIDC routing · owns all state     │
 └─────────────┬───────────────────────────────┬───────────────┘
               │  gRPC over mTLS               │  gRPC over mTLS
               ▼  net-a                        ▼  net-b
 ┌──────────────────────────────┐┌──────────────────────────────┐
 │ RUST CRYPTO SERVICE (Guard)  ││ PYTHON AI WORKER (Thinker)   │
 │  Passkey validation          ││  Real-time risk scoring      │
 │  Envelope row encryption     ││  Anomaly matrix tracking     │
 └──────────────────────────────┘└──────────────────────────────┘
          these two have no route to each other
```

### Data plane — on the login path

| Service | Language | Job |
| --- | --- | --- |
| `gateway` | Go | Public transport, tenant boundary, OIDC, tokens, sessions |
| `crypto` | Rust | Passkey verification, envelope encryption, blind indexing |
| `ai` | Python | Risk scoring, anomaly tracking — advisory only |

### Control plane — off the login path

| Service | Language | Job |
| --- | --- | --- |
| `api` | Python | Tenants, policy, admin |
| `worker` | Python | Webhooks, audit export, batch jobs |
| `console` | TypeScript | Admin and self-service UI |

### Integration — any website, any mobile app

Every client integrates through the gateway's standard OIDC / OAuth 2.1
surface; anything OIDC-certified works with no code from us. Client kits that
make the secure path the easy path live in [sdk/](sdk/); mobile-specific
guidance is in [docs/mobile-integration.md](docs/mobile-integration.md).

---

## Security model

### Why three languages

Each language sits where its own failure mode costs the least.

| Service | Holds keys | Holds state | Public | If compromised, the attacker gets |
| --- | --- | --- | --- | --- |
| `gateway` | ❌ | ✅ | ✅ | Ciphertext it cannot read, plus an RPC surface |
| `crypto` | ✅ | ❌ | ❌ | Everything — but the smallest, most-reviewed code |
| `ai` | ❌ | ⚠️ behavioural | ❌ | A score generator with no authority |

Python carries the largest dependency tree, so it is the **most likely** service
to be compromised — and it is given the **least** power. Rust is the least
likely and holds the most. Likelihood and blast radius run in opposite
directions; that is the point of the split.

| Language | Chosen for the one thing it alone provides |
| --- | --- |
| Rust | Deterministic key erasure. No garbage collector can copy a secret and leave the original behind. |
| Go | Deadline propagation via `context`, cheap concurrency, mature OIDC and TLS libraries. |
| Python | The ML ecosystem — and nothing else. |

⚠️ The vault sits **furthest** from the internet, not closest. If Rust faced the
public edge, every HTTP parsing bug would be a bug in the process holding the
KEK. The Guard only ever sees input the Gateway has already validated.

### Request order — cheapest check first

Each stage costs more than the last and runs only if the cheaper one passed.

| # | Stage | Budget | On failure |
| --- | --- | --- | --- |
| 1 | Go — rate limit, tenant resolve, input shape | ~1 ms | Reject |
| 2 | Rust — verify the cryptographic proof | ~15 ms | ❌ Reject, stop here |
| 3 | Python — score the risk | ~50 ms | ⚠️ Continue at band `HIGH` |
| 4 | Go — combine verdict, score, tenant policy | ~20 ms | — |

⚠️ Step 3 never runs for an attempt that failed step 2. **Authenticate before
you compute.** Scoring in parallel would save ~15 ms on a real login and hand an
attacker a free way to exhaust the most expensive service in the system with
forged signatures.

### Fail-closed matrix

Degradation is always toward strictness.

| Failure | Behaviour |
| --- | --- |
| Guard unreachable or slow | ❌ Reject all authentication. No fallback path exists. |
| Thinker unreachable or slow | ⚠️ Apply band `HIGH`. Step-up required, not denied. |
| KMS or Vault unreachable | ❌ Guard refuses to unwrap. Encrypted reads fail. |

The asymmetry is deliberate. No Guard means we cannot prove identity, so nobody
gets in. No Thinker means we cannot rate risk, so everybody is treated as risky.
Neither degrades toward open.

### What each layer actually protects

Rust owns exactly one row of this table. The rest is configuration and
discipline, and no language choice performs them for you.

| Layer | Covered by |
| --- | --- |
| Memory safety, key erasure | 🦀 Rust — `#![forbid(unsafe_code)]`, `zeroize` on drop |
| CPU and cache side channels | Confidential VM, constant-time crates (`subtle`) |
| Disk | No swap, `mlock` on key pages, read-only rootfs, `tmpfs` for temp |
| Dependencies | `cargo-deny`, `pip-audit`, small dependency counts, pinned lockfiles |
| Traffic | mTLS, per-pair networks, rate limits |
| Infrastructure | Non-root, dropped capabilities, no shell in the image |

⚠️ "We used Rust" is the same error as "we have passkeys." Each closes one layer
completely and nothing else. Rust does not protect the CPU, disk, cache,
dependencies, traffic, or infrastructure.

⚠️ Two Rust traps worth fixing early: integer overflow **wraps silently** in
release builds — set `overflow-checks = true` for the crypto crate; and
`build.rs` executes arbitrary code at compile time, so a poisoned crate runs on
CI before any binary ships.

### Cryptographic provider

Primitives sit behind a `CryptoProvider` trait, so the backend is a deployment
choice rather than a code change.

| Backend | Used by | FIPS 140-3 |
| --- | --- | --- |
| RustCrypto / `ring` | Development and non-regulated deployments | ❌ Not validated |
| `aws-lc-rs` in FIPS mode | `regulated` profile | ✅ Validated |
| PKCS#11 offload to a customer HSM | `regulated`, customer key custody | ✅ Inherited from the device |

⚠️ This abstraction has to exist before the first crypto call site is written.
US financial buyers require validated modules, and no pure-Rust library is
validated or pursuing validation. Adding FIPS later means touching every call
site in the service that holds the keys — the change nobody wants to review
under a deadline. Detail in [docs/key-custody.md](docs/key-custody.md).

⚠️ A validated module also *removes* algorithms. Ed25519 is absent from some
FIPS builds, so ES256 is the safe default for passkey verification.

---

## Deployment

### Containers

One container per service, hardened by trust level. A container is not a
security boundary by default — the isolation comes from this configuration.

| | `gateway` (Go) | `crypto` (Rust) | `ai` (Python) |
| --- | --- | --- | --- |
| Base image | distroless | scratch | distroless-python |
| Shell present | ❌ None | ❌ None | ❌ None |
| Runs as root | ❌ No | ❌ No | ❌ No |
| Filesystem | Read-only | Read-only | Read-only |
| Linux capabilities | Drop all | Drop all | Drop all |
| Public ingress | ✅ The only one | ❌ Never | ❌ Never |
| Internet egress | Tunnel only | KMS only | ❌ None |

Exporting models to ONNX takes the Python image from roughly 2 GB to 200 MB.
That is not only a speed decision — it removes most of the packages that would
otherwise need auditing.

### Ingress

The public door is an adapter. Cloudflare Tunnel is one implementation of it,
not the architecture.

| Adapter | For |
| --- | --- |
| Cloudflare Tunnel | SaaS and self-hosted deployments with no inbound firewall holes |
| Customer load balancer — F5, NGINX, Envoy | Deployments that terminate their own TLS |
| Cloud private link | Customer-cloud deployments with no public route at all |

⚠️ A mandatory third-party SaaS in the authentication path fails architecture
review at any bank: it is an unapproved fourth party, a concentration risk, and
it terminates TLS. The property worth keeping is *one public door with no
inbound firewall holes* — not one particular vendor's tunnel.

### Networks

Three networks, not one. The Guard and the Thinker cannot reach each other —
there is no path, so a compromised ML dependency cannot send a packet toward the
keys.

| Network | Members |
| --- | --- |
| `edge` | Ingress adapter + `gateway` |
| `net-a` | `gateway` + `crypto` |
| `net-b` | `gateway` + `ai` |

Guard and Thinker are `expose`d, never `ports`-published. Certificates are
mounted at runtime, never baked into an image.

### Transport

| Property | Value |
| --- | --- |
| Protocol | gRPC over mutual TLS |
| Certificate lifetime | 24 h, rotated automatically from an internal CA |
| Peer check | Certificate validity **and** an identity allowlist |
| Plaintext gRPC | Not a supported mode, including local development |

A valid certificate is not authorisation. `gateway` may call both services;
neither of them may call anything.

⚠️ If development runs without mTLS, development and production behave
differently, and the development path eventually ships.

### Repository

Single repository. The `.proto` contract is shared by all three services, so a
contract change and its three implementations must land in one commit that CI
verifies together. Separate repositories would make that a four-PR dance with no
way to check the services still agree.

```text
proto/      the wire contract, source of truth
gateway/    Go — public door, tenant boundary, OIDC, sessions
crypto/     Rust — keys, passkey verification, envelope encryption
ai/         Python — advisory risk scoring
api/        Python — control plane: tenants, policy, admin
worker/     Python — webhooks, audit export, batch jobs
console/    Next.js — admin and self-service UI
sdk/        client kits: web, iOS, Android, Flutter, React Native, server
deploy/     compose files, network configuration
docs/       threat model, backlog, compliance, custody, mobile
```

⚠️ Every directory exists and holds a README — the service's contract with the
rest of the system: its job, what it holds, what it must never do, and its
container hardening. **No code yet, by explicit decision: plan before code.**
When building starts, the first code to land is `proto/` plus the CI guard
below, so the schema rule is enforced from the very first commit of code.

CI enforces two invariants:

| Check | Prevents |
| --- | --- |
| `buf breaking` | Silent wire-format breaks between services |
| Schema guard on `RiskAssessment` | Any `allow` / `deny` / `decision` field being added |

The second turns "the risk model must never authorise" from a rule people
remember into a build failure nobody can bypass in a hurry.

---

## Configuration profiles

Deployments differ. Rather than dozens of independent switches — which produce
thousands of combinations nobody tested — Ai-Auth ships named profiles.

| Profile | Meaning |
| --- | --- |
| `strict` | **Default.** Passkey or hardware key only. No phishable path anywhere, including recovery. |
| `balanced` | Passkey required for sensitive actions; social login permitted for ordinary use. |
| `legacy` | Social and email paths permitted everywhere. Migration only. |
| `regulated` | `strict`, plus FAPI 2.0 enforcement, customer key custody, validated cryptography, and full audit export. For financial and regulated deployments. |

### Why `strict` is the default

Every user gets the security level a bank would demand, because the parts of
that level which matter most cost nothing to give away.

| Bank-grade **security** — free once written, on by default | Bank **compliance** — costs real money, `regulated` only |
| --- | --- |
| Phishing-resistant login, passkeys and hardware keys | FIPS 140-3 validated module |
| No bearer credential anywhere — DPoP, DBSC | Customer-held HSM key custody |
| Fail-closed on every failure path | SOC 2 and ISO 27001 attestations |
| Key separation, no route from the ML service to the keys | DORA contracts, audit and inspection rights |
| Short access tokens, one-time refresh tokens | WORM audit retention |
| Recovery as strong as login | PSD2 dynamic linking for payments |
| Full audit trail of every decision | Threat-led penetration testing |

The left column is the entire reason for this architecture, and none of it gets
cheaper by being weakened for a smaller deployment. So it is the default, and
opting *down* is the deliberate act.

⚠️ **The cost of this choice is real.** Under `strict` a user whose device
cannot do WebAuthn cannot sign in, and no email link will rescue them. An
operator who needs that must explicitly select `balanced` or `legacy` and accept
the phishable path in writing. That is the intent: the weak door is a decision
somebody made, never a default somebody inherited.

⚠️ **`strict` makes second-credential enrolment mandatory, not a nudge.** A
synced passkey (iCloud Keychain, Google Password Manager) does survive device
loss — the user signs into their platform account on a new device and the
passkey returns. But sync has a price and a boundary. The price: the account is
now only as strong as the platform account's own recovery, which is why NIST
caps synced passkeys at AAL2 — the weakest-path rule follows the chain into
Apple's and Google's buildings. The boundary: device-bound passkeys and hardware
keys never sync, platform accounts can themselves be lost, and passkeys do not
cross ecosystems. So high-assurance actors — operators, staff, `regulated`
deployments — must use non-synced credentials, and for them a single credential
on a single lost device **is** a permanent lockout. Two credentials before the
account becomes usable — see the P0 rows in
[docs/hardening-backlog.md](docs/hardening-backlog.md) §2.

`regulated` is not a stricter set of preferences. It turns on requirements that
an auditor or a certification body checks, and it fails closed at startup if any
of them cannot be satisfied.

| Under `regulated` | Enforced |
| --- | --- |
| PAR, `iss` response parameter, exact redirect match, `S256` PKCE | FAPI 2.0 Security Profile |
| Client auth by mTLS or `private_key_jwt` only | No client secrets in redirect flows |
| Sender-constrained tokens, no bearer path anywhere | DPoP or mTLS-bound |
| Validated cryptographic provider | FIPS backend or HSM offload |
| Customer key custody | KEK in the customer's HSM; we cannot decrypt alone |
| Ingress adapter without a third party | No fourth party in the auth path |
| Append-only audit log with SIEM export | Retention and WORM export configured |
| Telemetry egress | Off, allowlist only |

⚠️ Startup refuses to run `regulated` on an unvalidated crypto backend, a
vendor-held KEK, or a bearer-token configuration. A profile that silently
degrades is worse than no profile — it produces a deployment that believes it is
compliant. See [docs/compliance.md](docs/compliance.md).

Two kinds of setting, and only one of them gets a switch:

| Kind | Example | Configurable |
| --- | --- | --- |
| Policy — the deployment's risk appetite | Which factors, session lifetime, which providers | ✅ Yes |
| Safety rail — no legitimate reason to disable | Exact redirect URI match, PKCE required, reject `alg: none`, verify passkey origin | ❌ No |

⚠️ Most operators never change defaults, so the default profile is the real
security level of the product. That is precisely why the default is the
strongest profile rather than the most convenient one — an operator who never
opens the configuration file still ships a phishing-resistant deployment.

Flag names state the risk plainly — `allow_phishable_recovery: true`, never
`easy_recovery: true`. Nobody enables the first by accident, and every
step-down is written to the audit log as an explicit downgrade event.

The admin console reports the **effective** assurance level computed from the
running configuration, because security is set by the weakest permitted path,
not the strongest available one. Startup refuses incoherent combinations, such
as a passkey-only login policy beside email-link recovery.

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

The table below is the `strict` **default profile**. Every actor gets a
phishing-resistant path, and no actor has a weaker one available.

| Actor | Default requirement (`strict`) | Phishable path? | If an operator opts down to `balanced` |
| --- | --- | --- | --- |
| Operator setup | Two passkeys, or a passkey plus a hardware key | ❌ None | Facebook + Google + passkey |
| Operator daily | Passkey or hardware key | ❌ None | Passkey, **or** both socials ⚠️ |
| Shopper | Passkey or hardware key | ❌ None | Facebook, passkey optional ⚠️ |
| Staff | Console-provisioned, passkey required at login | ❌ None | Console-provisioned, factor unspecified ⚠️ |
| Recovery, all actors | Second enrolled credential | ❌ None | Email link ⚠️ |

⚠️ Social login is **not** an authenticator under `strict`. It may identify an
account, never prove it. This is the whole point of the default: the weakest
permitted path sets the assurance level, so under `strict` there is no weaker
path for it to be set by.

⚠️ The right-hand column is what an operator gives up by opting down. Under
`balanced` the social path is proxy-phishable (T1 Path A), so an operator's
passkey stops raising their assurance level at all. What still carries weight
there is the step-up requirement on sensitive actions: a stolen social session
can read, but cannot change credentials, move money, or alter tenant settings.
Every step-down is written to the audit log.

⚠️ Recovery moves with the login policy automatically — a `strict` login path
beside email-link recovery is still an email-link system, so `strict` forbids
both (T3). Enrolling a second credential at signup is what makes that
survivable, and it matters more than any recovery flow design. Startup refuses
a configuration where recovery is weaker than login.

⚠️ The `Staff` row previously described provisioning only — who may obtain an
account, not what proves their identity at login. Under a `strict` default the
gap closes by inheritance: staff authenticate with a passkey like everyone else,
and console provisioning decides only who is allowed to enrol one.

---

## Non-goals

| Not building | Reason |
| --- | --- |
| Password-only login | Rejected by design |
| SMS as primary factor | SIM-swap risk |
| Directory sync (SCIM) v1 | Later, if demanded |
