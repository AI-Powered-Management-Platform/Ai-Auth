# Ai-Auth

AI-assisted identity provider. Passkey-first authentication, OIDC provider,
multi-tenant session control, and risk scoring on every login.
This is independence service package base on, API bases, container, communication base on certificate.
Infrastructure security: CF tunnel, Google PAM, Google Confidential computing 
Tigh-performance, tri-language identity provider into a production-grade, globally compliant software package, you must move from design concepts to deep technical execution.Here is the master roadmap of the core security domains you need to research and build out deeply in your codebase.

 🛡️ 1. Cryptography & Hardware Isolation (Rust Core)
Because your system handles the highest level of security, you must dive deep into how cryptography behaves inside bare-metal memory.Google Confidential Space / Intel SGX / AMD SEV: Study how to package your Rust binary into a Confidential VM, ensuring memory pages are hardware-encrypted by the CPU so root cloud administrators cannot read running data.WebAuthn Passkey Cryptography: Deeply learn the processing of Attestation and Assertion data streams from Apple/Google devices. You must safely store public keys (COSE format) and verify signatures (Ed25519 or ES256) at assembly speeds.Cryptographic Key Lifecycle Management: Architect how the master Key Encryption Key (KEK) is pulled from Google Cloud KMS or HashiCorp Vault to wrap and unwrap individual row Data Encryption Keys (DEKs).
🚀 2. Ultra-High Performance & Transport Security (Go Core)
Go owns your network edge. You must configure it to withstand intense adversarial traffic without breaking.Mutual TLS (mTLS) Mesh Network: Design an automated internal Certificate Authority (CA) pattern (like using cert-manager or HashiCorp Vault) to rotate short-lived SSL/TLS certificates for Go-Rust-Python internal gRPC communication.Zero-Allocation Network Primitives: Study how Go's sync.Pool avoids object allocation garbage collection overhead during millions of incoming login routing cycles.OIDC/OAuth2 PKCE Validation Engine: Master the exact verification mechanics of cryptographic code_challenge state tracking to eliminate mobile session hijacking vulnerabilities entirely.

🧠 3. Invisible Threat Detection & Isolation (Python Worker)
Your AI must operate with maximum defense-in-depth, treating Python packages as potentially vulnerable.ONNX Engine & C-Extension Optimization: Research how to export models from Python into .onnx formats to entirely bypass the Python Global Interpreter Lock (GIL) and cut container image sizes down.Real-time Behavioral Velocity Graphing: Figure out how to securely stream time-series metadata (login speeds, impossible physical travel times, device fingerprint mutations) from Go to Python within a strict 50ms processing window.Secure Python Dependency Isolation: Implement strict supply-chain checking (pip-audit, container scanning) to safeguard the Python container against third-party machine learning package vulnerabilities.
📂 4. Global Data Privacy & Database Engineering (DB Layer)
You must translate "world law" into strict database actions so that you remain globally compliant automatically.Application-Layer Envelope Encryption (Blind Indexing): Write the specific SQL structures and Go logic to search for user profiles via salted HMAC blind indexes, so that no plain-text emails or names exist in the database.Cryptographic Account Shredding: Build the cascading delete logic that ensures destroying a single user's encryption key instantly sanitizes all historic database backups without altering the active immutable ledger.Multi-Region Partitioning (Data Sovereignty): Study how databases like CockroachDB or Google Spanner natively route data rows to specific global geographic locations based on the user's home country.

🏛️ 5. Operational Security & Open-Source Supply Chain (SecOps)As an open-source project, your repository settings matter just as much as your code statements.Responsible Vulnerability Disclosures: Set up automated GitHub private vulnerability reporting tools so ethical hackers can submit security bugs away from public GitHub issues.Automated Secret Scanners: Integrate pre-commit and post-commit hooks like TruffleHog to guarantee that no internal development TLS certificate or production API key ever leaks into public Git history.

Securely connect mobile applications (built in platforms like iOS, Android, Flutter, or React Native) to your advanced Go/Rust/Python identity provider, you must dive deeply into mobile-specific security architecture.Unlike web browsers, mobile apps run inside a sandbox on a physical hardware device, communicate over unstable mobile networks, and cannot securely use traditional HTTP-only web cookies.Here is the deep-dive technical roadmap of the security concepts and implementation primitives you must master for mobile integration.
🛡️ 1. OAuth2/OIDC with PKCE (Proof Key for Code Exchange)
Standard OAuth2 is vulnerable on mobile devices because malicious apps can intercept redirect deep links. PKCE solves this by forcing a dynamic cryptographic proof for every single login session.The Cryptographic Handshake: Your Go Core Gateway must expose an explicit /authorize and /token endpoint that enforces the PKCE protocol.The mobile app creates a random string on the fly (code_verifier).The app hashes it using SHA-256 (code_challenge).Your Go Gateway saves this challenge. When exchanging the temporary code for tokens later, Go hashes the provided verifier. If it matches the challenge, Go issues the tokens.Deep Link Hijacking Prevention: You must teach mobile developers how to configure Universal Links (iOS) and App Links (Android). These verify that only their official app can intercept the authentication callback URL by matching a digital signature file (apple-app-site-association or assetlinks.json) hosted publicly on your Go router.

🔑 2. Native Mobile Passkeys (WebAuthn Native API)
Your users want biometric login (FaceID, TouchID, or Fingerprint) that works directly via the device's secure hardware.ASWebAuthenticationSession (iOS) & Credential Manager (Android): Mobile apps should not build custom web forms for logins. They must use the operating system's native secure browser modules. These modules hook directly into the phone’s hardware enclave to securely pass passkey public-key signatures back to your Rust Cryptography Core for absolute validation.Passkey Syncing Security: Understand how passkeys roam and sync via iCloud Keychain or Google Password Manager. Your system must handle scenarios where a passkey is securely shared across a user's multi-device ecosystem while maintaining strict multi-tenant validation

📦 3. Secure On-Device Storage (Hardware Enclaves)
Once your Go engine issues an Access Token and a long-lived Refresh Token to the mobile app, storing them insecurely (like in plain text files) will result in immediate token theft if a device is rooted or compromised.iOS Keychain Services: Learn how to utilize the iOS Keychain with strict accessibility attributes (e.g., kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly). This guarantees tokens are hardware-encrypted and can never leave that specific physical phone via an iCloud backup.Android Keystore & EncryptedSharedPreferences: Master Android's hardware-backed keystore provider. This isolates cryptographic keys from the application code space, ensuring that even if the app's process is memory-inspected, the master token-encryption keys remain hidden inside the device's secure hardware layer

📡 4. Advanced Network Defense & Telemetry Extraction
Mobile network traffic is easily intercepted via public Wi-Fi networks using Man-in-the-Middle (MitM) tools. Your system must actively protect the transport layer.Strict SSL/TLS Pinning: Teach mobile clients how to implement certificate pinning. The mobile app will reject any connection to your Go Gateway unless the server presents the exact cryptographic public key certificate hardcoded into the app. This makes public Wi-Fi traffic sniffing impossible.Mobile Telemetry Injection for your Python AI: Your mobile app must capture unique mobile signals to stream to your Python AI Worker for accurate risk scoring. You need to gather:Device Integrity Attestation: Using Google Play Integrity API (Android) or DeviceCheck/App Attest (iOS) to cryptographically prove the app hasn't been cracked, modified, or run inside a malicious emulator.Network Velocity: Rapidly changing IP addresses or cellular carrier switching to flag potential location-spoofing or proxy usage

🛑 5. Mobile Session Lifecycle & Instant Revocation
Mobile users rarely log out. Sessions can last for months, making an active mobile token a high-value target.Short Access / Long Refresh Pattern: Keep Access Tokens valid for only 5 to 15 minutes. Issue Refresh Tokens that last for weeks but are rotated on every single use (Refresh Token Rotation). If a hacker steals a used refresh token and tries to reuse it, your Go engine will instantly invalidate the entire session tree.Real-time Push Revocation: If your Python AI worker detects a severe risk anomaly elsewhere on the account, your system must use a high-speed backchannel (like Redis Bloom Filters or Firebase Silent Push Notifications) to instantly flag the on-device mobile storage to wipe its local tokens immediately.


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
