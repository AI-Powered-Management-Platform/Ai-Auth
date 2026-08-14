# Ai-Auth — security hardening backlog

Researched 2026-07-30 against current standards and live attack data. Each item
is a feature to build, not advice.

Priority: **P0** ship before first real user · **P1** before paid tenants ·
**P2** roadmap · **PR** required by the `regulated` profile regardless of the
number beside it.

| Related | Contents |
| --- | --- |
| [threat-model.md](threat-model.md) | Attack mechanics behind these controls |
| [compliance.md](compliance.md) | Which framework demands which control |
| [../SECURITY.md](../SECURITY.md) | How to report a vulnerability |

⚠️ This is a build backlog, not a vulnerability disclosure policy. Report
security issues through [SECURITY.md](../SECURITY.md).

---

## 0. The v1 cut — what gets built first

Added 2026-08-14 to close the scope risk: the catalogue is large, the team is
small, and depth beats breadth. v1 is the smallest slice that is honestly
usable and honestly `strict`.

| In v1 | Out of v1 (deferred, not deleted) |
| --- | --- |
| `gateway` + `crypto` + Postgres/Redis | `console` beyond a minimal admin page |
| OIDC code flow + PKCE, passkey login, `strict` profile | Federation (SAML, upstream OIDC), social connectors |
| Two-credential enrolment at signup (T15) | Email OTP / magic links (`legacy` only) |
| Refresh rotation + DPoP + revocation checked every request (T11) | CAEP/SSF transmit, agent identity (RFC 8693) |
| Purpose-bound, rate-limited crypto calls (T9/T10) | HYOK/HSM adapters beyond the provider trait |
| Append-only audit log | SIEM/WORM export pipelines |
| `ai` as a rules-only stub — velocity + new-device, no ML | Trained models, ONNX pipeline, summarizer |
| Web SDK docs (plain OIDC works day one) | Native mobile SDKs |

⚠️ The `ai` stub still speaks `RiskAssessment` over the real contract, so the
schema guard and fail-closed path are exercised from the first day — the ML
inside arrives later without touching any interface.

---

## 1. The gap passkeys do not close

Passkeys defeat phishing at login. They do nothing after login. Adversary-in-
the-middle proxies now steal the session token instead of the password.

| Fact | Number |
| --- | --- |
| AiTM incident growth | Up 146% in a year |
| Detected daily | Roughly 40,000 |
| Tycoon 2FA share | 62% of Microsoft-blocked phishing |

Evilginx3, Tycoon 2FA, and Mamba 2FA sell this as a service. Login-time
hardening alone is not a defence.

| P | Feature | Detail |
| --- | --- | --- |
| P0 | Refresh token rotation | One-time use, family revoke on reuse |
| P0 | Short access token TTL | Minutes, not hours |
| P0 | DPoP sender-constrained tokens | RFC 9449, proof-of-possession per call |
| P1 | DBSC session binding | TPM-bound cookie, Chrome 146 GA |
| P1 | mTLS-bound tokens option | RFC 8705, for machine clients |
| P1 | Proxy-phishing signals | Impossible-latency, header, TLS mismatch |

DBSC shipped generally available on Windows Chrome in April 2026. It binds the
session cookie to hardware, so a stolen cookie is useless off-device.

---

## 2. ⚠️ Fallback parity — your biggest self-inflicted hole

A passkey-first system with an SMS or email OTP escape hatch is an SMS system.
The attacker simply picks the weak door. Recovery is authentication.

| P | Feature | Detail |
| --- | --- | --- |
| P0 | No phishable primary fallback | Never SMS as sole recovery |
| P0 | Recovery strength equals login | Same assurance level required; startup refuses a weaker recovery path than login |
| P0 | Downgrade events logged | Every step-down is an audit record |
| P0 | Risk-gated step-down | New device blocks weak fallback |
| P0 | Multi-credential enrolment at signup | Two credentials before the account is usable — mandatory under the `strict` default, which has no phishable rescue path |
| P1 | Trusted-contact recovery | Human path, no support ticket |
| P2 | Delayed recovery window | Time lock plus owner notification |

---

## 3. Continuous access — stop trusting old decisions

A session issued an hour ago has no idea the user was fired, the device was
wiped, or the password was breached.

| P | Feature | Detail |
| --- | --- | --- |
| P1 | Shared Signals Framework | Transmit and receive security events |
| P1 | CAEP session events | Session revoked, assurance changed |
| P1 | RISC account events | Credential compromise, account disabled |
| P1 | OIDC back-channel logout | Real global sign-out across clients |
| P2 | Policy re-evaluation mid-session | Revoke on signal, not on expiry |

SSF, CAEP, and RISC are final OpenID Foundation specs. Google, Apple, IBM,
Okta, SailPoint, Thales, and Beyond Identity have shipped implementations.
Keycloak merged an SSF transmitter in May 2026 behind an experimental flag.
Shipping this makes Ai-Auth interoperable with enterprise buyers.

---

## 4. Agent identity — the reason to call it Ai-Auth

AI agents acting for users is the live 2026 problem. Nobody has a clean answer,
which is exactly the gap a new IdP can own.

| P | Feature | Detail |
| --- | --- | --- |
| P1 | RFC 8693 token exchange | Subject token plus actor token |
| P1 | Delegation not impersonation | Token records user and agent |
| P1 | Audience-restricted tokens | Bound to one resource server |
| P1 | Delegation depth limit | Cap recursive agent chains |
| P1 | Agent registry | First-class non-human identities |
| P2 | Autonomy mode flag | Acting alone vs acting for user |
| P2 | AuthZEN authorization API | External decision point |
| P2 | Per-agent revocation | Kill one agent, keep the user |

Reference work: OpenID "Identity Management for Agentic AI" (Oct 2025), AIMS
standard (Mar 2026), CSA Agentic Trust Framework (Feb 2026).

---

## 5. Authorization request hardening

| P | Feature | Detail |
| --- | --- | --- |
| P0 | PKCE mandatory, `S256` only | No exceptions, no `plain` method |
| P0 | Exact redirect URI match | No wildcards, no prefix match |
| P0 | JWT algorithm allowlist | Blocks `none` and alg confusion |
| P0 · PR | PAR (RFC 9126) | Request never transits the browser |
| P0 · PR | `iss` in authorization response (RFC 9207) | Mix-up attack defence |
| P0 · PR | Authorization code flow only | No implicit, no hybrid |
| P0 · PR | Client auth by mTLS or `private_key_jwt` | No `client_secret_basic` or `_post` |
| P1 · PR | JAR and JARM | Signed request and response |
| P1 · PR | FAPI 2.0 Security Profile conformance | The entry ticket for regulated buyers |
| P2 | FAPI 2.0 Message Signing profile | Non-repudiation, where required |
| P2 | FAL mapping for federation | NIST 800-63C-4 assurance levels for upstream and downstream federation |

⚠️ FAPI 2.0 was previously listed here as P2. For any regulated buyer it is the
first gate, not a later nicety — see [compliance.md](compliance.md). Every row
marked **PR** exists because the profile requires it.

---

## 6. Credential and account integrity

| P | Feature | Detail |
| --- | --- | --- |
| P0 | Breached password check | k-anonymity, per NIST blocklist rule |
| P0 | Enumeration resistance | Identical response and timing |
| P0 | Re-auth for credential change | Fresh proof before adding passkey |
| P0 | Full WebAuthn verification | Origin, RP ID, sign count, attestation |
| P1 | WebAuthn Signal API | Purge stale credentials from picker |
| P1 | Step-up on sensitive actions | `acr_values` and `max_age` |
| P1 | Cross-device flow binding | Hybrid transport, no bare device code |
| P2 | AAL mapping to 800-63-4 | Syncable AAL2, device-bound AAL3 |

NIST SP 800-63-4 was finalised in July 2025. Syncable passkeys are explicitly
accepted at AAL2; AAL3 still needs device-bound hardware.

---

## 7. AI-specific risk

| P | Feature | Detail |
| --- | --- | --- |
| P0 | Risk model cannot authorise | Advisory score, never the decision |
| P0 | Fail-closed on model outage | Degrade to strict, never to open |
| P1 | Prompt injection isolation | User strings are data only |
| P1 | Model decision audit trail | Every score explainable and stored |
| P2 | Adversarial drift monitoring | Detect poisoned behaviour baselines |

---

## 8. Post-quantum readiness

| P | Feature | Detail |
| --- | --- | --- |
| P1 | Hybrid TLS key exchange | X25519 plus ML-KEM-768 |
| P2 | ML-DSA token signing | When JOSE support lands |
| P2 | Crypto inventory and agility | Swap algorithms without redeploy |

⚠️ WebAuthn itself is still ECDSA. Post-quantum passkeys do not exist yet, so
plan for a credential re-enrolment event later this decade.

---

## 9. Cryptographic provider and key custody

A regulated buyer will not accept the vendor holding the key encryption key, and
US financial buyers require validated cryptography. Both are architectural, not
configurable, so they must land before the Rust core is written.

| P | Feature | Detail |
| --- | --- | --- |
| P0 | Crypto provider abstraction | Primitives behind a trait; swap without touching call sites |
| P0 · PR | FIPS 140-3 validated backend | `aws-lc-rs` FIPS provider, or offload to an HSM |
| P0 · PR | PKCS#11 key custody | Customer HSM holds the KEK; it never reaches our memory |
| P1 · PR | BYOK and HYOK import paths | Customer-generated, customer-revocable |
| P1 · PR | Dual control on KEK operations | m-of-n quorum, split knowledge, signed ceremony record |
| P1 | Key ceremony procedure | Written, witnessed, repeatable |
| P2 | Crypto agility inventory | Swap algorithms without a redeploy |

⚠️ `ring`, `RustCrypto` and `dalek` are not FIPS validated and will not be.
Choosing them without an abstraction layer forecloses the US financial market.
Full detail in [key-custody.md](key-custody.md).

---

## 10. Pluggable ingress

| P | Feature | Detail |
| --- | --- | --- |
| P0 · PR | Ingress adapter interface | Cloudflare Tunnel is one option, not the design |
| P0 · PR | Customer-terminated TLS path | Their F5, NGINX, Envoy, or private link |
| P1 · PR | No mandatory fourth party in the auth path | Concentration risk is a review blocker |
| P1 | Air-gapped mode | Offline licence, no phone-home, offline updates |
| P1 · PR | Egress allowlist, telemetry off by default | Documented, with an off switch |
| P0 · PR | Published TLS profile | Written versions and cipher suites, FAPI-restricted; dev and prod identical |
| P1 · PR | Data export format and exit runbook | Documented, versioned, tested — what makes a DORA exit strategy real |

---

## 11. Auditability and evidence

Regulated buyers purchase the audit trail as much as the authentication.

| P | Feature | Detail |
| --- | --- | --- |
| P0 · PR | Append-only, tamper-evident log | Hash-chained records, periodic anchor |
| P0 · PR | Every admin action attributed | Including vendor support access |
| P1 · PR | SIEM streaming | CEF, LEEF, syslog, or OTel — not only a REST endpoint |
| P1 · PR | WORM export with retention policy | Seven years is the common banking figure |
| P1 · PR | Break-glass procedure | Documented, alarmed, reviewed after every use |
| P1 · PR | Model decision provenance | Score, model version, and inputs stored per decision |
| P1 | SBOM per release | CycloneDX or SPDX |
| P1 | Signed artifacts and build provenance | Sigstore/cosign, SLSA level 3 |
| P0 | Secret scanning | Pre-commit hook (TruffleHog or gitleaks) plus GitHub push protection — no key or certificate ever enters history |
| P2 | Reproducible builds | Strong differentiator on a `scratch` image |

---

## 12. Inter-service trust — the seams

Added 2026-08-14 from the adversarial review. T1–T11 controls above harden
services; these harden the trust *between* them, where the confused-deputy
class lives ([threat-model.md](threat-model.md) T9–T15).

| P | Feature | Detail |
| --- | --- | --- |
| P0 | Purpose-bound key operations | Every crypto call names subject and purpose; crypto acts only within it — T9 |
| P0 | Per-tenant authorisation inside crypto | A DEK unwraps only against same-tenant ciphertext — T10 |
| P0 | Rate and quota caps on unwrap and sign | A decryption flood or token-minting spree trips a cap — T9 |
| P0 | Per-operation key-op audit | Subject, purpose, caller, outcome — every unwrap and sign recorded — T9 |
| P0 | Revocation checked every request | Redis filter, Postgres authority — closes the TTL window — T11 |
| P0 | No ORM in the control plane | Tenant scope visible in every query — T10 |
| P0 | Re-auth and verified ownership on account linking | T12 |
| P0 | Verified channel before first-credential enrolment | T15 |
| P1 | AI features never auto-apply; injection isolation | T13 |
| P0 | Guardrail files Tier-1; pinned CI toolchain; protected branches | T14 |

⚠️ The single most important row is the first: a stateless vault that cannot
refuse its caller is a decryption and signing oracle. Making it able to say no
is what the phrase "the vault holds the keys" was supposed to mean.

---

## Sources

- [DBSC explained](https://www.corbado.com/blog/device-bound-session-credentials-dbsc)
- [Passkeys vs MFA fallbacks](https://workos.com/blog/passkeys-stop-ai-phishing-mfa-fallbacks)
- [AiTM phishing detection 2026](https://www.stingrai.io/blog/adversary-in-the-middle-aitm-phishing-detection-2026)
- [Token-based MFA bypass](https://www.obsidiansecurity.com/blog/token-based-attacks-how-attackers-bypass-mfa)
- [OpenID CAEP 1.0 final](https://openid.net/specs/openid-caep-1_0-final.html)
- [Shared Signals specifications](https://openid.net/wg/sharedsignals/specifications/)
- [OpenID approves three signal standards](https://www.biometricupdate.com/202509/openid-approves-3-standards-for-sharing-real-time-digital-identity-security-signals)
- [Keycloak SSF transmitter](https://skycloak.io/blog/keycloak-caep-shared-signals-continuous-access/)
- [IETF AI agent auth draft](https://www.ietf.org/archive/id/draft-klrc-aiagent-auth-00.html)
- [OAuth token exchange for agents](https://www.strata.io/blog/agentic-identity/why-agentic-ai-demands-more-from-oauth-6a/)
- [AuthZEN at Identiverse 2026](https://openid.net/authzen-at-identiverse-2026-authorization-in-the-agent-era/)
- [NIST SP 800-63B-4 final](https://csrc.nist.gov/pubs/sp/800/63/b/4/final)
- [NIST PQC standards](https://www.paloaltonetworks.com/cyberpedia/pqc-standards)
