# Ai-Auth — security hardening backlog

Researched 2026-07-30 against current standards and live attack data. Each item
is a feature to build, not advice.

Priority: **P0** ship before first real user · **P1** before paid tenants ·
**P2** roadmap.

Attack mechanics behind these controls: [docs/threat-model.md](docs/threat-model.md).

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
| P0 | Recovery strength equals login | Same assurance level required |
| P0 | Downgrade events logged | Every step-down is an audit record |
| P0 | Risk-gated step-down | New device blocks weak fallback |
| P1 | Multi-passkey enrolment nudge | Two credentials, not one |
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
| P0 | PKCE mandatory | No exceptions, no plain method |
| P0 | Exact redirect URI match | No wildcards, no prefix match |
| P0 | JWT algorithm allowlist | Blocks `none` and alg confusion |
| P1 | PAR (RFC 9126) | Request never transits the browser |
| P1 | JAR and JARM | Signed request and response |
| P2 | FAPI 2.0 profile | Financial-grade conformance |

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
