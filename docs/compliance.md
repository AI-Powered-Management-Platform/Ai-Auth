# Ai-Auth — compliance and certification map

Which control in this repository answers which framework, and what is still
missing. Written for the security questionnaire a regulated buyer sends before
they will take a first meeting.

⚠️ **Nothing here is certified.** Ai-Auth is at design stage. Every row below
states an *intended* control and its design status. No audit has been performed,
no certification has been awarded, and no claim in this document may be repeated
to a customer as a completed fact until the corresponding evidence exists.

| Status | Meaning |
| --- | --- |
| ✅ | Designed and specified in this repository |
| ⚠️ | Partially designed — named, not yet specified |
| ❌ | Gap — nothing designed yet |
| 📋 | Not a code deliverable — needs money, time, or an organisation |

| Related | Contents |
| --- | --- |
| [hardening-backlog.md](hardening-backlog.md) | The build order for these controls |
| [threat-model.md](threat-model.md) | Why each control exists |
| [key-custody.md](key-custody.md) | Key ownership, HSM, FIPS |
| [trust-package.md](trust-package.md) | The evidence bundle buyers ask for |

---

## 1. The certification ladder

Do these in order. Each rung earns the references the next one demands.

| # | Certification | Opens | Rough cost | Elapsed | Status |
| --- | --- | --- | --- | --- | --- |
| 1 | OpenID Connect conformance (Basic, Config OP) | Any serious buyer | Suite free to run; listing fee applies | Weeks, once stable | ❌ |
| 2 | FAPI 2.0 Security Profile + Attacker Model | Open banking, regulated fintech | Low thousands | 2–4 months | ❌ |
| 3 | SOC 2 Type II | Mid-market B2B, US | $25–60k/yr | 6–12 mo observation | 📋 |
| 4 | ISO 27001:2022 (+ 27017, 27018) | EU and Asia buyers | $20–50k/yr | 6–12 months | 📋 |
| 5 | Penetration test, named firm, annual | Everyone above | $15–40k | 4–8 weeks | 📋 |
| 6 | FIPS 140-3 validated crypto path | US financial, federal-adjacent | Inherited from provider or HSM | Architectural | ❌ |

⚠️ The rung-1 conformance suite costs nothing to run against a deployment, and
it is the rung most projects skip. Its absence is read as "they have not tested
against the spec." The paid listing matters less than the passing result.

⚠️ SOC 2 Type I is not a substitute for Type II. Regulated buyers ask for the
Type II report with a full observation window and a bridge letter covering the
gap since it closed.

---

## 2. FAPI 2.0 Security Profile

The single most important certification for financial buyers. Most of the
profile is already implied by the design; the gaps are specific and small.

| FAPI 2.0 requirement | Ai-Auth control | Status |
| --- | --- | --- |
| PKCE required, `S256` only, no `plain` | Mandatory PKCE, safety rail, not configurable | ✅ |
| Exact redirect URI string matching | Safety rail, no wildcards or prefixes | ✅ |
| Authorization code flow only — no implicit, no hybrid | O — OAuth 2.1 / OIDC provider | ✅ |
| Sender-constrained access tokens (mTLS or DPoP) | DPoP by default; mTLS-bound option P1 | ✅ |
| Pushed Authorization Requests (RFC 9126) | Backlog §5, promoted to P0 | ⚠️ |
| `iss` in the authorization response (RFC 9207) or JARM | Backlog §5 | ⚠️ |
| Client authentication by mTLS or `private_key_jwt` | Not yet specified | ❌ |
| No `client_secret_basic` or `client_secret_post` | Not yet specified | ❌ |
| Refresh tokens sender-constrained or rotated | R — refresh token rotation, one-time use | ✅ |
| Bounded access token lifetime | Short access TTL, minutes | ✅ |
| Algorithm allowlist, `none` rejected | Safety rail, not configurable | ✅ |
| TLS 1.2 minimum, restricted ciphers; 1.3 preferred | mTLS everywhere, internal CA | ⚠️ |
| Authorization server metadata / discovery document | O — discovery document | ✅ |

**The four gaps are client authentication, PAR, `iss`, and a written TLS
profile.** Nothing else in FAPI 2.0 needs new architecture.

The FAPI 2.0 **Attacker Model** assumes an attacker who reads and modifies
network traffic, can register as a client, and controls a co-resident app. That
is the same adversary as [threat-model.md](threat-model.md) T1 Path A, so the
threat model already argues the case — it just needs to cite the profile.

---

## 3. NIST SP 800-63-4

Finalised July 2025. Buyers use it as vocabulary even outside the US.

| Level | Requirement | Ai-Auth | Status |
| --- | --- | --- | --- |
| AAL1 | Single factor | Below our floor — not offered | ✅ |
| AAL2 | Two factors, or one multi-factor authenticator. Syncable passkeys explicitly accepted | Met by the `strict` default; `balanced` and `legacy` fall below it on their phishable paths | ✅ |
| AAL3 | Hardware-bound authenticator, verifier impersonation resistance, no syncable credential | `strict` (default) or `regulated`, with a roaming key or device-bound passkey rather than a synced one | ⚠️ |
| FAL1–3 | Federation assurance | Not yet mapped | ❌ |
| IAL1–3 | Identity proofing | Out of scope — V hooks to KYC providers | 📋 |

| 800-63B rule | Ai-Auth | Status |
| --- | --- | --- |
| Breached-credential blocklist, k-anonymity lookup | Backlog §6, P0 | ⚠️ |
| No composition rules, no forced periodic rotation | Password-only login is a non-goal | ✅ |
| Phishing-resistant authenticator at AAL3 | Passkeys, FIDO2 keys | ✅ |
| Reauthentication limits — absolute and inactivity ceilings | Absolute + idle timeouts, `max_age` step-up | ✅ |

⚠️ **The AAL3 claim depends on the profile, and profiles are per-deployment.**
The console already reports the *effective* assurance level from running
configuration — that reporting is what makes an AAL claim defensible in an
audit, and it should emit the AAL number directly rather than a house term.

---

## 4. PSD2 strong customer authentication (EU)

Relevant if any customer is a payment service provider. RTS (EU) 2018/389.

| Requirement | Ai-Auth | Status |
| --- | --- | --- |
| Two of three: knowledge, possession, inherence | Passkey = possession + inherence | ✅ |
| Independence of elements — breach of one does not compromise another | Service split, hardware-backed keys | ✅ |
| **Dynamic linking** — the auth code is bound to amount and payee; any change invalidates it | **Nothing designed** | ❌ |
| Exemption handling — low value, TRA, trusted beneficiaries, recurring | Not designed | ❌ |
| Re-authentication interval for account information access | Absolute session lifetime exists; the specific interval is not encoded | ⚠️ |
| Audit trail of every SCA decision | Backlog §11 | ⚠️ |

⚠️ **Dynamic linking is the gap a generic IdP always has.** A payment
authentication is not "prove who you are" — it is "prove you approve *this
amount* to *this payee*." That means a transaction-binding challenge carried
through WebAuthn and displayed on the authenticator, plus invalidation on any
field change. It is a distinct feature, not a configuration of login.

⚠️ PSD3 and the PSR are in the EU legislative process and will change this
section. Do not hard-code RTS article numbers into product copy.

---

## 5. DORA (EU) — the contract is a technical requirement

Regulation (EU) 2022/2554, applying since 17 January 2025. If a customer is an
EU financial entity, DORA obligations flow to us by contract whether or not we
are established in the EU.

| DORA expectation | What we must provide | Status |
| --- | --- | --- |
| Full description of services and processing locations | Data flow diagrams, region list | ⚠️ |
| Data protection, availability, integrity terms | Contract | 📋 |
| **Access, inspection, and audit rights** — including on-site | Contract + willingness to host auditors | 📋 |
| **Exit strategy and data portability** | Documented export format and migration runbook | ❌ |
| Subcontractor conditions and change notification | Subprocessor list and notice period | ❌ |
| Incident reporting to the financial entity, on their timeline | Contractual SLA, not our 90-day public policy | ⚠️ |
| Service level descriptions with quantitative targets | RTO, RPO, availability numbers | ❌ |
| Support for their Register of Information | Structured facts: LEI, entity, function, criticality | ❌ |
| Participation in threat-led penetration testing | Where a customer is in scope | 📋 |

⚠️ DORA is why "we can add all of this" is only half true. Audit rights, exit
plans, and incident SLAs are contractual commitments an organisation makes, not
documents a repository contains. What the repository *can* do is make them cheap
to honour: a documented export format makes the exit plan real, and an
append-only audit log makes the inspection right answerable.

---

## 6. SOC 2 and ISO 27001

Both are about the organisation, not the product. Listed so the split is clear.

| Framework | What it audits | Product work | Organisation work |
| --- | --- | --- | --- |
| SOC 2 Type II | Controls operating over 6–12 months | Access logging, change management evidence, monitoring | Policies, onboarding/offboarding, vendor management, risk register |
| ISO 27001:2022 | An ISMS, 93 Annex A controls in 4 themes | Technological theme, ~34 controls | Organisational, People, Physical themes — ~59 controls |

Roughly **two thirds of both is paperwork we cannot write in code.** The design
already covers most of the technological half: least privilege, cryptography,
secure development, logging, network segregation, capacity, secure deletion.

---

## 7. PCI DSS 4.0 — read the scope before claiming anything

Ai-Auth does not process, store, or transmit cardholder data, so it is not in
the cardholder data environment. It becomes relevant one step removed:

| PCI DSS 4.0 requirement | Relevance |
| --- | --- |
| 8.4.2 — MFA for all access into the CDE | If Ai-Auth is the MFA in front of a customer's CDE, it is a security-impacting system |
| 8.5.1 — MFA not bypassable, at least two distinct factors, replay-resistant | Passkeys satisfy this cleanly; a phishable fallback does not |
| 12.8 — third-party service provider management | We appear on their vendor list either way |

⚠️ Never write "PCI DSS compliant" about an IdP. Write "supports requirement
8.4.2 and 8.5.1 for access into a customer's CDE." The first is meaningless and
an assessor will say so.

---

## 8. EU AI Act

Regulation (EU) 2024/1689. Prohibited practices have applied since February
2025; high-risk obligations phase in through 2026 and 2027.

Our position is unusually strong here **because the model has no authority**:

| Concern | Answer |
| --- | --- |
| Does the AI make decisions about people? | No. It emits an advisory score. A CI schema guard fails the build if `allow`, `deny`, or `decision` is added to `RiskAssessment` |
| Is it biometric categorisation or emotion recognition? | No. Behavioural velocity and device metadata only |
| Is there human oversight? | Authorisation is decided by the gateway from a cryptographic verdict and tenant policy |
| Is the outcome explainable? | Backlog §7 — every score explainable and stored |
| What if the model fails? | Fail closed to band `HIGH`. Degradation is toward strictness, never toward open |

⚠️ Whether login risk scoring falls under an Annex III high-risk category is a
legal question that depends on the deployment — access control to essential
services draws more scrutiny than fraud scoring. **Get counsel before making any
classification claim in writing.** This document does not settle it.

⚠️ Model risk management rules apply separately and regardless: SR 11-7 in the
US, EBA guidelines in the EU. Buyers will ask for model documentation,
validation evidence, and ongoing monitoring. Backlog §7 covers the technical
half.

---

## 9. Asia-Pacific

Named so they are not forgotten. Each needs local verification before any claim.

| Jurisdiction | Instrument | Notes |
| --- | --- | --- |
| Singapore | MAS TRM Guidelines; Notice on Cyber Hygiene | Requires MFA for administrative accounts — directly in our path |
| Hong Kong | HKMA Supervisory Policy Manual, e-banking authentication | Two-factor expectations for high-risk transactions |
| Malaysia | BNM RMiT | Prescriptive on cryptography and key management |
| Australia | APRA CPS 234; CPS 230 operational risk | CPS 234 pushes information-security obligations onto service providers by contract |
| India | RBI directions on IT governance and outsourcing | Data localisation implications |
| Cambodia | NBC technology and cyber-risk regulations | ⚠️ Specifics not verified here — confirm the current Prakas with local counsel |

⚠️ This table is a starting list, not legal advice, and the region moves fast.
Verify every row against the current instrument before it reaches a customer
document.

---

## 10. Consolidated gaps

Everything marked ❌ above, in build order.

| # | Gap | Blocks | Where it lands |
| --- | --- | --- | --- |
| 1 | Crypto provider abstraction + FIPS backend | US financial market, permanently if missed | [key-custody.md](key-custody.md) |
| 2 | Client authentication by mTLS / `private_key_jwt` | FAPI 2.0 | Backlog §5 |
| 3 | PAR and `iss` response parameter | FAPI 2.0 | Backlog §5 |
| 4 | Written TLS profile, versions and ciphers | FAPI 2.0, most questionnaires | Backlog §10 |
| 5 | Pluggable ingress — remove the mandatory fourth party | Architecture review at any bank | Backlog §10 |
| 6 | Append-only audit log + SIEM export | DORA, SOC 2, ISO 27001, every buyer | Backlog §11 |
| 7 | Documented export format and exit runbook | DORA exit strategy | Backlog §10 |
| 8 | Quantitative RTO, RPO, availability targets | DORA, every questionnaire | 📋 + design |
| 9 | Dynamic linking for payment authentication | PSD2 SCA, PSP customers only | New feature |
| 10 | FAL mapping for federation | NIST 800-63-4 completeness | Backlog §5 |

---

## What this document does not claim

| Not claimed |
| --- |
| That any certification has been obtained |
| That any control has been audited, tested, or independently verified |
| That any code implementing these controls exists |
| That the regulatory summaries here are legal advice |
| That the jurisdiction list is complete |

The purpose of this file is to make the distance between design and compliance
**visible and countable**, so that nobody — including us — mistakes an intention
for an attestation.
