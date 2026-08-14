# Ai-Auth — threat model

Written 2026-07-30. Each threat lists how it works, why obvious defences fail,
and which controls actually stop it. Controls map to priorities in
[hardening-backlog.md](hardening-backlog.md), and to frameworks in
[compliance.md](compliance.md).

| ID | Threat | Severity |
| --- | --- | --- |
| T1 | Session theft after login | Critical |
| T2 | Fallback factor downgrade | Critical |
| T3 | Account recovery abuse | High |
| T4 | Cross-device flow phishing | High |
| T5 | Token leakage | High |
| T6 | Credential stuffing | Medium |
| T7 | Agent delegation abuse | Medium |
| T8 | Risk model manipulation | Medium |

---

## T1 — Session theft after passkey login

The single most important threat in this document. It is also the one a
passkey-first design does **not** solve.

### The core problem

A passkey proves who you are **once**, at the door. The server then hands the
browser a session cookie, and that cookie is a *bearer* credential.

> Bearer means: whoever holds it, is you. No further proof required.

| Phase | Credential | Phishable? |
| --- | --- | --- |
| Login | Passkey assertion | ❌ No, origin-bound |
| Everything after | Session cookie | ✅ Yes, just a string |

### Why the passkey cannot help

WebAuthn binds the signature to the exact origin. The browser refuses to sign
for a lookalike domain. That is why passkeys defeat phishing at login.

But the passkey signs **only the login challenge**. It does not sign the cookie
or any later request. Once the cookie exists, the passkey has finished its whole
job and left.

| What is protected | What is not |
| --- | --- |
| The login moment | The 90 days after |

### Path A — proxy theft (adversary-in-the-middle)

The attacker runs a reverse proxy between the user and the real site.

```text
user → attacker proxy → real login server
     ← attacker proxy ←
```

Every page the user sees is real, relayed live. The user logs in successfully.
The proxy copies the `Set-Cookie` header on its way back.

| Step | What happens |
| --- | --- |
| 1 | Phishing link, lookalike domain |
| 2 | Proxy relays the real login page |
| 3 | User authenticates, genuinely |
| 4 | Real server issues session cookie |
| 5 | Proxy copies the cookie |
| 6 | Attacker replays it, is the user |

⚠️ **This path needs a phishable factor.** A strict passkey login breaks step 3
— the browser sees the attacker's origin and will not sign. So the attack only
lands on passkey users via a downgrade:

| Downgrade path | Why it works |
| --- | --- |
| Proxy offers password plus OTP | User never reaches passkey |
| Fake "passkey unavailable" error | Real credential, wrong door |
| Account recovery flow | Recovery is usually weaker |
| Cross-device QR relay | Attacker displays the real QR |

See T2. This is the same root cause.

Sold as a service: evilginx3, Tycoon 2FA, Mamba 2FA.

| Metric | Value |
| --- | --- |
| AiTM incident growth | Up 146% in a year |
| Detected daily | Roughly 40,000 |
| Tycoon 2FA share | 62% of Microsoft-blocked phishing |

### Path B — endpoint theft

Works against a 100% passkey-only system with zero fallbacks. No phishing, no
proxy, no downgrade.

| Vector | Mechanism |
| --- | --- |
| Infostealer malware | Reads cookie store from disk |
| Malicious browser extension | Has cookie API access |
| Cookie in backup or sync | Copied off the device |
| Stolen or resold laptop | Cookies still valid |

The user authenticates perfectly with a hardware-backed passkey. Malware then
copies the resulting cookie out of the browser profile.

⚠️ Login security was never the weak point here. This is the path most teams
miss when they say "we have passkeys, we're done."

### Path C — token leakage

| Vector | Mechanism |
| --- | --- |
| XSS on our domain | Reads non-HttpOnly cookie |
| Token in URL or referrer | Leaks to third parties |
| Server or proxy logs | Tokens written to disk |
| Misconfigured CORS | Cross-origin read allowed |
| Open redirect | Fragment token forwarded |
| Mobile deep-link hijack | Another app claims the scheme |

### What the attacker gets

| Item | Typical value |
| --- | --- |
| Consumer session cookie | 30 to 90 days |
| Refresh token lifetime | Often 90 days |
| Re-authentication needed | Usually none |
| MFA prompt on replay | None, already satisfied |

They land **inside** an authenticated session. The MFA policy already passed, so
it never fires again. A password change does not always kill a live session.

### Controls — Tier 1, kill the bearer model

Make the credential worthless without the original hardware.

| Control | How it works | P |
| --- | --- | --- |
| DBSC | Cookie bound to TPM key | P1 |
| DPoP (RFC 9449) | Each request signed by client | P0 |
| mTLS tokens (RFC 8705) | Token bound to client certificate | P1 |

**DBSC** — the browser creates a key pair in the TPM at session start. The
server issues a short-lived cookie. The browser silently proves possession of
the private key to refresh it. A cookie copied to another machine cannot be
refreshed and dies within minutes. Shipped generally available on Windows Chrome
in April 2026.

**DPoP** — the client signs a small JWT over the HTTP method, URL, and a nonce
for every call. The access token carries a `cnf.jkt` thumbprint of the public
key. A stolen token without the private key is rejected.

| Property | DBSC | DPoP |
| --- | --- | --- |
| Surface | Browser cookies | API tokens |
| Key storage | TPM, hardware | App-managed |
| Who implements | Browser vendor | Us |

### Controls — Tier 2, shrink the window

| Control | Effect | P |
| --- | --- | --- |
| Short access TTL | Minutes, not hours | P0 |
| One-time refresh tokens | Reuse detected instantly | P0 |
| Family revoke on reuse | Whole chain dies | P0 |
| Absolute session lifetime | Hard ceiling regardless | P0 |

Rotation is also a detector. The attacker and the real user both present the
same refresh token; the second use is a detected reuse; revoke the family.

### Controls — Tier 3, detect and revoke fast

| Control | Signal | P |
| --- | --- | --- |
| CAEP / Shared Signals | Push revocation to all apps | P1 |
| Impossible travel | Two continents, ten minutes | P1 |
| Device fingerprint change | Cookie moved machines | P1 |
| TLS fingerprint mismatch | Different client stack | P1 |
| Latency anomaly | Extra proxy hop | P1 |
| User agent shift mid-session | Cookie replayed elsewhere | P1 |

### Controls — Tier 4, contain the damage

| Control | Effect | P |
| --- | --- | --- |
| Re-auth for sensitive actions | Fresh passkey before money moves | P1 |
| Step-up via `max_age` | Old session cannot act | P1 |
| HttpOnly, Secure, SameSite | Blocks the easy reads | P0 |
| Strict CSP with nonce | Blocks XSS token theft | P0 |
| Never log tokens | Removes a whole vector | P0 |
| No tokens in URLs | Removes referrer leakage | P0 |

### ⚠️ Gap in the A–Z feature list

The catalogue has **S — Session management** and **R — Refresh token rotation**.
Both are reactive: they help *after* a session is known stolen. Nothing in the
original list made a stolen cookie unusable, which is the actual fix. Tier 1
closes that gap.

---

## T2 — Fallback factor downgrade

The weakest login path sets the real security level. A passkey-first system with
an SMS escape hatch is an SMS system.

| Control | P |
| --- | --- |
| No phishable primary fallback | P0 |
| Recovery strength equals login | P0 |
| Downgrade events logged | P0 |
| Risk-gated step-down | P0 |
| Multi-passkey enrolment nudge | P1 |

⚠️ Applies to our own policy today. "Passkey **OR** both socials" means the
social path is proxy-phishable, so T1 Path A is open regardless of passkey
support.

---

## T3 — Account recovery abuse

Recovery is authentication. Most breaches walk in through it.

| Control | P |
| --- | --- |
| Same assurance level as login | P0 |
| Re-auth before credential change | P0 |
| Trusted-contact recovery | P1 |
| Delayed recovery window | P2 |
| Owner notification on every attempt | P0 |

---

## T4 — Cross-device flow phishing

QR-code and device-code flows let an attacker display a real prompt from a
context the user cannot verify.

| Control | P |
| --- | --- |
| Hybrid transport with proximity | P1 |
| No bare device code, high value | P1 |
| Show requesting app and location | P1 |
| Short code lifetime | P0 |

---

## T5 — Token leakage

Covered as T1 Path C. Controls: strict CSP, HttpOnly cookies, exact redirect URI
match, no tokens in URLs, token scrubbing in logs.

---

## T6 — Credential stuffing

| Control | P |
| --- | --- |
| Breached password check, k-anonymity | P0 |
| Per-IP and per-account throttles | P0 |
| Enumeration resistance, uniform timing | P0 |
| Bot classification | P1 |

---

## T7 — Agent delegation abuse

An AI agent holding a user token is an unbounded impersonation. Chains of agents
multiply it.

| Control | P |
| --- | --- |
| RFC 8693 subject plus actor token | P1 |
| Audience-restricted tokens | P1 |
| Delegation depth limit | P1 |
| Per-agent revocation | P2 |
| Autonomy mode flag | P2 |

---

## T8 — Risk model manipulation

| Control | P |
| --- | --- |
| Risk model advisory, never authorising | P0 |
| Fail closed on model outage | P0 |
| Prompt injection isolation | P1 |
| Adversarial drift monitoring | P2 |

---

## Sources

- [DBSC explained](https://www.corbado.com/blog/device-bound-session-credentials-dbsc)
- [Passkeys vs MFA fallbacks](https://workos.com/blog/passkeys-stop-ai-phishing-mfa-fallbacks)
- [AiTM phishing detection 2026](https://www.stingrai.io/blog/adversary-in-the-middle-aitm-phishing-detection-2026)
- [Token-based MFA bypass](https://www.obsidiansecurity.com/blog/token-based-attacks-how-attackers-bypass-mfa)
- [AiTM MFA bypass mechanics](https://hivesecurity.gitlab.io/blog/aitm-phishing-mfa-bypass-evilginx/)
- [OpenID CAEP 1.0 final](https://openid.net/specs/openid-caep-1_0-final.html)
- [NIST SP 800-63B-4 final](https://csrc.nist.gov/pubs/sp/800/63/b/4/final)
