# Security policy

How to report a vulnerability in Ai-Auth, and what happens after you do.

⚠️ **Status: design stage.** No code has shipped, so there is nothing running to
attack yet. This policy exists now so that it is in place before the first line
of code, not bolted on after the first report arrives in a public issue.

| Looking for | Go to |
| --- | --- |
| The hardening backlog | [docs/hardening-backlog.md](docs/hardening-backlog.md) |
| Attack mechanics, T1–T8 | [docs/threat-model.md](docs/threat-model.md) |
| Framework and certification mapping | [docs/compliance.md](docs/compliance.md) |

---

## Reporting

**Do not open a public issue for a security bug.** Use one of these:

| Channel | Use for | How |
| --- | --- | --- |
| GitHub private vulnerability reporting | Everything, preferred | Security tab → *Report a vulnerability* — **enabled 2026-08-14** |
| Email fallback | Only if you cannot use GitHub | `hsopheak85@gmail.com` — interim personal address until a project domain exists |

⚠️ Interim setup, honestly stated: the email fallback is a personal address
and no PGP key is published yet. For anything sensitive, use the GitHub
channel — it is private end-to-end. A dedicated `security@` mailbox and a
published key replace this row before the first release.

### What to include

The more of this you send, the faster it moves.

| Field | Why |
| --- | --- |
| Affected component | `gateway`, `crypto`, `ai`, `api`, `worker`, `console` |
| Version or commit | Exactly what you tested |
| Reproduction steps | Ideally a script or request sequence |
| Impact | What an attacker gains, concretely |
| Suggested fix | Optional, always welcome |

Report in any language you are comfortable writing. If English is not your first
language, send it in yours — a translated report is better than a delayed one.

---

## What we commit to

| Stage | Target |
| --- | --- |
| Acknowledge receipt | 3 business days |
| Initial severity assessment | 10 business days |
| Fix or documented mitigation — critical | 30 days |
| Fix or documented mitigation — high | 60 days |
| Fix or documented mitigation — medium and low | 90 days |
| Public advisory after a fix ships | 7 days |

We will keep you updated at least every 14 days while a report is open, tell you
when a fix lands, and credit you in the advisory unless you ask us not to.

Severity follows CVSS v4.0, adjusted for exploitability in a default
`strict` deployment. A finding that only applies when an operator has opted
down to `balanced` or `legacy` is still valid — say which profile it needs.

---

## Coordinated disclosure

We ask for **90 days** before public disclosure, or until a fix ships —
whichever comes first. If a fix will take longer than 90 days we will say so and
explain why rather than go quiet.

If a vulnerability is being actively exploited, tell us immediately and we will
compress the timeline. Publishing before a fix is available is your right, but
it puts deployments at risk; talk to us first.

---

## Safe harbour

We will not pursue legal action, and will not ask a third party to, against
anyone who acts in good faith under this policy. Good faith means:

| Do | Do not |
| --- | --- |
| Test only against your own deployment or accounts | Touch other people's data |
| Stop at proof of concept | Pivot, persist, or exfiltrate |
| Report promptly and privately | Publish before the timeline agreed |
| Respect rate limits | Run denial-of-service or load tests |
| Use test accounts and test tenants | Social-engineer staff or users |

If you are unsure whether an action is in scope, ask first. We would rather
answer a question than argue about a boundary afterwards.

---

## Scope

### In scope

| Area |
| --- |
| Authentication and session handling in `gateway` |
| Cryptographic verification, key handling, and encryption in `crypto` |
| Tenant isolation and authorisation boundaries anywhere |
| Any path by which the `ai` service influences an authorisation outcome |
| OIDC and OAuth 2.1 protocol conformance flaws |
| Token issuance, binding, rotation, and revocation |
| Admin console and control-plane APIs |
| Build, release, and supply-chain integrity |

### Out of scope

| Area | Why |
| --- | --- |
| Findings from automated scanners with no demonstrated impact | Noise |
| Missing headers with no exploit path | Report as a normal issue |
| Denial of service by volume | Test against your own deployment only |
| Social engineering of staff or users | Not a software defect |
| Vulnerabilities in third-party dependencies | Report upstream; tell us so we can pin or patch |
| Anything requiring a rooted device plus physical access plus the unlock code | Outside the threat model — see [docs/threat-model.md](docs/threat-model.md) |

⚠️ Session theft after a successful login (T1) **is in scope** and is the
highest-value finding in this system. Passkeys do not close it.

---

## Rewards

There is no bug bounty at the design stage — it would be dishonest to advertise
one with no funding behind it. Every valid report gets credit in the advisory
and in the release notes. A bounty programme will be announced here if and when
it is funded.

---

## Supported versions

| Version | Supported |
| --- | --- |
| — | Nothing has been released yet |

Once releases begin, the current minor version and the one before it receive
security fixes.
