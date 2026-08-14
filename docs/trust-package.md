# Ai-Auth — trust package and route to regulated buyers

What a bank's third-party risk team asks for, what it costs, and how a small
vendor answers the question that kills most of them: *what happens if you
disappear?*

⚠️ **Design stage.** Nothing in this file exists yet. It is a shopping list and
a sequence, written early so the cost is known before it is a surprise.

| Related | Contents |
| --- | --- |
| [compliance.md](compliance.md) | Framework mapping and certification ladder |
| [key-custody.md](key-custody.md) | The cryptography answers |
| [../SECURITY.md](../SECURITY.md) | Disclosure policy — the first thing they check |

---

## 1. The evidence bundle

Assemble this **before** the first call. Each missing item adds roughly a month
to the review, and a review that stalls twice usually does not restart.

| Artifact | Why they want it | Status |
| --- | --- | --- |
| SOC 2 Type II report + bridge letter | Independent proof controls actually ran | ❌ |
| ISO 27001 certificate + Statement of Applicability | Non-US equivalent, often both are required | ❌ |
| Annual penetration test, named firm | Third-party technical assurance | ❌ |
| Remediation letter for that test | Findings alone are not evidence; closure is | ❌ |
| Pre-filled SIG Lite / SIG Core or CAIQ | 300–1000 rows. Fill once, reuse forever | ❌ |
| Architecture and data-flow diagrams | Mostly exist in the README already | ⚠️ |
| Subprocessor list with locations | Cloudflare, cloud provider, KMS — all of it | ❌ |
| BCP/DR plan **and last test result** | The test result is the part they check | ❌ |
| Quantitative RTO, RPO, availability targets | Adjectives fail this row | ❌ |
| Vulnerability handling SLA | Now in [SECURITY.md](../SECURITY.md) | ✅ |
| Secure SDLC description | Code review, CI gates, dependency policy | ⚠️ |
| SBOM per release | CycloneDX or SPDX | ❌ |
| Cyber liability insurance certificate | $5–10M is a common floor | ❌ |
| Source code escrow agreement | Standard for a critical vendor | ❌ |
| Financial statements or funding evidence | Vendor viability screening | ❌ |
| Named security contact and org chart | They want a person, not an inbox | ❌ |

⚠️ Two of these are cheap and already half-done: the **data-flow diagrams** and
the **secure SDLC description** can be lifted almost verbatim from the README
and the CI invariants. Do them first — they make the bundle look started.

---

## 2. The questionnaire

Expect a spreadsheet of 300 to 1000 rows, per customer, and expect it again
every year. Handle it once:

| Move | Effect |
| --- | --- |
| Pre-fill SIG Core and CAIQ, keep them versioned in the repo | Turns each new questionnaire into a mapping exercise, not a rewrite |
| Keep an internal answer bank keyed by control | Same answer everywhere, no contradictions between reviews |
| Publish a trust page with the non-confidential subset | Deflects perhaps half the questions before they are asked |
| Never leave a row blank | "Not applicable, because …" scores; empty reads as evasion |

⚠️ Contradicting yourself across two questionnaires is worse than admitting a
gap. Reviewers compare, and an inconsistency turns a technical review into a
credibility review.

---

## 3. Deployment models

A bank will not run its login path on a shared multi-tenant SaaS operated by a
small vendor. Self-hosting must be a first-class product, not a favour.

| Model | Who | What we must support |
| --- | --- | --- |
| Multi-tenant SaaS | Startups, fintechs | Current design |
| Dedicated single-tenant | Mid-market, PSPs | Isolated deployment, own database, own keys |
| **Customer cloud (BYOC)** | Most banks | Their account, their VPC, their IAM, their observability |
| **On-premises** | Tier-1, high-sensitivity | No egress, HSM in the rack |
| **Air-gapped** | Rare, high value | Offline licence, offline updates, no phone-home |

| Property | Requirement |
| --- | --- |
| Telemetry | Off by default, documented, with an off switch that is real |
| Observability | Export to their Prometheus/OTel/SIEM, not only our dashboard |
| Admin identity | Federate the console into *their* IdP — we are not exempt from our own thesis |
| Updates | Signed artifacts, verifiable offline, customer-controlled timing |
| Ingress | Their load balancer or ours — see [hardening-backlog.md](hardening-backlog.md) §10 |

⚠️ The multi-tenant design still matters: a bank is one tenant with many
business units, and row-level tenant isolation is what makes that safe. The
commercial unit changes, not the architecture.

---

## 4. Vendor viability — the gate nobody plans for

A bank cannot put its login path on a vendor that might not exist in three
years. This screening kills more security startups than any technical finding,
and no amount of good cryptography answers it.

| Answer | How it works | Strength |
| --- | --- | --- |
| **Open source** | The customer can fork and self-maintain if we vanish | Strongest — removes the objection rather than mitigating it |
| Source code escrow | Released to the customer on defined trigger events | Standard, accepted, weaker |
| Partner or OEM | Ship inside a systems integrator who carries the compliance weight | Fast, costs margin and the direct relationship |
| Reference customers | Three named, contactable, in their sector | Required regardless of the above |

⚠️ **Open source is the natural fit here.** The repository is already written to
be read — the threat model argues its own weak points, and the security model
explains its reasoning instead of asserting conclusions. That posture is worth
more as a public artifact than as a private one, and it converts the viability
question from a weakness into a selling point. Pair it with a support contract
and the commercial model still works.

---

## 5. Realistic sequence

Each rung supplies the references the next demands. Skipping is not faster.

| Stage | Target buyer | Needs | Rough elapsed |
| --- | --- | --- | --- |
| 0 | Nobody — build it | Working code, tests, the P0 backlog | — |
| 1 | Startups, internal tools | OIDC conformance, public repo | +2 months |
| 2 | Fintechs, SaaS with compliance needs | Pen test, SOC 2 Type I underway | +6 months |
| 3 | PSPs, neobanks, credit unions | **FAPI 2.0 certified**, SOC 2 Type II | +12–18 months |
| 4 | EU regulated entities | ISO 27001, DORA contract package, exit plan | +18–24 months |
| 5 | Tier-1 banks | All of the above, HSM custody, 3 references, viability answer | +24–36 months |

⚠️ Sales cycles lengthen with each rung: weeks at stage 1, six to eighteen
months at stage 5. Budget for the cycle, not only for the certification.

⚠️ Do not attempt stage 5 first. A tier-1 bank that says no remembers, and the
second attempt is harder than the first.

---

## 6. Running cost, once this is real

Approximate annual figures for a small vendor holding stage 3–4. They are
estimates for planning, not quotes.

| Item | Per year |
| --- | --- |
| SOC 2 Type II audit | $25–60k |
| ISO 27001 certification and surveillance | $20–50k |
| Penetration test | $15–40k |
| Compliance automation tooling | $10–25k |
| Cyber liability insurance | $10–30k |
| Certification fees and conformance testing | $5–10k |
| **Total** | **roughly $85–215k/yr, before salaries** |

⚠️ This is the honest reason "add everything above" is only half achievable in a
repository. The documents are free; the attestations are not, and they recur
every year whether or not a deal closes. Decide the target rung deliberately,
because the cost is set by the rung, not by the number of customers on it.

---

## 7. Language discipline

What gets written on a website is read by an auditor later.

| Do not write | Write instead |
| --- | --- |
| "Bank-grade security" | "FAPI 2.0 Security Profile, certified <date>" |
| "PCI DSS compliant" | "Supports PCI DSS 4.0 requirements 8.4.2 and 8.5.1 for access into your CDE" |
| "Fully GDPR compliant" | "Per-subject cryptographic erasure, EU data residency, DPA available" |
| "Military-grade encryption" | "AES-256-GCM via a FIPS 140-3 validated module, certificate #…" |
| "Unhackable", "zero risk" | The threat model, linked |
| "AI-powered security decisions" | "The risk model is advisory and cannot authorise" |

⚠️ The last row is the one that matters most in this product. To a bank risk
committee, "AI decides who gets in" is a blocker; "the AI cannot decide, and the
build fails if anyone tries to let it" is a control. Same system, opposite
outcome, decided entirely by which sentence is on the page.
