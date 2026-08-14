# proto — the wire contract

Source of truth for every message crossing a service boundary. A contract
change and its implementations land in one commit that CI verifies together.

| Fact | Value |
| --- | --- |
| Status | ✅ First contract landed — `risk.proto`, guarded by CI |
| Files | [`risk.proto`](risk.proto) — the `RiskAssessment` message |
| Transport | gRPC over mutual TLS, no plaintext mode anywhere including dev |

## The schema guard — the first code this repository ever got

`RiskAssessment` is the Thinker's entire authority: score, band, reasons,
model version. CI fails any commit that adds an `allow`, `deny`, `decision`,
or similar field — [`scripts/check_risk_schema.py`](../scripts/check_risk_schema.py),
run by [`.github/workflows/ci.yml`](../.github/workflows/ci.yml). The guard
also fails if `risk.proto` itself disappears, so deleting the contract cannot
silence the check (T14). The rule "the risk model must never authorise" is a
build failure nobody can bypass in a hurry — see
[threat model](../docs/threat-model.md) T8.

## Checks that run on this directory

| Check | Prevents |
| --- | --- |
| `buf breaking` | Silent wire-format breaks between services |
| `buf lint` | Style drift in the contract |
| Schema guard script | Any authorising field on `RiskAssessment` |
