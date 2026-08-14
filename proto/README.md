# proto — the wire contract

Source of truth for every message crossing a service boundary. A contract
change and its implementations land in one commit that CI verifies together.

| Fact | Value |
| --- | --- |
| Status | 📋 Planned — **no `.proto` files yet, by explicit decision: plan before code** |
| First file to land | `risk.proto` — the `RiskAssessment` message |
| Transport | gRPC over mutual TLS, no plaintext mode anywhere including dev |

## The schema guard — the first code this repository will ever get

`RiskAssessment` is the Thinker's entire authority: score, band, reasons,
model version. When building starts, CI will fail any commit that adds an
`allow`, `deny`, `decision`, or similar field to it. The rule "the risk model
must never authorise" becomes a build failure nobody can bypass in a hurry —
see [threat model](../docs/threat-model.md) T8.

## Checks that run on this directory

| Check | Prevents |
| --- | --- |
| `buf breaking` | Silent wire-format breaks between services |
| `buf lint` | Style drift in the contract |
| Schema guard script | Any authorising field on `RiskAssessment` |
