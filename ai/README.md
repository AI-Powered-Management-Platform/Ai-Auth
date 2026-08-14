# ai — the thinker (Python)

Advisory risk scoring inside a 50 ms budget. The most likely service to be
compromised — largest dependency tree — so it is given the least power. That
asymmetry is the design.

| Fact | Value |
| --- | --- |
| Plane | Data — on the login path, advisory only |
| Language | Python — the ML ecosystem, and nothing else |
| Holds keys | ❌ Never |
| Holds state | ⚠️ Behavioural baselines only |
| Public | ❌ Never |
| Networks | `net-b` only — no route to `crypto` exists |
| Container | distroless-python · non-root · read-only rootfs · all capabilities dropped · **no egress at all** |
| Status | 📋 Planned — documentation only, no code yet |

## Job

| Responsibility | Detail |
| --- | --- |
| Risk scoring | Impossible travel, velocity, device drift, reputation — per attempt |
| Anomaly tracking | Per-user login baselines |
| Bot classification | Humans vs scripts |
| Mobile telemetry | Play Integrity / App Attest verdicts as inputs — see [mobile integration](../docs/mobile-integration.md) §5 |

Models run via ONNX — no GIL on the hot path, and the image drops from ~2 GB
to ~200 MB, which removes most of the packages that would need auditing.

## The one rule that defines this service

The output is `RiskAssessment`: a score, a band, reasons, a model version.
**A CI schema guard fails the build if anyone adds an `allow`, `deny`, or
`decision` field.** The Thinker cannot authorise — not by policy, by build.
See [threat model](../docs/threat-model.md) T8.

## Never

| Rule | Why |
| --- | --- |
| Never sees an attempt that failed verification | Forged signatures must not exhaust the most expensive service |
| Never blocks a login by being down | Gateway degrades to band `HIGH` — stricter, not open |
| Never reaches `crypto` | A compromised ML dependency cannot send one packet toward the keys |
| Never treats user strings as instructions | Prompt-injection isolation — inputs are data |
