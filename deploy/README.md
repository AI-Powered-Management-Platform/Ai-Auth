# deploy — composition and networks

One container per service, one hardening level per trust tier, three networks
so the vault and the thinker can never exchange a packet.

| Fact | Value |
| --- | --- |
| Status | 📋 Planned — documentation only, no compose files yet |
| Unit | One container per service — per language, per skill, per blast radius |

## Networks

| Network | Members | Why |
| --- | --- | --- |
| `edge` | ingress adapter + `gateway` | The single public door |
| `net-a` | `gateway` + `crypto` | Verification and key operations |
| `net-b` | `gateway` + `ai` | Risk telemetry and scores |

`crypto` and `ai` share no network. A compromised ML dependency has no route
toward the keys — not a firewall rule, an absence of path.

## Rules the compose files must encode

| Rule | Mechanism |
| --- | --- |
| Internal services are never published | `expose`, never `ports` |
| Certificates never enter an image | Mounted at runtime; 24 h leaves from the internal CA |
| mTLS in development too | A dev path without mTLS eventually ships |
| Read-only everything | `read_only: true`, `tmpfs` for scratch, no swap for the vault |
| No shell, no root, no capabilities | distroless / scratch bases, `cap_drop: [ALL]` |
| Ingress is pluggable | Tunnel, customer LB, or private link — [backlog §10](../docs/hardening-backlog.md) |

Per-service hardening matrix: [README — Deployment](../README.md#deployment).
Profiles (`strict` default, `regulated`) map to compose overlays, one file per
profile — named profiles, not switch soup.
