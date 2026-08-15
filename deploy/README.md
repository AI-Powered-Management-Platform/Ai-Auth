# deploy — composition and networks

One container per service, one hardening level per trust tier, three networks
so the vault and the thinker can never exchange a packet.

| Fact | Value |
| --- | --- |
| Status | 🚧 Working — `compose.yaml` boots gateway + crypto + postgres + redis with mTLS proven end to end |
| Unit | One container per service — per language, per skill, per blast radius |

## Networks

| Network | Members | Why |
| --- | --- | --- |
| `edge` | ingress adapter + `gateway` | The single public door |
| `net-a` | `gateway` + `crypto` | Verification and key operations |
| `net-b` | `gateway` + `ai` | Risk telemetry and scores |
| `net-data` | `gateway` + `postgres` + `redis` | The stores. `crypto` has **no route here** — the vault talks to no database ([data-layer.md](../docs/data-layer.md)) |

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

### Run it

```sh
./scripts/dev-certs.sh                      # mint the dev PKI (gitignored)
docker compose -f deploy/compose.yaml up --build -d
curl http://127.0.0.1:8080/readyz           # {"guard":"ok","status":"ready"}
```

`/readyz` returning `guard: ok` proves the whole chain: mutual TLS handshake,
the Guard's T9 gate rejecting an empty probe, and the rejection arriving as a
proper gRPC status. A 503 means the Guard cannot answer — which is the
fail-closed matrix working, not a bug.

The three internal networks are `internal: true` — compose-level proof that
`crypto` and `ai` have no route to the internet or to each other.

Per-service hardening matrix: [README — Deployment](../README.md#deployment).
Profiles (`strict` default, `regulated`) map to compose overlays, one file per
profile — named profiles, not switch soup.
