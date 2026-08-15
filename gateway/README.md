# gateway — the public door (Go)

The only service the internet can reach, and the only one an integrator ever
talks to. Terminates ingress, owns every session, issues every token — and can
read none of the data it stores.

| Fact | Value |
| --- | --- |
| Plane | Data — on the login path |
| Language | Go — deadline propagation via `context`, cheap concurrency, mature OIDC and TLS libraries |
| Holds keys | ❌ Never |
| Holds state | ✅ Sessions, tokens, tenants — ciphertext it cannot read |
| Public | ✅ The only one |
| Networks | `edge`, `net-a` → crypto, `net-b` → ai |
| Container | distroless · non-root · read-only rootfs · all capabilities dropped · egress to tunnel only |
| Status | 🚧 v1 building — health endpoints, timeouts, graceful shutdown; no auth surface yet |

## Job

| Responsibility | Detail |
| --- | --- |
| OIDC / OAuth 2.1 provider | `/authorize`, `/token`, discovery, JWKS — PKCE `S256` mandatory, exact redirect match |
| Tenant boundary | Resolve tenant and rate-limit before anything costs money |
| Token lifecycle | Short access TTL, one-time refresh rotation, family revoke, DPoP binding |
| Verified app links | Serves `/.well-known/apple-app-site-association` and `/.well-known/assetlinks.json` |
| Decision assembly | Combines the Guard's cryptographic verdict, the Thinker's band, and tenant policy — the gateway decides, nothing else does |

Request order and budgets: see the [security model](../README.md#security-model).
This is also the integration surface for every website and mobile app — see
[../sdk/](../sdk/) and [../docs/mobile-integration.md](../docs/mobile-integration.md).

## Never

| Rule | Why |
| --- | --- |
| Never holds a key | A breach of the public process yields ciphertext plus an RPC surface, nothing more |
| Never treats the risk score as a decision | The Thinker advises; the gateway decides from verdict and policy |
| Never calls anything except `crypto` and `ai` | A valid certificate is not authorisation |
| Never scores an attempt that failed verification | Authenticate before you compute — [threat model](../docs/threat-model.md) T8 |
| Never degrades open | Guard down → reject; Thinker down → band `HIGH` |
