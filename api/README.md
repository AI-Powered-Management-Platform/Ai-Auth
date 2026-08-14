# api — control plane (Python / FastAPI)

Tenants, policy, and administration. Deliberately **off the login path**: this
service can be down and every login still works.

| Fact | Value |
| --- | --- |
| Plane | Control — never on the login path |
| Language | Python / FastAPI |
| Holds keys | ❌ Never |
| Public | ❌ Admin traffic enters through the gateway |
| Container | distroless-python · non-root · read-only rootfs · all capabilities dropped |
| Status | 📋 Planned — documentation only, no code yet |

## Job

| Responsibility | Detail |
| --- | --- |
| Tenant lifecycle | Create, configure, suspend, delete — row-level isolation per tenant |
| Policy management | Profiles (`strict` default), factors, session lifetimes, providers |
| Configuration coherence | Refuses incoherent combinations at write time — e.g. passkey-only login beside email-link recovery |
| Admin RBAC | Every admin action attributed and written to the append-only audit log |

## Never

| Rule | Why |
| --- | --- |
| Never issues or validates tokens | That is the gateway's job alone |
| Never weakens a safety rail | Exact redirect match, PKCE, `alg` allowlist are not settings — [profiles](../README.md#configuration-profiles) |
| Never writes policy without an audit record | Downgrades are explicit, logged events |
