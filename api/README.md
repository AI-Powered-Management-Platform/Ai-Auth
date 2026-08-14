# api — control plane (Go)

Tenants, policy, and administration. Deliberately **off the login path**: this
service can be down and every login still works.

| Fact | Value |
| --- | --- |
| Plane | Control — never on the login path |
| Language | Go — decided 2026-08-14. This service writes tenant policy, which is real authority; it does not live in the most-compromisable language, and it reuses the gateway's mTLS, gRPC, tenant, and audit libraries |
| Holds keys | ❌ Never |
| Public | ❌ Admin traffic enters through the gateway |
| Container | distroless · non-root · read-only rootfs · all capabilities dropped |
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
| Never queries user data through an ORM | Tenant scoping must be visible in review. `sqlc` + `pgx` keep every `WHERE tenant_id` on screen; an ORM hides the query and a missing scope becomes an invisible cross-tenant leak (T10) |
