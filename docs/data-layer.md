# Ai-Auth — data layer

One Postgres cluster, one Redis, nothing else. No service brings its own
engine, and an operator never runs extra database infrastructure.

| Store | Role | If it is lost |
| --- | --- | --- |
| Postgres | System of record — the truth | Restore from backup; nothing else substitutes |
| Redis | Speed only — cache, rate-limit counters, revocation pre-check | Nothing. The system slows down and gets stricter, never looser |

| Status | 📋 Planned — documentation only, no schema yet |
| --- | --- |

---

## One cluster, not one database per service

The microservices textbook says database-per-service. Rejected here: it
multiplies backups, migrations, and failure modes without adding a security
boundary this design doesn't already have. The boundary that matters is
**schema-per-service with least-privilege roles** — the data-layer twin of the
three-network rule.

| Service | DB role grants | Can touch |
| --- | --- | --- |
| `gateway` | own role | sessions, tokens; tenants read-only |
| `crypto` | ❌ **no credentials at all** | stateless — the vault never talks to the database |
| `ai` | own role | behavioural-baseline schema only |
| `api` | own role | tenants and policy (write), audit (append-only) |
| `worker` | own role | audit read for export, job queue |
| `console` | ❌ none | reaches data only through `api` |

A compromised `ai` container cannot query a session row — its credentials do
not grant the schema. Grants are migrations, reviewed like code.

⚠️ Audit tables are append-only at the database level (no `UPDATE`/`DELETE`
grant to anyone), matching [hardening-backlog.md](hardening-backlog.md) §11.

---

## What lives where

| Data | Store | Protection |
| --- | --- | --- |
| Users, credentials, tenants, policy | Postgres | Per-row DEK envelope encryption, blind indexes — [key-custody.md](key-custody.md) |
| Sessions, refresh-token families | Postgres | Revocation authority lives here |
| Audit log | Postgres | Append-only, hash-chained, exported by `worker` |
| Job queue | Postgres (`river`) | Transactional with the data it works on — **no separate broker exists** |
| Rate-limit counters, hot cache | Redis | Ephemeral by design |
| Revocation fast pre-check | Redis | Advisory only — every refresh still checks Postgres |

⚠️ The Redis rule: nothing in Redis may be the only copy of anything, and no
security decision may depend on Redis being up. Redis down → conservative rate
limits and slower checks — degradation toward strictness, as everywhere.

---

## Tenancy and deployment models

| Model | Data layout |
| --- | --- |
| Multi-tenant SaaS | One cluster, row-level security per organization — no shared session namespace |
| Dedicated / BYOC | The customer's managed Postgres (RDS, Cloud SQL, Azure) + Redis — same schema, their endpoint |
| Global residency | CockroachDB speaks the Postgres wire protocol: home-region row pinning per [compliance.md](compliance.md) §9.3 without changing the product |

Encryption keys never live in any of these stores — the KEK sits in
KMS/HSM and per-row DEKs are stored only wrapped. A database backup is
ciphertext; destroying a user's key sanitises every backup at once.

---

## Engine policy

**Postgres only.** Supporting a second engine multiplies the row-level
security implementation, the migration matrix, the test surface, and the
compliance evidence — for deployers who can already get managed Postgres in
every cloud and every region on the planet.

| Not supported | Because |
| --- | --- |
| MySQL, MariaDB, SQL Server, Mongo | One engine deeply hardened beats three shallowly |
| Pluggable ORM abstraction | The schema uses Postgres-specific RLS and types on purpose |
| Redis alternatives (Valkey works) | Anything wire-compatible is fine; nothing beyond the ephemeral role is |
