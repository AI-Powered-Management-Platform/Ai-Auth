# console — admin and self-service UI (Next.js)

The face of the control plane: operators manage tenants and policy, users
manage their own credentials and sessions.

| Fact | Value |
| --- | --- |
| Plane | Control — never on the login path |
| Language | TypeScript / Next.js |
| Holds keys | ❌ Never |
| Public | Via the gateway, like everything else |
| Status | 📋 Planned — documentation only, no code yet |

## Job

| Responsibility | Detail |
| --- | --- |
| Effective assurance display | Shows the level computed from the **running** configuration — the weakest permitted path, not the strongest available one |
| Credential self-service | Enrol passkeys, list sessions, revoke one or all — no support tickets |
| Policy administration | Profile selection with the risk of every step-down stated plainly |
| Audit views | The plain-words incident summaries from the audit summarizer |

## Never

| Rule | Why |
| --- | --- |
| Never talks to data-plane services directly | The `api` service is its only backend |
| Never displays a house term where a standard exists | Assurance shows the NIST AAL number — [compliance](../docs/compliance.md) §3 |
| Never exempts its own admins from the thesis | Console admin login federates into the customer's IdP and requires a passkey under the `strict` default |
