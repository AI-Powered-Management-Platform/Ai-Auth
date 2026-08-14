# worker — background jobs (Python)

Webhooks, audit export, and batch work. No inbound traffic at all — it
consumes queues and emits outward.

| Fact | Value |
| --- | --- |
| Plane | Control — never on the login path |
| Language | Python |
| Holds keys | ❌ Webhook signing secrets only, per tenant |
| Public | ❌ No inbound; egress to registered webhook endpoints |
| Container | distroless-python · non-root · read-only rootfs · all capabilities dropped |
| Status | 📋 Planned — documentation only, no code yet |

## Job

| Responsibility | Detail |
| --- | --- |
| Webhook delivery | `login`, `logout`, `lockout`, `mfa_enrolled`, `grant`, `revoke` — HMAC-signed, retried with backoff |
| Audit export | Append-only log → SIEM streams and WORM archives — [backlog §11](../docs/hardening-backlog.md) |
| Batch jobs | KEK-rotation re-wraps, retention deletes, cryptographic shreds — [key custody](../docs/key-custody.md) §6–7 |
| Security signals | CAEP / Shared Signals transmission when it ships |

## Never

| Rule | Why |
| --- | --- |
| Never delivers an unsigned event | Receivers must be able to verify origin |
| Never exports plaintext personal data | Exports carry ciphertext or tokenised references |
| Never deletes rows directly for erasure | Erasure is key destruction, not row editing |
