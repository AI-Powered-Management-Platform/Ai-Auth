# crypto — the vault (Rust)

Passkey verification, envelope encryption, blind indexing. Holds every key,
sits furthest from the internet, and only ever sees input the gateway has
already validated.

| Fact | Value |
| --- | --- |
| Plane | Data — on the login path |
| Language | Rust — deterministic key erasure; no garbage collector copies a secret and leaves the original behind |
| Holds keys | ✅ All of them |
| Holds state | ❌ None — no database credentials exist for this service |
| Public | ❌ Never |
| Networks | `net-a` only — no route to `ai` exists |
| Container | scratch · non-root · read-only rootfs · all capabilities dropped · egress to KMS only |
| Status | 📋 Planned — documentation only, no code yet |

## Job

| Responsibility | Detail |
| --- | --- |
| WebAuthn verification | Full assertion and attestation checks — origin, RP ID, sign count. COSE keys, ES256 default |
| Envelope encryption | Wrap and unwrap per-row DEKs under the KEK — see [key custody](../docs/key-custody.md) |
| Blind indexing | Salted HMAC indexes so equality search needs no plaintext |
| Provider abstraction | Every primitive behind the `CryptoProvider` trait — RustCrypto for dev, `aws-lc-rs` FIPS or PKCS#11 HSM for `regulated` |

## Non-negotiable build rules

| Rule | Why |
| --- | --- |
| `#![forbid(unsafe_code)]` | The whole point of the language choice |
| `zeroize` on drop, `mlock` on key pages | Secrets do not outlive their use |
| `overflow-checks = true` in release | Integer overflow wraps silently otherwise |
| `cargo-deny` + pinned lockfile | `build.rs` runs arbitrary code at compile time |
| Constant-time comparisons (`subtle`) | Cache and timing side channels |

## Never

| Rule | Why |
| --- | --- |
| Never parses raw internet input | Every HTTP parsing bug would be a bug in the process holding the KEK |
| Never logs key material or plaintext | An entire leak class, removed |
| Never falls back when KMS is unreachable | No unwrap → encrypted reads fail. Fail closed |
| Never reaches `ai` | No network path exists, by design |
