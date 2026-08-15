# crypto — the vault (Rust)

Passkey verification, envelope encryption, blind indexing. Holds every key,
sits furthest from the internet, and only ever sees input the gateway has
already validated.

| Fact | Value |
| --- | --- |
| Plane | Data — on the login path |
| Language | Rust — deterministic key erasure; no garbage collector copies a secret and leaves the original behind |
| Holds keys | ✅ In memory, during use only — nothing at rest. The KEK lives in KMS/HSM; DEKs rest in Postgres **wrapped**; a restart starts clean |
| Holds state | ❌ None — no database credentials exist for this service |
| Public | ❌ Never |
| Networks | `net-a` only — no route to `ai` exists |
| Container | scratch · non-root · read-only rootfs · all capabilities dropped · egress to KMS only |
| Status | 🚧 v1 building — tonic mTLS server, T9 gate enforced and audited, per-tenant and global rate ceilings, `CryptoProvider` trait in place; tenant-bound blind indexing and envelope encryption live (AES-256-GCM, tenant as AAD); and passkey verification (ES256, full check set) all live |

## Where key material actually lives

The vault is a worker, not a warehouse — it stores no key anywhere.

| Key | At rest | In use |
| --- | --- | --- |
| KEK | KMS / HSM — outside the system, hardware-held | Never leaves the HSM under HYOK; otherwise cached in `mlock`ed RAM |
| Per-row DEKs | Postgres, wrapped by the KEK — ciphertext the gateway ferries but cannot open | Unwrapped in RAM for milliseconds, zeroized on drop |
| Passkey public keys | Postgres, plain — public by definition | Verified on request |

Stealing this container's disk yields nothing: `scratch` base, read-only,
stateless. Stealing Postgres yields wrapped keys — noise without the KEK.
The two halves only meet in this process's memory, for the life of one
request. Full hierarchy: [key custody](../docs/key-custody.md) §4.

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
| Never decrypts or signs without an authorised, purpose-bound request | A stateless vault that obeys its caller blindly is a decryption and signing oracle — T9. Each request names the subject and purpose; cross-tenant DEK/ciphertext pairings are rejected; unwrap and sign rates are capped and individually audited |
| Never reaches `ai` | No network path exists, by design |
