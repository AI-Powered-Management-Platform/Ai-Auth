# Ai-Auth — key custody, HSM, and validated cryptography

Who holds the keys, where the primitives come from, and how a customer keeps
control of both. This is the file a bank's cryptography reviewer reads first.

⚠️ **Design stage.** Nothing here is implemented. It is written now because two
of these decisions — the provider abstraction and the custody interface — cannot
be retrofitted. Choosing wrong at the first commit forecloses the regulated
market permanently.

| Related | Contents |
| --- | --- |
| [compliance.md](compliance.md) | Which framework demands which of these |
| [hardening-backlog.md](hardening-backlog.md) §9 | Build order |
| [../README.md](../README.md) | Where `crypto` sits in the architecture |

---

## 1. Custody models

"We use a KMS" is not an answer to a bank. The question is *whose* KMS, and
whether the vendor can decrypt customer data without the customer's knowledge.

| Model | Where the KEK lives | Vendor can decrypt alone | Who accepts it |
| --- | --- | --- | --- |
| Vendor-managed | Our KMS, our account | ✅ Yes | Startups, internal use |
| **BYOK** | Our KMS, customer-generated and importable | ✅ Yes, until revoked | Minimum for a regulated buyer |
| **HYOK / external key store** | Customer's HSM; every unwrap is a call out to them | ❌ No | Most banks |
| **On-prem HSM (PKCS#11)** | Customer's HSM, in the customer's deployment | ❌ No | Tier-1 banks |

⚠️ The difference that matters to a reviewer is the **"vendor can decrypt
alone"** column. Under HYOK and on-prem HSM the customer holds a kill switch:
revoke the key and every ciphertext we hold becomes noise, with no cooperation
required from us. That single property answers most of a vendor-risk
questionnaire on its own.

| P | Deliverable |
| --- | --- |
| P0 | PKCS#11 custody interface in the `crypto` service |
| P1 | BYOK import path with customer-held revocation |
| P1 | HYOK / external key store adapter |
| P1 | Documented latency and availability impact of remote unwrap |

⚠️ HYOK moves an unwrap onto the network. The ~15 ms Rust budget in the README
request-order table is a **local** figure and does not survive a remote HSM
call. Cache wrapped DEKs, never plaintext ones, and publish the real number for
each custody model rather than quoting the local one.

---

## 2. FIPS 140-3 — the constraint that shapes the Rust core

US financial buyers, and anyone federal-adjacent, require validated
cryptographic modules. Most of the Rust ecosystem cannot supply one.

| Library | FIPS 140-3 | Notes |
| --- | --- | --- |
| `ring` | ❌ | Not validated, and not pursuing validation |
| RustCrypto (`aes-gcm`, `sha2`, …) | ❌ | Pure-Rust, unvalidated |
| `ed25519-dalek`, `curve25519-dalek` | ❌ | Unvalidated |
| **`aws-lc-rs`** in FIPS mode | ✅ | Backed by AWS-LC-FIPS; the practical Rust path |
| **`rustls`** + `aws-lc-rs` FIPS provider | ✅ | Supported provider configuration |
| OpenSSL 3.x FIPS provider via bindings | ✅ | Heavier dependency, wider algorithm set |
| **PKCS#11 offload to an HSM** | ✅ | Validation is inherited from the device |

The other services matter too — the gateway terminates TLS, and the Go control
plane signs webhooks and moves secrets:

| Service | Path to validated crypto |
| --- | --- |
| `gateway` (Go) | Go's native FIPS 140-3 mode, or a BoringCrypto build |
| `api` (Go) | Same Go path; delegates row encryption to `crypto` rather than holding keys |
| `worker` (Go) | Same Go path — webhook HMAC signing uses the validated module |
| `crypto` (Rust) | `aws-lc-rs` FIPS provider, or PKCS#11 offload |
| `ai` (Python) | Not in the crypto path by design — keep it that way |

⚠️ FIPS mode **removes** algorithms as well as validating them. Ed25519 arrived
only in FIPS 186-5 and is absent from some validated modules, so the Ed25519
assumption in the README may not survive a FIPS build. ES256 (P-256) is the safe
default for passkey verification, and it is what authenticators overwhelmingly
emit in practice.

⚠️ Validation is granted to a **specific version of a specific module in a
specific configuration**. Upgrading a validated dependency can silently leave
the boundary. Pin the validated version, record the certificate number, and
treat an upgrade as a compliance change, not a routine bump.

---

## 3. The provider abstraction

This is the single most important structural decision in the `crypto` service.
Every primitive goes behind a trait so the backend is a deployment choice.

```text
        ┌──────────────────────────────────────────┐
        │      crypto service — call sites         │
        │   passkey verify · envelope · blind idx  │
        └────────────────────┬─────────────────────┘
                             │  CryptoProvider trait
        ┌────────────────────┼─────────────────────┐
        ▼                    ▼                     ▼
  aws-lc-rs (FIPS)      RustCrypto           PKCS#11 / HSM
  regulated profile     dev + default        customer custody
```

Sketch of the boundary — illustrative, not a committed API:

```rust
pub trait CryptoProvider: Send + Sync {
    fn verify_webauthn(&self, alg: CoseAlg, key: &[u8], msg: &[u8], sig: &[u8])
        -> Result<(), VerifyError>;
    fn unwrap_dek(&self, kek: KeyHandle, wrapped: &[u8]) -> Result<Zeroizing<Dek>, KeyError>;
    fn wrap_dek(&self, kek: KeyHandle, dek: &Dek) -> Result<Vec<u8>, KeyError>;
    fn hmac_blind_index(&self, key: KeyHandle, input: &[u8]) -> Result<[u8; 32], KeyError>;
    fn attestation(&self) -> ProviderAttestation;  // module name, version, FIPS cert
}
```

Three rules that make the abstraction worth having:

| Rule | Why |
| --- | --- |
| `KeyHandle` is a handle, never key material | With an HSM the bytes never enter our address space |
| Every provider reports its own attestation | The console can display the real module and certificate number |
| The default provider is chosen by profile, not by build flag | `regulated` selects FIPS; nobody can ship a debug build into it |

⚠️ Without this trait, adding FIPS later means touching every call site in the
most security-sensitive service in the system — the change nobody wants to
review under deadline.

---

## 4. Key hierarchy

Four separate hierarchies. A compromise in one must not reach another.

| Hierarchy | Root | Purpose | Rotation |
| --- | --- | --- | --- |
| Data encryption | HSM or KMS root → KEK → per-row DEK | Envelope encryption of user data | KEK yearly; DEK per row, never |
| Token signing | HSM-held signing key → published JWKS | JWT and PASETO issuance | Quarterly, overlapping validity |
| Internal PKI | Offline root CA → intermediate → service certs | mTLS between the three services | Leaf 24 h, intermediate yearly |
| Blind index | Separate HMAC key, distinct from any DEK | Searchable encryption | With the KEK, requires reindex |

⚠️ The blind-index key must **not** be derived from a data key. If they share a
root, destroying a user's DEK for a shred leaves the index entry still valid and
still linkable — the shred becomes incomplete in exactly the way an auditor
tests for.

⚠️ Blind indexing leaks equality by construction: identical plaintext produces
identical index. That is the trade for searchability, and it must be stated in
the data protection impact assessment rather than discovered in one.

---

## 5. Dual control and the key ceremony

No single person — including us — may unwrap a customer KEK.

| Control | Requirement |
| --- | --- |
| Split knowledge | No individual holds a complete key or complete activation data |
| m-of-n quorum | Minimum 2-of-3 for KEK operations; 3-of-5 for root |
| Separation of duties | The person who authorises is not the person who executes |
| Witnessed | Two witnesses, neither a custodian |
| Recorded | Signed minutes, timestamped, retained for the key's life plus retention |
| Tamper-evident | Serialised bags or smart cards, serials logged |
| Offline | Root operations air-gapped, no network on the ceremony host |

| P | Deliverable |
| --- | --- |
| P1 | Written ceremony script — generation, backup, restore, destruction |
| P1 | Quorum enforcement in the custody interface, not in a policy document |
| P1 | Ceremony record as an append-only audit entry |
| P2 | Rehearsed restore-from-backup, evidenced annually |

⚠️ Banks audit the **procedure**, not only the code. A perfect m-of-n
implementation with no written ceremony, no witnesses, and no minutes fails the
review. This is a document deliverable that carries the same weight as a
feature.

---

## 6. Rotation and revocation

| Key | Lifetime | On rotation | On compromise |
| --- | --- | --- | --- |
| mTLS leaf | 24 h | Automatic, internal CA | Re-issue, allowlist entry removed |
| Token signing | 90 days | Both keys in JWKS through the overlap | Publish new JWKS, revoke sessions, force re-auth |
| KEK | 12 months | Re-wrap DEKs; plaintext never re-encrypted | Customer revokes; all ciphertext dies with it |
| Per-row DEK | Life of the row | Never rotated — shredded instead | Row destroyed |
| Blind index HMAC | With the KEK | Full reindex required | Reindex, and treat prior indexes as leaked equality |

⚠️ KEK rotation re-wraps data encryption keys. It does **not** re-encrypt user
data, so it is cheap — but only if DEKs were per-row from day one. Retrofitting
per-row DEKs onto a single-key design is a full table rewrite under load.

---

## 7. Cryptographic shredding

Destroying a user's key destroys their data everywhere it was ever written,
including backups nobody can selectively edit.

| Step | Action |
| --- | --- |
| 1 | Destroy the user's DEK, and the index-key material scoped to them |
| 2 | Ciphertext in live tables, replicas, and every historic backup becomes unrecoverable |
| 3 | The immutable audit ledger keeps the *event*, never the plaintext |
| 4 | Emit a signed shred certificate — subject, timestamp, operator, quorum |

⚠️ This is the only mechanism that satisfies erasure obligations without
rewriting immutable backups, and it constrains the schema from the first
migration: **anything that must be erasable has to be encrypted with a
per-subject key from the beginning.** A plaintext column added later for
convenience quietly breaks the guarantee, so schema review must enforce it.

⚠️ Under HYOK the customer can shred without us. Say so in the sales
conversation — it is the strongest sentence in this document.

---

## 8. What a reviewer will ask

Have an answer to each of these before the first bank meeting.

| Question | Where the answer lives |
| --- | --- |
| Can you decrypt our data without us? | §1 — no, under HYOK or on-prem HSM |
| Which validated module, which certificate number? | §2 + provider attestation in §3 |
| What happens on key compromise? | §6 |
| Who can perform a KEK operation, and how is that enforced? | §5 |
| Show us the key ceremony record | §5 — deliverable, not yet written |
| How do we exit and take our data? | [compliance.md](compliance.md) §5 — gap |
| What is the latency cost of our HSM being in the path? | §1 — must be measured, not estimated |
| Is any key material ever in a log, a core dump, or swap? | `zeroize` on drop, `mlock`, no swap, read-only rootfs |

⚠️ The last row is where most vendors fail. Key material reaching a crash dump
is a routine finding, and the README's no-swap and `mlock` posture only holds if
panics, core dumps, and debug tooling are disabled in the `regulated` profile
too.
