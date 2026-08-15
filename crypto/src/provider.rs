//! The `CryptoProvider` boundary — the decision that cannot be retrofitted.
//!
//! Every primitive the Guard uses goes through this trait, so the backend is
//! a deployment choice rather than a code change: RustCrypto for development,
//! `aws-lc-rs` in FIPS mode or a PKCS#11 HSM for `regulated`
//! (docs/key-custody.md §2–3). Call sites never name an algorithm crate.
//!
//! Three rules the trait exists to enforce:
//!   1. `KeyHandle` is a handle, never key material — with an HSM the bytes
//!      never enter our address space, and the type makes that expressible.
//!   2. Every provider reports its own attestation, so the console can show
//!      the real module and certificate number rather than a claim.
//!   3. Tenant identity is an *argument to the cryptography*, not a lookup
//!      the caller may forget (T10).

use std::fmt;

/// Opaque reference to a key the provider holds. Deliberately carries no
/// bytes: an HSM-backed provider stores a PKCS#11 object id behind the same
/// type as a software provider's in-memory slot.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct KeyHandle(String);

impl KeyHandle {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for KeyHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyHandle({})", self.0)
    }
}

/// What a provider says about itself, surfaced in the admin console and in
/// audit records. `fips` is a fact about the module, never an aspiration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderAttestation {
    pub module: &'static str,
    pub version: &'static str,
    pub fips: bool,
    /// FIPS certificate number when the module is validated.
    pub certificate: Option<&'static str>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ProviderError {
    UnknownKey(KeyHandle),
    Backend(String),
}

impl fmt::Display for ProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownKey(h) => write!(f, "unknown key handle {h:?}"),
            Self::Backend(msg) => write!(f, "crypto backend error: {msg}"),
        }
    }
}

impl std::error::Error for ProviderError {}

/// The primitives the Guard is allowed to ask for. Grows one reviewed method
/// at a time; today it carries the operation that needs no key ceremony to be
/// useful and no secret to be returned.
pub trait CryptoProvider: Send + Sync {
    /// Deterministic, tenant-bound index for equality search over encrypted
    /// data. `tenant_id` is mixed into the derivation, so identical plaintext
    /// in two tenants yields different indexes — cross-tenant correlation is
    /// impossible even for whoever reads the whole column (T10).
    fn blind_index(
        &self,
        key: &KeyHandle,
        tenant_id: &str,
        input: &[u8],
    ) -> Result<[u8; 32], ProviderError>;

    fn attestation(&self) -> ProviderAttestation;
}
