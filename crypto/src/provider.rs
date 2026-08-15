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
    /// Authentication failed: wrong key, wrong tenant, or tampered bytes.
    /// Deliberately undifferentiated — telling the caller *which* is an oracle.
    Decrypt,
}

impl fmt::Display for ProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownKey(h) => write!(f, "unknown key handle {h:?}"),
            Self::Backend(msg) => write!(f, "crypto backend error: {msg}"),
            Self::Decrypt => write!(f, "decryption failed"),
        }
    }
}

impl std::error::Error for ProviderError {}

/// The primitives the Guard is allowed to ask for. Grows one reviewed method
/// at a time; today it carries the operation that needs no key ceremony to be
/// useful and no secret to be returned.
/// A data encryption key, wrapped by the KEK. Opaque ciphertext: the gateway
/// stores and ferries these, and can never open one.
pub type WrappedDek = Vec<u8>;

pub trait CryptoProvider: Send + Sync {
    /// Generates a fresh DEK and returns it wrapped under the KEK. Per-row
    /// DEKs are what make cryptographic shredding cheap: destroy one key and
    /// that subject's ciphertext dies everywhere, backups included
    /// (docs/key-custody.md §7).
    fn generate_wrapped_dek(
        &self,
        kek: &KeyHandle,
        tenant_id: &str,
    ) -> Result<WrappedDek, ProviderError>;

    /// Encrypts one field. `tenant_id` is authenticated associated data on
    /// both the wrap and the payload, so a DEK cannot open ciphertext from
    /// another tenant — the binding is cryptographic, not a lookup (T10).
    fn encrypt_field(
        &self,
        kek: &KeyHandle,
        tenant_id: &str,
        wrapped_dek: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ProviderError>;

    fn decrypt_field(
        &self,
        kek: &KeyHandle,
        tenant_id: &str,
        wrapped_dek: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, ProviderError>;

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
