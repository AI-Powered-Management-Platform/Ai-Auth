//! Software provider: RustCrypto primitives, for development and for
//! deployments outside the `regulated` profile.
//!
//! ⚠️ NOT FIPS 140-3 validated, and `attestation()` says so plainly. The
//! `regulated` profile must refuse to start on this provider — the check
//! belongs at startup, where a deployment either satisfies its profile or
//! does not exist (docs/key-custody.md §2).

use std::collections::HashMap;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::provider::{CryptoProvider, KeyHandle, ProviderAttestation, ProviderError};

type HmacSha256 = Hmac<Sha256>;

/// Domain separation tag. Without it, an HMAC key reused for another purpose
/// could produce colliding outputs across contexts; with it, every future
/// operation gets its own tag and the domains cannot overlap.
const DOMAIN_BLIND_INDEX: &[u8] = b"aiauth/blind-index/v1";

pub struct SoftwareProvider {
    keys: HashMap<KeyHandle, Zeroizing<Vec<u8>>>,
}

impl SoftwareProvider {
    pub fn new() -> Self {
        Self { keys: HashMap::new() }
    }

    /// Loads key material under a handle. Keys arrive from the KEK-unwrap
    /// path in production; this entry point exists so tests and development
    /// can seed a provider without a KMS.
    pub fn with_key(mut self, handle: KeyHandle, material: Vec<u8>) -> Self {
        self.keys.insert(handle, Zeroizing::new(material));
        self
    }
}

impl Default for SoftwareProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl CryptoProvider for SoftwareProvider {
    fn blind_index(
        &self,
        key: &KeyHandle,
        tenant_id: &str,
        input: &[u8],
    ) -> Result<[u8; 32], ProviderError> {
        let material = self
            .keys
            .get(key)
            .ok_or_else(|| ProviderError::UnknownKey(key.clone()))?;

        let mut mac = HmacSha256::new_from_slice(material)
            .map_err(|e| ProviderError::Backend(e.to_string()))?;

        // Length-prefixed framing: without it, tenant "ab" + input "c" and
        // tenant "a" + input "bc" would hash identically, letting a caller
        // forge a collision across tenant boundaries.
        mac.update(DOMAIN_BLIND_INDEX);
        mac.update(&(tenant_id.len() as u64).to_be_bytes());
        mac.update(tenant_id.as_bytes());
        mac.update(&(input.len() as u64).to_be_bytes());
        mac.update(input);

        Ok(mac.finalize().into_bytes().into())
    }

    fn attestation(&self) -> ProviderAttestation {
        ProviderAttestation {
            module: "RustCrypto (hmac, sha2)",
            version: env!("CARGO_PKG_VERSION"),
            fips: false,
            certificate: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider() -> SoftwareProvider {
        SoftwareProvider::new().with_key(KeyHandle::new("idx-1"), vec![7u8; 32])
    }

    #[test]
    fn index_is_deterministic() {
        let p = provider();
        let k = KeyHandle::new("idx-1");
        let a = p.blind_index(&k, "tenant-a", b"user@example.com").unwrap();
        let b = p.blind_index(&k, "tenant-a", b"user@example.com").unwrap();
        assert_eq!(a, b, "equality search requires a stable index");
    }

    #[test]
    fn same_plaintext_differs_across_tenants() {
        let p = provider();
        let k = KeyHandle::new("idx-1");
        let a = p.blind_index(&k, "tenant-a", b"user@example.com").unwrap();
        let b = p.blind_index(&k, "tenant-b", b"user@example.com").unwrap();
        assert_ne!(a, b, "T10: tenants must not be correlatable by index");
    }

    #[test]
    fn framing_prevents_cross_boundary_collision() {
        let p = provider();
        let k = KeyHandle::new("idx-1");
        // Without length prefixes these two concatenate identically.
        let a = p.blind_index(&k, "ab", b"c").unwrap();
        let b = p.blind_index(&k, "a", b"bc").unwrap();
        assert_ne!(a, b, "length framing must separate the fields");
    }

    #[test]
    fn different_input_differs() {
        let p = provider();
        let k = KeyHandle::new("idx-1");
        let a = p.blind_index(&k, "t", b"alice@example.com").unwrap();
        let b = p.blind_index(&k, "t", b"bob@example.com").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn unknown_handle_is_an_error_not_a_default_key() {
        let err = provider()
            .blind_index(&KeyHandle::new("nope"), "t", b"x")
            .unwrap_err();
        assert!(matches!(err, ProviderError::UnknownKey(_)));
    }

    #[test]
    fn attestation_admits_it_is_not_fips() {
        let a = provider().attestation();
        assert!(!a.fips, "the software provider must never claim validation");
        assert!(a.certificate.is_none());
    }

    #[test]
    fn key_handle_debug_shows_id_not_material() {
        let printed = format!("{:?}", KeyHandle::new("idx-1"));
        assert!(printed.contains("idx-1"));
        assert!(!printed.contains('7'), "handles carry no key bytes at all");
    }
}
