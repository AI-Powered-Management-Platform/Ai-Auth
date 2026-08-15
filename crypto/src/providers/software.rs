//! Software provider: RustCrypto primitives, for development and for
//! deployments outside the `regulated` profile.
//!
//! ⚠️ NOT FIPS 140-3 validated, and `attestation()` says so plainly. The
//! `regulated` profile must refuse to start on this provider — the check
//! belongs at startup, where a deployment either satisfies its profile or
//! does not exist (docs/key-custody.md §2).

use std::collections::HashMap;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::provider::{CryptoProvider, KeyHandle, ProviderAttestation, ProviderError, WrappedDek};

type HmacSha256 = Hmac<Sha256>;

/// Domain separation tag. Without it, an HMAC key reused for another purpose
/// could produce colliding outputs across contexts; with it, every future
/// operation gets its own tag and the domains cannot overlap.
const DOMAIN_BLIND_INDEX: &[u8] = b"aiauth/blind-index/v1";
const DOMAIN_DEK_WRAP: &[u8] = b"aiauth/dek-wrap/v1";
const DOMAIN_FIELD: &[u8] = b"aiauth/field/v1";

const NONCE_LEN: usize = 12;
const DEK_LEN: usize = 32;

/// `nonce || ciphertext`. A fresh random nonce per operation; 96-bit nonces
/// with per-row DEKs keep reuse probability negligible.
fn aead_seal(key: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, ProviderError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| ProviderError::Backend(e.to_string()))?;
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad })
        .map_err(|e| ProviderError::Backend(e.to_string()))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn aead_open(key: &[u8], aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, ProviderError> {
    if sealed.len() <= NONCE_LEN {
        return Err(ProviderError::Decrypt);
    }
    let (nonce, ct) = sealed.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| ProviderError::Backend(e.to_string()))?;
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad })
        // Wrong key, wrong tenant, and tampered bytes are one error on
        // purpose: distinguishing them hands an attacker an oracle.
        .map_err(|_| ProviderError::Decrypt)
}

/// Associated data binds a domain and the tenant, length-framed so the
/// fields cannot be shifted across the boundary.
fn aad(domain: &[u8], tenant_id: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(domain.len() + 8 + tenant_id.len());
    v.extend_from_slice(domain);
    v.extend_from_slice(&(tenant_id.len() as u64).to_be_bytes());
    v.extend_from_slice(tenant_id.as_bytes());
    v
}

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

impl SoftwareProvider {
    fn kek(&self, handle: &KeyHandle) -> Result<&Zeroizing<Vec<u8>>, ProviderError> {
        self.keys
            .get(handle)
            .ok_or_else(|| ProviderError::UnknownKey(handle.clone()))
    }

    /// Unwraps a DEK for the life of one operation. The plaintext DEK is a
    /// `Zeroizing` local: it is wiped when this function returns, whichever
    /// way it returns.
    fn unwrap_dek(
        &self,
        kek: &KeyHandle,
        tenant_id: &str,
        wrapped: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
        let k = self.kek(kek)?;
        Ok(Zeroizing::new(aead_open(k, &aad(DOMAIN_DEK_WRAP, tenant_id), wrapped)?))
    }
}

impl CryptoProvider for SoftwareProvider {
    fn generate_wrapped_dek(
        &self,
        kek: &KeyHandle,
        tenant_id: &str,
    ) -> Result<WrappedDek, ProviderError> {
        let k = self.kek(kek)?;
        let mut dek = Zeroizing::new(vec![0u8; DEK_LEN]);
        rand::thread_rng().fill_bytes(&mut dek);
        aead_seal(k, &aad(DOMAIN_DEK_WRAP, tenant_id), &dek)
    }

    fn encrypt_field(
        &self,
        kek: &KeyHandle,
        tenant_id: &str,
        wrapped_dek: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        let dek = self.unwrap_dek(kek, tenant_id, wrapped_dek)?;
        aead_seal(&dek, &aad(DOMAIN_FIELD, tenant_id), plaintext)
    }

    fn decrypt_field(
        &self,
        kek: &KeyHandle,
        tenant_id: &str,
        wrapped_dek: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, ProviderError> {
        let dek = self.unwrap_dek(kek, tenant_id, wrapped_dek)?;
        aead_open(&dek, &aad(DOMAIN_FIELD, tenant_id), ciphertext)
    }

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

        let mut mac = <HmacSha256 as Mac>::new_from_slice(material)
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
    fn envelope_round_trip() {
        let p = provider();
        let k = KeyHandle::new("idx-1");
        let dek = p.generate_wrapped_dek(&k, "t1").unwrap();
        let ct = p.encrypt_field(&k, "t1", &dek, b"secret@example.com").unwrap();
        let pt = p.decrypt_field(&k, "t1", &dek, &ct).unwrap();
        assert_eq!(pt, b"secret@example.com");
    }

    #[test]
    fn ciphertext_never_contains_the_plaintext() {
        let p = provider();
        let k = KeyHandle::new("idx-1");
        let dek = p.generate_wrapped_dek(&k, "t1").unwrap();
        let ct = p.encrypt_field(&k, "t1", &dek, b"secret@example.com").unwrap();
        assert!(!ct.windows(6).any(|w| w == b"secret"));
    }

    #[test]
    fn a_dek_cannot_open_another_tenants_ciphertext() {
        // The T10 claim, as cryptography: same DEK bytes, different tenant in
        // the associated data, and the open fails.
        let p = provider();
        let k = KeyHandle::new("idx-1");
        let dek = p.generate_wrapped_dek(&k, "t1").unwrap();
        let ct = p.encrypt_field(&k, "t1", &dek, b"payload").unwrap();
        assert_eq!(p.decrypt_field(&k, "t2", &dek, &ct), Err(ProviderError::Decrypt));
    }

    #[test]
    fn wrapped_dek_is_bound_to_its_tenant() {
        let p = provider();
        let k = KeyHandle::new("idx-1");
        let dek = p.generate_wrapped_dek(&k, "t1").unwrap();
        // Unwrapping under the wrong tenant fails before any field is touched.
        assert_eq!(p.encrypt_field(&k, "t2", &dek, b"x"), Err(ProviderError::Decrypt));
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let p = provider();
        let k = KeyHandle::new("idx-1");
        let dek = p.generate_wrapped_dek(&k, "t1").unwrap();
        let mut ct = p.encrypt_field(&k, "t1", &dek, b"payload").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert_eq!(p.decrypt_field(&k, "t1", &dek, &ct), Err(ProviderError::Decrypt));
    }

    #[test]
    fn each_encryption_uses_a_fresh_nonce() {
        let p = provider();
        let k = KeyHandle::new("idx-1");
        let dek = p.generate_wrapped_dek(&k, "t1").unwrap();
        let a = p.encrypt_field(&k, "t1", &dek, b"same").unwrap();
        let b = p.encrypt_field(&k, "t1", &dek, b"same").unwrap();
        assert_ne!(a, b, "identical plaintext must not produce identical ciphertext");
    }

    #[test]
    fn truncated_input_is_rejected_not_panicked() {
        let p = provider();
        let k = KeyHandle::new("idx-1");
        let dek = p.generate_wrapped_dek(&k, "t1").unwrap();
        assert_eq!(p.decrypt_field(&k, "t1", &dek, b"short"), Err(ProviderError::Decrypt));
    }

    #[test]
    fn key_handle_debug_shows_id_not_material() {
        let printed = format!("{:?}", KeyHandle::new("idx-1"));
        assert!(printed.contains("idx-1"));
        assert!(!printed.contains('7'), "handles carry no key bytes at all");
    }
}
