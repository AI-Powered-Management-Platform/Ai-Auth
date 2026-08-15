//! The Guard's crate: the T9 request gate, the service skeleton, and the
//! secret-handling primitive. Cryptographic operations arrive behind the
//! CryptoProvider trait in a later, separately reviewed batch.

#![forbid(unsafe_code)]

pub mod context;
pub mod gen;
pub mod provider;
pub mod providers;
pub mod service;
pub mod webauthn;

use zeroize::Zeroizing;

/// A byte buffer that is wiped when dropped.
///
/// Backed by `zeroize` — volatile writes and compiler fences, the real wipe
/// the interim `black_box` version approximated before this batch landed.
pub struct SecretBuf(Zeroizing<Vec<u8>>);

impl SecretBuf {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Secrets never appear in logs or panics: Debug prints length only.
impl std::fmt::Debug for SecretBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretBuf(len={}, contents hidden)", self.0.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expose_returns_contents() {
        let s = SecretBuf::new(vec![1, 2, 3]);
        assert_eq!(s.expose(), &[1, 2, 3]);
        assert_eq!(s.len(), 3);
        assert!(!s.is_empty());
    }

    #[test]
    fn debug_never_prints_contents() {
        let s = SecretBuf::new(b"kek-material".to_vec());
        let printed = format!("{s:?}");
        assert!(!printed.contains("kek"));
        assert!(printed.contains("hidden"));
    }
}
