//! The Guard's crate. v1 skeleton: the secret-handling primitive only.
//!
//! No dependencies yet, deliberately: the first `cargo add` is a reviewed,
//! Tier-1 decision (docs/development-lifecycle.md §3). When the real
//! dependency batch lands (`zeroize`, `subtle`, the CryptoProvider backends),
//! `SecretBuf` switches to `zeroize`'s volatile, fence-backed wipe.

#![forbid(unsafe_code)]

use std::hint::black_box;

/// A byte buffer that overwrites its contents on drop.
///
/// Interim, std-only wipe: fill with zeros and pass the buffer through
/// [`black_box`] so the compiler cannot prove the writes dead and elide them.
/// This is best-effort until `zeroize` (volatile writes + compiler fences)
/// arrives with the first dependency batch — tracked in the v1 cut.
pub struct SecretBuf(Vec<u8>);

impl SecretBuf {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
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

impl Drop for SecretBuf {
    fn drop(&mut self) {
        self.0.fill(0);
        black_box(&self.0);
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
