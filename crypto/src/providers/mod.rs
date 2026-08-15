//! Backends implementing [`crate::provider::CryptoProvider`]. The FIPS
//! (`aws-lc-rs`) and PKCS#11 providers land here beside the software one,
//! selected by profile at startup rather than by build flag.
pub mod software;
