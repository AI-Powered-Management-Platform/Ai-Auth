//! Deployment profiles, and the startup checks that make them honest.
//!
//! A profile that silently degrades is worse than no profile: it produces a
//! deployment that believes it is compliant. So `regulated` is not a set of
//! preferences — it is a set of preconditions, checked before the service
//! accepts a single request, and a deployment that cannot satisfy them does
//! not start.

use crate::provider::ProviderAttestation;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    /// The default. Phishing-resistant everywhere, no weak path anywhere.
    Strict,
    Balanced,
    Legacy,
    /// `strict` plus the machinery an auditor checks.
    Regulated,
}

impl Profile {
    /// Parses a profile name. An unrecognised value is an error, never a
    /// silent fallback: a typo in configuration must not quietly downgrade a
    /// deployment to something weaker than intended.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "strict" => Ok(Self::Strict),
            "balanced" => Ok(Self::Balanced),
            "legacy" => Ok(Self::Legacy),
            "regulated" => Ok(Self::Regulated),
            other => Err(format!(
                "unknown profile {other:?}: expected strict, balanced, legacy, or regulated"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Balanced => "balanced",
            Self::Legacy => "legacy",
            Self::Regulated => "regulated",
        }
    }
}

impl Default for Profile {
    /// `strict`, because the default profile is the real security level of
    /// the product — most operators never change it.
    fn default() -> Self {
        Self::Strict
    }
}

/// Why a deployment was refused. Each variant names a precondition the
/// profile requires and the running configuration does not meet.
#[derive(Debug, PartialEq, Eq)]
pub enum StartupRefusal {
    /// `regulated` demands a validated cryptographic module. The software
    /// provider is honest about not being one — see docs/key-custody.md §2.
    ProviderNotValidated { profile: &'static str, module: &'static str },
}

impl std::fmt::Display for StartupRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProviderNotValidated { profile, module } => write!(
                f,
                "profile {profile} requires a FIPS 140-3 validated cryptographic module, \
                 but the configured provider is {module}, which is not validated. \
                 Configure a validated backend or run a different profile."
            ),
        }
    }
}

/// The gate between configuration and service. Called before the server
/// binds, so an incoherent deployment fails at startup rather than at the
/// first request that needed the guarantee.
pub fn check(profile: Profile, attestation: &ProviderAttestation) -> Result<(), StartupRefusal> {
    if profile == Profile::Regulated && !attestation.fips {
        return Err(StartupRefusal::ProviderNotValidated {
            profile: profile.as_str(),
            module: attestation.module,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attestation(fips: bool) -> ProviderAttestation {
        ProviderAttestation {
            module: if fips { "aws-lc-fips" } else { "RustCrypto (hmac, sha2)" },
            version: "test",
            fips,
            certificate: if fips { Some("4816") } else { None },
        }
    }

    #[test]
    fn the_default_profile_is_strict() {
        assert_eq!(Profile::default(), Profile::Strict);
    }

    #[test]
    fn known_names_parse_case_insensitively() {
        assert_eq!(Profile::parse("strict").unwrap(), Profile::Strict);
        assert_eq!(Profile::parse(" Regulated ").unwrap(), Profile::Regulated);
        assert_eq!(Profile::parse("LEGACY").unwrap(), Profile::Legacy);
    }

    #[test]
    fn an_unknown_profile_is_an_error_not_a_fallback() {
        // A typo must not silently produce a weaker deployment.
        assert!(Profile::parse("strickt").is_err());
        assert!(Profile::parse("").is_err());
    }

    #[test]
    fn regulated_refuses_an_unvalidated_provider() {
        let err = check(Profile::Regulated, &attestation(false)).unwrap_err();
        assert!(matches!(err, StartupRefusal::ProviderNotValidated { .. }));
        // The message must name the fix, not just the failure.
        assert!(err.to_string().contains("not validated"));
    }

    #[test]
    fn regulated_accepts_a_validated_provider() {
        assert!(check(Profile::Regulated, &attestation(true)).is_ok());
    }

    #[test]
    fn other_profiles_do_not_require_validation() {
        for p in [Profile::Strict, Profile::Balanced, Profile::Legacy] {
            assert!(check(p, &attestation(false)).is_ok(), "{p:?} should start");
        }
    }
}
