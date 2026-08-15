//! WebAuthn assertion verification — the step that makes a passkey a passkey.
//!
//! The checks below are not a subset chosen for convenience: each one closes
//! a specific attack, and skipping any of them turns the ceremony into
//! theatre. Order is cheapest-first, so a malformed request costs microseconds.
//!
//! What this closes, and what it does not: origin binding is why a passkey
//! cannot be phished — the browser will not sign for a lookalike domain. It
//! says nothing about what happens after login; that is T1, answered by
//! token binding, not here.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

/// Why an assertion was refused. Codes are stable strings for the audit
/// trail; they name the failed check, never the credential or the user.
#[derive(Debug, PartialEq, Eq)]
pub enum Rejection {
    MalformedClientData,
    WrongType,
    ChallengeMismatch,
    OriginMismatch,
    RpIdMismatch,
    UserNotPresent,
    SignCountRegression,
    MalformedAuthenticatorData,
    UnsupportedKey,
    BadSignature,
}

impl Rejection {
    pub fn code(&self) -> &'static str {
        match self {
            Self::MalformedClientData => "malformed_client_data",
            Self::WrongType => "wrong_type",
            Self::ChallengeMismatch => "challenge_mismatch",
            Self::OriginMismatch => "origin_mismatch",
            Self::RpIdMismatch => "rp_id_mismatch",
            Self::UserNotPresent => "user_not_present",
            Self::SignCountRegression => "sign_count_regression",
            Self::MalformedAuthenticatorData => "malformed_authenticator_data",
            Self::UnsupportedKey => "unsupported_key",
            Self::BadSignature => "bad_signature",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Verified {
    pub new_sign_count: u32,
}

/// Everything the verifier is told. Expectations come from the gateway's
/// stored ceremony state, never from the assertion itself.
pub struct Expectations<'a> {
    pub rp_id: &'a str,
    pub origin: &'a str,
    pub challenge: &'a [u8],
    pub stored_sign_count: u32,
}

const FLAG_UP: u8 = 0x01;
const AUTH_DATA_MIN: usize = 37; // rpIdHash(32) + flags(1) + signCount(4)

/// Verifies one assertion. `public_key_sec1` is an uncompressed P-256 point;
/// COSE unwrapping happens at registration, so the hot path stays small.
pub fn verify(
    exp: &Expectations,
    public_key_sec1: &[u8],
    authenticator_data: &[u8],
    client_data_json: &[u8],
    signature: &[u8],
) -> Result<Verified, Rejection> {
    // 1. clientDataJSON — parsed as data, never trusted as instruction.
    let client: serde_json::Value =
        serde_json::from_slice(client_data_json).map_err(|_| Rejection::MalformedClientData)?;

    if client.get("type").and_then(|v| v.as_str()) != Some("webauthn.get") {
        // A registration response replayed into login would otherwise pass.
        return Err(Rejection::WrongType);
    }

    // 2. Challenge: proves freshness, defeats replay.
    let got_challenge = client
        .get("challenge")
        .and_then(|v| v.as_str())
        .ok_or(Rejection::MalformedClientData)?;
    let got_challenge = URL_SAFE_NO_PAD
        .decode(got_challenge)
        .map_err(|_| Rejection::MalformedClientData)?;
    if got_challenge != exp.challenge {
        return Err(Rejection::ChallengeMismatch);
    }

    // 3. Origin: THE anti-phishing check. A proxy on a lookalike domain
    //    cannot make the browser produce this value.
    if client.get("origin").and_then(|v| v.as_str()) != Some(exp.origin) {
        return Err(Rejection::OriginMismatch);
    }

    // 4. authenticatorData shape, then rpIdHash — binds the credential to us.
    if authenticator_data.len() < AUTH_DATA_MIN {
        return Err(Rejection::MalformedAuthenticatorData);
    }
    let expected_rp_hash = Sha256::digest(exp.rp_id.as_bytes());
    if authenticator_data[..32] != expected_rp_hash[..] {
        return Err(Rejection::RpIdMismatch);
    }

    // 5. User presence: somebody touched the authenticator.
    let flags = authenticator_data[32];
    if flags & FLAG_UP == 0 {
        return Err(Rejection::UserNotPresent);
    }

    // 6. Sign count: a counter that goes backwards suggests a cloned
    //    authenticator. Zero means the authenticator does not keep one.
    let sign_count = u32::from_be_bytes([
        authenticator_data[33],
        authenticator_data[34],
        authenticator_data[35],
        authenticator_data[36],
    ]);
    if sign_count != 0 && sign_count <= exp.stored_sign_count {
        return Err(Rejection::SignCountRegression);
    }

    // 7. Signature over authenticatorData || SHA-256(clientDataJSON).
    let key = VerifyingKey::from_sec1_bytes(public_key_sec1).map_err(|_| Rejection::UnsupportedKey)?;
    let sig = Signature::from_der(signature)
        .or_else(|_| Signature::from_slice(signature))
        .map_err(|_| Rejection::BadSignature)?;

    let mut signed = Vec::with_capacity(authenticator_data.len() + 32);
    signed.extend_from_slice(authenticator_data);
    signed.extend_from_slice(&Sha256::digest(client_data_json));

    key.verify(&signed, &sig).map_err(|_| Rejection::BadSignature)?;

    Ok(Verified { new_sign_count: sign_count })
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::SigningKey;
    use rand::rngs::OsRng;

    const RP: &str = "auth.example.com";
    const ORIGIN: &str = "https://auth.example.com";

    struct Fixture {
        key: SigningKey,
        pubkey: Vec<u8>,
        challenge: Vec<u8>,
    }

    fn fixture() -> Fixture {
        let key = SigningKey::random(&mut OsRng);
        let pubkey = key.verifying_key().to_encoded_point(false).as_bytes().to_vec();
        Fixture { key, pubkey, challenge: vec![9u8; 32] }
    }

    fn client_data(ty: &str, challenge: &[u8], origin: &str) -> Vec<u8> {
        format!(
            r#"{{"type":"{ty}","challenge":"{}","origin":"{origin}"}}"#,
            URL_SAFE_NO_PAD.encode(challenge)
        )
        .into_bytes()
    }

    fn auth_data(rp: &str, flags: u8, count: u32) -> Vec<u8> {
        let mut d = Sha256::digest(rp.as_bytes()).to_vec();
        d.push(flags);
        d.extend_from_slice(&count.to_be_bytes());
        d
    }

    fn sign(f: &Fixture, ad: &[u8], cd: &[u8]) -> Vec<u8> {
        let mut msg = ad.to_vec();
        msg.extend_from_slice(&Sha256::digest(cd));
        let sig: Signature = f.key.sign(&msg);
        sig.to_der().as_bytes().to_vec()
    }

    fn expectations<'a>(f: &'a Fixture, stored: u32) -> Expectations<'a> {
        Expectations { rp_id: RP, origin: ORIGIN, challenge: &f.challenge, stored_sign_count: stored }
    }

    #[test]
    fn a_genuine_assertion_verifies() {
        let f = fixture();
        let cd = client_data("webauthn.get", &f.challenge, ORIGIN);
        let ad = auth_data(RP, FLAG_UP, 5);
        let sig = sign(&f, &ad, &cd);
        let v = verify(&expectations(&f, 4), &f.pubkey, &ad, &cd, &sig).unwrap();
        assert_eq!(v.new_sign_count, 5);
    }

    #[test]
    fn a_lookalike_origin_is_refused() {
        // The anti-phishing check: a proxy on evil.example cannot forge this.
        let f = fixture();
        let cd = client_data("webauthn.get", &f.challenge, "https://auth.exarnple.com");
        let ad = auth_data(RP, FLAG_UP, 5);
        let sig = sign(&f, &ad, &cd);
        assert_eq!(verify(&expectations(&f, 4), &f.pubkey, &ad, &cd, &sig), Err(Rejection::OriginMismatch));
    }

    #[test]
    fn a_replayed_challenge_is_refused() {
        let f = fixture();
        let cd = client_data("webauthn.get", &[1u8; 32], ORIGIN);
        let ad = auth_data(RP, FLAG_UP, 5);
        let sig = sign(&f, &ad, &cd);
        assert_eq!(verify(&expectations(&f, 4), &f.pubkey, &ad, &cd, &sig), Err(Rejection::ChallengeMismatch));
    }

    #[test]
    fn a_registration_response_cannot_be_used_to_log_in() {
        let f = fixture();
        let cd = client_data("webauthn.create", &f.challenge, ORIGIN);
        let ad = auth_data(RP, FLAG_UP, 5);
        let sig = sign(&f, &ad, &cd);
        assert_eq!(verify(&expectations(&f, 4), &f.pubkey, &ad, &cd, &sig), Err(Rejection::WrongType));
    }

    #[test]
    fn an_assertion_for_another_relying_party_is_refused() {
        let f = fixture();
        let cd = client_data("webauthn.get", &f.challenge, ORIGIN);
        let ad = auth_data("other.example.com", FLAG_UP, 5);
        let sig = sign(&f, &ad, &cd);
        assert_eq!(verify(&expectations(&f, 4), &f.pubkey, &ad, &cd, &sig), Err(Rejection::RpIdMismatch));
    }

    #[test]
    fn absent_user_presence_is_refused() {
        let f = fixture();
        let cd = client_data("webauthn.get", &f.challenge, ORIGIN);
        let ad = auth_data(RP, 0x00, 5);
        let sig = sign(&f, &ad, &cd);
        assert_eq!(verify(&expectations(&f, 4), &f.pubkey, &ad, &cd, &sig), Err(Rejection::UserNotPresent));
    }

    #[test]
    fn a_regressing_sign_count_suggests_a_clone() {
        let f = fixture();
        let cd = client_data("webauthn.get", &f.challenge, ORIGIN);
        let ad = auth_data(RP, FLAG_UP, 3);
        let sig = sign(&f, &ad, &cd);
        assert_eq!(verify(&expectations(&f, 7), &f.pubkey, &ad, &cd, &sig), Err(Rejection::SignCountRegression));
    }

    #[test]
    fn a_zero_sign_count_is_accepted() {
        // Authenticators that keep no counter always send 0; refusing them
        // would lock out a large share of real devices.
        let f = fixture();
        let cd = client_data("webauthn.get", &f.challenge, ORIGIN);
        let ad = auth_data(RP, FLAG_UP, 0);
        let sig = sign(&f, &ad, &cd);
        assert!(verify(&expectations(&f, 9), &f.pubkey, &ad, &cd, &sig).is_ok());
    }

    #[test]
    fn another_credential_cannot_sign_for_this_one() {
        let f = fixture();
        let impostor = fixture();
        let cd = client_data("webauthn.get", &f.challenge, ORIGIN);
        let ad = auth_data(RP, FLAG_UP, 5);
        let sig = sign(&impostor, &ad, &cd);
        assert_eq!(verify(&expectations(&f, 4), &f.pubkey, &ad, &cd, &sig), Err(Rejection::BadSignature));
    }

    #[test]
    fn tampered_authenticator_data_breaks_the_signature() {
        let f = fixture();
        let cd = client_data("webauthn.get", &f.challenge, ORIGIN);
        let ad = auth_data(RP, FLAG_UP, 5);
        let sig = sign(&f, &ad, &cd);
        // Append extension bytes: structurally valid, so every earlier check
        // still passes and the signature is what catches it.
        let mut tampered = ad.clone();
        tampered.push(0xff);
        assert_eq!(verify(&expectations(&f, 4), &f.pubkey, &tampered, &cd, &sig), Err(Rejection::BadSignature));
    }

    #[test]
    fn truncated_authenticator_data_is_rejected_not_panicked() {
        let f = fixture();
        let cd = client_data("webauthn.get", &f.challenge, ORIGIN);
        assert_eq!(
            verify(&expectations(&f, 4), &f.pubkey, &[0u8; 10], &cd, &[0u8; 64]),
            Err(Rejection::MalformedAuthenticatorData)
        );
    }

    #[test]
    fn garbage_client_data_is_rejected_not_panicked() {
        let f = fixture();
        assert_eq!(
            verify(&expectations(&f, 4), &f.pubkey, &auth_data(RP, FLAG_UP, 5), b"not json", &[0u8; 64]),
            Err(Rejection::MalformedClientData)
        );
    }
}
