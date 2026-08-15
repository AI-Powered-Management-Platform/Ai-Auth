//! The Guard's service implementation. v1 posture: enforce the T9 gate and
//! audit every operation — then refuse, because the actual cryptography
//! arrives with the CryptoProvider batch. Enforcement exists before function
//! on purpose: no code path will ever exist where the work happens without
//! the gate in front of it.

use std::sync::Arc;

use tonic::{Request, Response, Status};

use crate::context;
use crate::webauthn;
use crate::gen::aiauth::crypto::v1::crypto_service_server::CryptoService;
use crate::provider::{CryptoProvider, KeyHandle, ProviderError};
use crate::gen::aiauth::crypto::v1::{
    BlindIndexRequest, BlindIndexResponse, DecryptFieldRequest, DecryptFieldResponse,
    EncryptFieldRequest, EncryptFieldResponse, Purpose, RequestContext, VerifyAssertionRequest,
    VerifyAssertionResponse,
};

pub struct Guard {
    provider: Arc<dyn CryptoProvider>,
    /// The blind-index key. One handle for now; per-tenant derivation and
    /// rotation arrive with the KEK path (docs/key-custody.md §4, §6).
    index_key: KeyHandle,
    /// Key encryption key: wraps and unwraps per-row DEKs.
    kek: KeyHandle,
}

impl Guard {
    pub fn new(provider: Arc<dyn CryptoProvider>, index_key: KeyHandle, kek: KeyHandle) -> Self {
        Self { provider, index_key, kek }
    }

    /// One shape for every cryptographic failure the caller sees. A decrypt
    /// failure is `permission_denied` — the caller asked for something it may
    /// not have (wrong tenant, wrong key) — and never says which.
    fn fail(&self, op: &str, ctx: Option<&RequestContext>, e: &ProviderError) -> Status {
        audit(op, ctx, "denied");
        match e {
            ProviderError::Decrypt => Status::permission_denied("not available for this context"),
            other => {
                eprintln!("{{\"error\":\"{op}\",\"detail\":\"{other}\"}}");
                Status::internal("operation unavailable")
            }
        }
    }
}

/// One line to stdout per key operation — the per-operation audit record
/// (backlog §12). Fields are identifiers and enums, never key material and
/// never user data.
fn audit(op: &str, ctx: Option<&RequestContext>, outcome: &str) {
    let (tenant, request) = match ctx {
        Some(c) => (c.tenant_id.as_str(), c.request_id.as_str()),
        None => ("", ""),
    };
    println!(
        "{{\"audit\":\"key_op\",\"op\":\"{op}\",\"tenant\":\"{tenant}\",\"request\":\"{request}\",\"outcome\":\"{outcome}\"}}"
    );
}

#[tonic::async_trait]
impl CryptoService for Guard {
    async fn verify_assertion(
        &self,
        req: Request<VerifyAssertionRequest>,
    ) -> Result<Response<VerifyAssertionResponse>, Status> {
        let msg = req.into_inner();
        // subject_required=false: with discoverable credentials the subject
        // may be unknown until the assertion itself names it.
        let ctx = msg.context.as_ref();
        if let Err(e) = context::validate(ctx, Purpose::PasskeyLogin, false) {
            audit("verify_assertion", ctx, "rejected");
            return Err(e);
        }

        let (Some(cred), Some(assertion)) = (msg.credential.as_ref(), msg.assertion.as_ref()) else {
            audit("verify_assertion", ctx, "rejected");
            return Err(Status::invalid_argument("credential and assertion are required"));
        };

        let exp = webauthn::Expectations {
            rp_id: &msg.rp_id,
            origin: &msg.expected_origin,
            challenge: &msg.expected_challenge,
            stored_sign_count: cred.sign_count,
        };

        match webauthn::verify(
            &exp,
            &cred.cose_public_key,
            &assertion.authenticator_data,
            &assertion.client_data_json,
            &assertion.signature,
        ) {
            Ok(v) => {
                audit("verify_assertion", ctx, "verified");
                Ok(Response::new(VerifyAssertionResponse {
                    verdict: crate::gen::aiauth::crypto::v1::verify_assertion_response::Verdict::Verified as i32,
                    reason: String::new(),
                    new_sign_count: v.new_sign_count,
                }))
            }
            Err(rejection) => {
                // A rejection is a normal answer, not an error: the gateway
                // needs the verdict to apply policy. The reason names the
                // failed check and never the credential or the user.
                audit("verify_assertion", ctx, rejection.code());
                Ok(Response::new(VerifyAssertionResponse {
                    verdict: crate::gen::aiauth::crypto::v1::verify_assertion_response::Verdict::Rejected as i32,
                    reason: rejection.code().to_string(),
                    new_sign_count: cred.sign_count,
                }))
            }
        }
    }

    async fn encrypt_field(
        &self,
        req: Request<EncryptFieldRequest>,
    ) -> Result<Response<EncryptFieldResponse>, Status> {
        let msg = req.into_inner();
        let ctx = msg.context.as_ref();
        if let Err(e) = context::validate(ctx, Purpose::RowEncrypt, true) {
            audit("encrypt_field", ctx, "rejected");
            return Err(e);
        }
        let tenant = &ctx.expect("validated").tenant_id;

        // Empty wrapped_dek means first write: mint a DEK for this row.
        let wrapped = if msg.wrapped_dek.is_empty() {
            match self.provider.generate_wrapped_dek(&self.kek, tenant) {
                Ok(w) => w,
                Err(e) => return Err(self.fail("encrypt_field", ctx, &e)),
            }
        } else {
            msg.wrapped_dek
        };

        match self
            .provider
            .encrypt_field(&self.kek, tenant, &wrapped, &msg.plaintext)
        {
            Ok(ciphertext) => {
                audit("encrypt_field", ctx, "ok");
                Ok(Response::new(EncryptFieldResponse {
                    ciphertext,
                    wrapped_dek: wrapped,
                }))
            }
            Err(e) => Err(self.fail("encrypt_field", ctx, &e)),
        }
    }

    async fn decrypt_field(
        &self,
        req: Request<DecryptFieldRequest>,
    ) -> Result<Response<DecryptFieldResponse>, Status> {
        let msg = req.into_inner();
        let ctx = msg.context.as_ref();
        if let Err(e) = context::validate(ctx, Purpose::RowDecrypt, true) {
            audit("decrypt_field", ctx, "rejected");
            return Err(e);
        }
        let tenant = &ctx.expect("validated").tenant_id;

        match self
            .provider
            .decrypt_field(&self.kek, tenant, &msg.wrapped_dek, &msg.ciphertext)
        {
            Ok(plaintext) => {
                audit("decrypt_field", ctx, "ok");
                Ok(Response::new(DecryptFieldResponse { plaintext }))
            }
            Err(e) => Err(self.fail("decrypt_field", ctx, &e)),
        }
    }

    async fn blind_index(
        &self,
        req: Request<BlindIndexRequest>,
    ) -> Result<Response<BlindIndexResponse>, Status> {
        let msg = req.into_inner();
        let ctx = msg.context.as_ref();

        // Gate first, always — the operation below is unreachable until the
        // request has proven what it is for and whom it concerns.
        if let Err(e) = context::validate(ctx, Purpose::BlindIndex, false) {
            audit("blind_index", ctx, "rejected");
            return Err(e);
        }

        // Safe: validate() rejects a missing context before this point.
        let tenant = &ctx.expect("validated").tenant_id;

        match self.provider.blind_index(&self.index_key, tenant, &msg.input) {
            Ok(index) => {
                audit("blind_index", ctx, "ok");
                Ok(Response::new(BlindIndexResponse { index: index.to_vec() }))
            }
            Err(e) => {
                audit("blind_index", ctx, "backend_error");
                // The caller learns that it failed, never why in cryptographic
                // detail — error text is an oracle if it describes key state.
                eprintln!("{{\"error\":\"blind_index backend\",\"detail\":\"{e}\"}}");
                Err(Status::internal("blind index unavailable"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gen::aiauth::crypto::v1::verify_assertion_response::Verdict;
    use crate::gen::aiauth::crypto::v1::{Assertion, StoredCredential};
    use crate::providers::software::SoftwareProvider;
    use tonic::Code;

    fn guard() -> Guard {
        let p = SoftwareProvider::new()
            .with_key(KeyHandle::new("idx-1"), vec![9u8; 32])
            .with_key(KeyHandle::new("kek-1"), vec![3u8; 32]);
        Guard::new(Arc::new(p), KeyHandle::new("idx-1"), KeyHandle::new("kek-1"))
    }

    fn ctx(purpose: Purpose) -> Option<RequestContext> {
        Some(RequestContext {
            tenant_id: "t1".into(),
            subject_id: "s1".into(),
            purpose: purpose as i32,
            request_id: "req-1".into(),
        })
    }

    #[tokio::test]
    async fn no_context_is_invalid_argument() {
        let err = guard()
            .verify_assertion(Request::new(VerifyAssertionRequest::default()))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
    }

    #[tokio::test]
    async fn wrong_purpose_is_permission_denied() {
        let req = DecryptFieldRequest {
            context: ctx(Purpose::PasskeyLogin),
            ..Default::default()
        };
        let err = guard().decrypt_field(Request::new(req)).await.unwrap_err();
        assert_eq!(err.code(), Code::PermissionDenied);
    }

    #[tokio::test]
    async fn a_malformed_assertion_is_a_rejected_verdict_not_an_error() {
        // The gateway must always get a verdict it can apply policy to.
        let req = VerifyAssertionRequest {
            context: ctx(Purpose::PasskeyLogin),
            rp_id: "auth.example.com".into(),
            expected_origin: "https://auth.example.com".into(),
            expected_challenge: vec![1u8; 32],
            credential: Some(StoredCredential { cose_public_key: vec![4u8; 65], sign_count: 0 }),
            assertion: Some(Assertion {
                authenticator_data: vec![0u8; 37],
                client_data_json: b"not json".to_vec(),
                signature: vec![0u8; 64],
            }),
        };
        let resp = guard().verify_assertion(Request::new(req)).await.unwrap().into_inner();
        assert_eq!(resp.verdict, Verdict::Rejected as i32);
        assert_eq!(resp.reason, "malformed_client_data");
    }

    #[tokio::test]
    async fn a_missing_assertion_is_an_error() {
        let req = VerifyAssertionRequest {
            context: ctx(Purpose::PasskeyLogin),
            ..Default::default()
        };
        let err = guard().verify_assertion(Request::new(req)).await.unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
    }

    #[tokio::test]
    async fn envelope_round_trip_over_the_service() {
        let g = guard();
        let enc = g
            .encrypt_field(Request::new(EncryptFieldRequest {
                context: ctx(Purpose::RowEncrypt),
                plaintext: b"alice@example.com".to_vec(),
                wrapped_dek: Vec::new(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(!enc.wrapped_dek.is_empty(), "first write must mint a DEK");

        let dec = g
            .decrypt_field(Request::new(DecryptFieldRequest {
                context: ctx(Purpose::RowDecrypt),
                ciphertext: enc.ciphertext,
                wrapped_dek: enc.wrapped_dek,
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(dec.plaintext, b"alice@example.com");
    }

    #[tokio::test]
    async fn another_tenant_cannot_decrypt_the_row() {
        let g = guard();
        let enc = g
            .encrypt_field(Request::new(EncryptFieldRequest {
                context: ctx(Purpose::RowEncrypt),
                plaintext: b"payload".to_vec(),
                wrapped_dek: Vec::new(),
            }))
            .await
            .unwrap()
            .into_inner();

        let mut other = ctx(Purpose::RowDecrypt).unwrap();
        other.tenant_id = "tenant-b".into();
        let err = g
            .decrypt_field(Request::new(DecryptFieldRequest {
                context: Some(other),
                ciphertext: enc.ciphertext,
                wrapped_dek: enc.wrapped_dek,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::PermissionDenied);
    }

    #[tokio::test]
    async fn blind_index_returns_a_32_byte_index() {
        let req = BlindIndexRequest {
            context: ctx(Purpose::BlindIndex),
            input: b"user@example.com".to_vec(),
        };
        let resp = guard().blind_index(Request::new(req)).await.unwrap();
        assert_eq!(resp.into_inner().index.len(), 32);
    }

    #[tokio::test]
    async fn blind_index_still_refuses_a_wrong_purpose() {
        let req = BlindIndexRequest {
            context: ctx(Purpose::RowEncrypt),
            input: b"x".to_vec(),
        };
        let err = guard().blind_index(Request::new(req)).await.unwrap_err();
        assert_eq!(err.code(), Code::PermissionDenied);
    }

    #[tokio::test]
    async fn unspecified_purpose_never_reaches_the_operation() {
        let req = EncryptFieldRequest {
            context: ctx(Purpose::Unspecified),
            ..Default::default()
        };
        let err = guard().encrypt_field(Request::new(req)).await.unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
    }
}
