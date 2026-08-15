//! The Guard's service implementation. v1 posture: enforce the T9 gate and
//! audit every operation — then refuse, because the actual cryptography
//! arrives with the CryptoProvider batch. Enforcement exists before function
//! on purpose: no code path will ever exist where the work happens without
//! the gate in front of it.

use std::sync::Arc;

use tonic::{Request, Response, Status};

use crate::context;
use crate::gen::aiauth::crypto::v1::crypto_service_server::CryptoService;
use crate::provider::{CryptoProvider, KeyHandle};
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
}

impl Guard {
    pub fn new(provider: Arc<dyn CryptoProvider>, index_key: KeyHandle) -> Self {
        Self { provider, index_key }
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

/// Gate first, audit always, work never (yet).
fn gate(
    op: &str,
    ctx: Option<&RequestContext>,
    want: Purpose,
    subject_required: bool,
) -> Result<(), Status> {
    match context::validate(ctx, want, subject_required) {
        Ok(()) => {
            audit(op, ctx, "accepted_unimplemented");
            Err(Status::unimplemented(
                "the operation is gated and audited; the cryptography arrives with the CryptoProvider batch",
            ))
        }
        Err(e) => {
            audit(op, ctx, "rejected");
            Err(e)
        }
    }
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
        gate("verify_assertion", msg.context.as_ref(), Purpose::PasskeyLogin, false)?;
        unreachable!("gate always returns Err in the v1 skeleton");
    }

    async fn encrypt_field(
        &self,
        req: Request<EncryptFieldRequest>,
    ) -> Result<Response<EncryptFieldResponse>, Status> {
        let msg = req.into_inner();
        gate("encrypt_field", msg.context.as_ref(), Purpose::RowEncrypt, true)?;
        unreachable!("gate always returns Err in the v1 skeleton");
    }

    async fn decrypt_field(
        &self,
        req: Request<DecryptFieldRequest>,
    ) -> Result<Response<DecryptFieldResponse>, Status> {
        let msg = req.into_inner();
        gate("decrypt_field", msg.context.as_ref(), Purpose::RowDecrypt, true)?;
        unreachable!("gate always returns Err in the v1 skeleton");
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
    use crate::providers::software::SoftwareProvider;
    use tonic::Code;

    fn guard() -> Guard {
        let p = SoftwareProvider::new().with_key(KeyHandle::new("idx-1"), vec![9u8; 32]);
        Guard::new(Arc::new(p), KeyHandle::new("idx-1"))
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
    async fn correct_purpose_reaches_unimplemented() {
        // Proves ordering on an operation whose cryptography is still absent:
        // the gate passed, and only then did the handler report that the work
        // itself does not exist yet.
        let req = DecryptFieldRequest {
            context: ctx(Purpose::RowDecrypt),
            ..Default::default()
        };
        let err = guard().decrypt_field(Request::new(req)).await.unwrap_err();
        assert_eq!(err.code(), Code::Unimplemented);
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
