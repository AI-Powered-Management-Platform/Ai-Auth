//! The T9 gate: every request must say who it is for and why, and the Guard
//! refuses before it does any work. This module is the contract's comment
//! block turned into `Err(...)`.

use tonic::Status;

use crate::gen::aiauth::crypto::v1::{Purpose, RequestContext};

/// Validates a request context against the purpose this operation requires.
///
/// Order matters: cheap structural checks first, then purpose. A rejection
/// here costs microseconds; every handler calls this before touching
/// anything expensive — authenticate before you compute, applied inward.
pub fn validate(
    ctx: Option<&RequestContext>,
    want: Purpose,
    subject_required: bool,
) -> Result<(), Status> {
    let ctx = ctx.ok_or_else(|| Status::invalid_argument("request_context is required"))?;

    if ctx.request_id.is_empty() {
        return Err(Status::invalid_argument(
            "request_id is required: every key operation is individually audited",
        ));
    }
    if ctx.tenant_id.is_empty() {
        return Err(Status::invalid_argument("tenant_id is required (T10)"));
    }
    if subject_required && ctx.subject_id.is_empty() {
        return Err(Status::invalid_argument(
            "subject_id is required for row operations",
        ));
    }

    let got = ctx.purpose();
    if got == Purpose::Unspecified {
        return Err(Status::invalid_argument(
            "PURPOSE_UNSPECIFIED is always rejected (T9)",
        ));
    }
    if got != want {
        return Err(Status::permission_denied(format!(
            "purpose {got:?} does not match this operation (T9)",
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::Code;

    fn ctx(tenant: &str, subject: &str, purpose: Purpose) -> RequestContext {
        RequestContext {
            tenant_id: tenant.into(),
            subject_id: subject.into(),
            purpose: purpose as i32,
            request_id: "req-1".into(),
        }
    }

    #[test]
    fn missing_context_is_rejected() {
        let err = validate(None, Purpose::PasskeyLogin, false).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
    }

    #[test]
    fn unspecified_purpose_is_always_rejected() {
        let c = ctx("t1", "s1", Purpose::Unspecified);
        let err = validate(Some(&c), Purpose::PasskeyLogin, false).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
    }

    #[test]
    fn wrong_purpose_is_permission_denied() {
        let c = ctx("t1", "s1", Purpose::PasskeyLogin);
        let err = validate(Some(&c), Purpose::RowDecrypt, true).unwrap_err();
        assert_eq!(err.code(), Code::PermissionDenied);
    }

    #[test]
    fn empty_tenant_is_rejected() {
        let c = ctx("", "s1", Purpose::BlindIndex);
        let err = validate(Some(&c), Purpose::BlindIndex, false).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
    }

    #[test]
    fn missing_subject_rejected_only_when_required() {
        let c = ctx("t1", "", Purpose::RowEncrypt);
        assert!(validate(Some(&c), Purpose::RowEncrypt, true).is_err());
        assert!(validate(Some(&c), Purpose::RowEncrypt, false).is_ok());
    }

    #[test]
    fn matching_purpose_passes() {
        let c = ctx("t1", "s1", Purpose::RowDecrypt);
        assert!(validate(Some(&c), Purpose::RowDecrypt, true).is_ok());
    }

    #[test]
    fn missing_request_id_is_rejected() {
        let mut c = ctx("t1", "s1", Purpose::BlindIndex);
        c.request_id.clear();
        let err = validate(Some(&c), Purpose::BlindIndex, false).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
    }
}
