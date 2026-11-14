//! The UniFFI crate exports exactly the names in `src/v05/surface-names.txt`.
#[path = "support_names.rs"]
mod support_names;

#[test]
fn the_native_surface_is_the_shared_list() {
    support_names::check("native05", None);
}
#[test]
fn every_refusal_reason_is_a_typed_code() {
    use colophon_core::v05::{Failure, Reason};
    use colophon_ffi::v05::api::{AccountError, REFUSAL_REASONS};
    let all = [
        Reason::Audience,
        Reason::Window,
        Reason::Replay,
        Reason::Conflict,
        Reason::Fork,
        Reason::Revoked,
        Reason::Expired,
        Reason::Ended,
        Reason::NotNarrower,
        Reason::OutOfScope,
        Reason::Origin,
        Reason::Rollback,
        Reason::NotGranted,
        Reason::WrongEpoch,
        Reason::ClockJump,
        Reason::BudgetSpent,
        Reason::WrongFormat,
        Reason::InvalidPayload,
        Reason::CaveatedLive,
        Reason::VaultLocked,
    ];
    assert_eq!(all.len(), REFUSAL_REASONS.len());
    for (r, name) in all.iter().zip(REFUSAL_REASONS) {
        assert_eq!(r.as_str(), name);
        match AccountError::from(Failure::Refused(*r)) {
            AccountError::Refused { code, reason, .. } => {
                assert_eq!(code, format!("refused:{name}"));
                assert_eq!(reason, name);
            }
            other => panic!("{other:?}"),
        }
    }
    for (f, code) in [
        (Failure::Malformed("x".into()), "malformed"),
        (Failure::BadSignature("x".into()), "badSignature"),
        (Failure::NewerFormat("x".into()), "newerFormat"),
        (Failure::Unavailable("x".into()), "unavailable"),
    ] {
        assert_eq!(AccountError::from(f).code(), code);
    }
}
