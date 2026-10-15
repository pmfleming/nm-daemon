use super::{AUTHENTICATION_RESERVE, CredentialStop, Guard, find, identity};
use crate::error::{ErrorCode, ErrorOperation, ErrorReport};
use crate::nm::ConnectionSettings;
use std::sync::{Arc, atomic::Ordering};
use std::time::{Duration, Instant};

#[test]
fn credentials_have_a_reserved_authentication_budget() {
    let deadline = Instant::now() + Duration::from_secs(90);
    let guard = Guard::new(
        "budget-owner".into(),
        "budget-profile".into(),
        deadline,
        || {},
    );
    assert_eq!(
        guard.state.credential_deadline() + AUTHENTICATION_RESERVE,
        deadline
    );
    assert!(guard.state.live());
    guard.state.stop(CredentialStop::Expired);
    assert!(!guard.state.live());
    let report = ErrorReport::from_error(&guard.state.error().unwrap(), ErrorOperation::Connect);
    assert_eq!(report.code, ErrorCode::Timeout);
    assert_eq!(report.details["credential_outcome"], "expired");
}

#[test]
fn verifier_enforces_credential_budget_even_when_lookup_worker_is_blocked() {
    let guard = Guard::new(
        "blocked-owner".into(),
        "blocked-profile".into(),
        Instant::now() + AUTHENTICATION_RESERVE - Duration::from_millis(1),
        || {},
    );
    assert!(
        guard.state.error().is_none(),
        "ordinary authentication still has its reserve"
    );
    let request = guard.state.track_credentials();
    let report = ErrorReport::from_error(&guard.state.error().unwrap(), ErrorOperation::Connect);
    assert_eq!(report.details["credential_outcome"], "expired");
    assert!(Instant::now() < guard.state.deadline);
    drop(request);
    assert_eq!(guard.state.pending_credentials.load(Ordering::Acquire), 0);
}

#[test]
fn first_credential_outcome_is_stable_and_cancellation_is_not_wrong_password() {
    let guard = Guard::new(
        "cancel-owner".into(),
        "cancel-profile".into(),
        Instant::now() + Duration::from_secs(90),
        || {},
    );
    guard.state.stop(CredentialStop::Cancelled);
    guard.state.stop(CredentialStop::Expired);
    let report = ErrorReport::from_error(&guard.state.error().unwrap(), ErrorOperation::Connect);
    assert_eq!(report.code, ErrorCode::Cancelled);
    assert_eq!(report.details["credential_outcome"], "cancelled");
}

#[test]
fn replacement_cancels_only_same_owner_and_profile_and_old_drop_cannot_remove_new_scope() {
    let settings = ConnectionSettings::new();
    let id = identity(&settings, "/test/profile");
    let deadline = Instant::now() + Duration::from_secs(90);
    let old = Guard::new("replace-owner".into(), id.clone(), deadline, || {});
    let old_state = Arc::clone(&old.state);
    let other = Guard::new("other-owner".into(), id.clone(), deadline, || {});
    let current = Guard::new("replace-owner".into(), id, deadline, || {});
    assert!(!old_state.live());
    assert!(old_state.error().is_some());
    assert!(other.state.live());
    drop(old);
    assert!(Arc::ptr_eq(
        &find("replace-owner", &settings, "/test/profile").unwrap(),
        &current.state
    ));
    let current_state = Arc::clone(&current.state);
    drop(current);
    assert!(!current_state.live());
    assert!(find("replace-owner", &settings, "/test/profile").is_none());
}

#[test]
fn preassigned_uuid_correlates_before_networkmanager_assigns_profile_path() {
    let settings = ConnectionSettings::from([(
        "connection".into(),
        crate::variant::value_map([("uuid", "synthetic-uuid".into())]).unwrap(),
    )]);
    let guard = Guard::new(
        "uuid-owner".into(),
        identity(&settings, "/"),
        Instant::now() + Duration::from_secs(90),
        || {},
    );
    assert!(Arc::ptr_eq(
        &find("uuid-owner", &settings, "/assigned/profile").unwrap(),
        &guard.state
    ));
    assert!(find("different-owner", &settings, "/assigned/profile").is_none());
}
