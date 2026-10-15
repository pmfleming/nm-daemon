use super::{AUTHENTICATION_RESERVE, CredentialStop, Guard, find, identity};
use crate::error::{ErrorOperation, ErrorReport};
use crate::nm::ConnectionSettings;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[test]
fn verifier_enforces_credential_budget_even_when_lookup_worker_is_blocked() {
    let deadline = Instant::now() + AUTHENTICATION_RESERVE - Duration::from_millis(1);
    let guard = Guard::new(
        "blocked-owner".into(),
        "blocked-profile".into(),
        deadline,
        || {},
    );
    assert_eq!(
        guard.state.credential_deadline() + AUTHENTICATION_RESERVE,
        deadline
    );
    assert!(
        guard.state.error().is_none(),
        "ordinary authentication still has its reserve"
    );
    let _request = guard.state.track_credentials();
    let report = ErrorReport::from_error(&guard.state.error().unwrap(), ErrorOperation::Connect);
    assert_eq!(report.details["credential_outcome"], "expired");
    assert!(Instant::now() < guard.state.deadline);
}

#[test]
fn replacement_cancels_only_same_owner_and_profile_and_old_drop_cannot_remove_new_scope() {
    let settings = ConnectionSettings::from([(
        "connection".into(),
        crate::variant::value_map([("uuid", "synthetic-uuid".into())]).unwrap(),
    )]);
    // Register before NM assigns a path; lookup must follow UUID, not that path.
    let id = identity(&settings, "/");
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
        &find("replace-owner", &settings, "/assigned/profile").unwrap(),
        &current.state
    ));
    assert!(find("different-owner", &settings, "/assigned/profile").is_none());
    let current_state = Arc::clone(&current.state);
    drop(current);
    assert!(!current_state.live());
    assert!(find("replace-owner", &settings, "/assigned/profile").is_none());
    // The first credential outcome must survive any later stop signal.
    assert_eq!(
        ErrorReport::from_error(&old_state.error().unwrap(), ErrorOperation::Connect).details["credential_outcome"],
        CredentialStop::Cancelled.name()
    );
}
