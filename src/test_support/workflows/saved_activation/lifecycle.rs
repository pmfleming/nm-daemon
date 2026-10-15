use super::saved_profile;
use crate::activation::{CredentialStop, Guard};
use crate::application::{Application, ConnectOutcome};
use crate::error::{ErrorCode, ErrorOperation, ErrorReport};
use crate::test_support::workflows::{ACTIVE, FakeNm, Outcome, isolated, path};
use anyhow::Result;
use std::time::Instant;

#[test]
fn temporary_join_uses_new_identity_without_updating_or_deleting_saved_profile() -> Result<()> {
    isolated(
        concat!(
            module_path!(),
            "::temporary_join_uses_new_identity_without_updating_or_deleting_saved_profile"
        ),
        || {
            let fake = FakeNm::new([Outcome::Connected], false)?;
            fake.state.lock().unwrap().settings = saved_profile(1)?;
            let app = Application::new(&fake.nm);
            let entries = fake
                .nm
                .network_entries_for_access_points(fake.nm.list_all_access_points()?)?;
            let mut request = app.connect_request_for_key(&entries[0].key, None, None, None)?;
            for candidate in
                std::iter::once(&mut request.candidate).chain(&mut request.alternatives)
            {
                candidate.target.profile.remember = Some(false);
            }
            assert!(matches!(
                app.connect(&request, None, |_| Ok(()))?,
                ConnectOutcome::Succeeded(_)
            ));
            let state = fake.state.lock().unwrap();
            assert_eq!(
                (state.updates, state.deleted, state.added),
                (0, 0, 1),
                "only AddAndActivateConnection2 is permitted; never Update/Delete the saved profile"
            );
            assert_eq!(state.persist.as_deref(), Some("volatile"));
            let uuid =
                crate::variant::setting::<&str>(&state.settings["connection"], "uuid").unwrap();
            assert_ne!(uuid, "saved-example");
            assert!(uuid::Uuid::parse_str(uuid).is_ok());
            assert_eq!(
                crate::variant::setting::<bool>(&state.settings["connection"], "autoconnect"),
                Some(false)
            );
            assert_eq!(
                crate::variant::setting::<u32>(
                    &state.settings["802-11-wireless-security"],
                    "psk-flags"
                ),
                Some(2)
            );
            Ok(())
        },
    )
}

#[test]
fn credential_stop_survives_elapsed_activation_deadline_and_aborts_exact_path() -> Result<()> {
    for (stop, code) in [
        (CredentialStop::Cancelled, ErrorCode::Cancelled),
        (CredentialStop::Expired, ErrorCode::Timeout),
        (CredentialStop::Unavailable, ErrorCode::PasswordUnavailable),
    ] {
        let fake = FakeNm::new([], false)?;
        fake.state.lock().unwrap().settings = saved_profile(1)?;
        let entries = fake
            .nm
            .network_entries_for_access_points(fake.nm.list_all_access_points()?)?;
        let request = Application::new(&fake.nm).connect_request_for_key(
            &entries[0].key,
            None,
            None,
            None,
        )?;
        let guard = Guard::new(":1.0".into(), "wait-test".into(), Instant::now(), || {});
        guard.state.stop(stop);
        guard.state.stop(CredentialStop::Expired); // A later stop must not overwrite the first outcome.
        fake.state.lock().unwrap().current = Some(Outcome::AwaitingSecrets);
        let error = crate::connect_wait::wait_for_active_target_path(
            &fake.nm,
            &request.candidate.target,
            Some(&path(ACTIVE)),
            None,
            Some(&guard.state),
        )
        .unwrap_err();
        let report = ErrorReport::from_error(&error, ErrorOperation::Connect);
        assert_eq!(report.code, code);
        assert_eq!(report.details["credential_outcome"], stop.name());
        assert_eq!(fake.state.lock().unwrap().deactivated, [ACTIVE]);
    }
    Ok(())
}
