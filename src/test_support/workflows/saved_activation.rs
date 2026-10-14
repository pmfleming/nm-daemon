use super::*;
use crate::application::{Application, ConnectOutcome};

fn saved_profile(flags: u32) -> Result<ConnectionSettings> {
    Ok(ConnectionSettings::from([
        ("connection".into(), value_map([
            ("id", "Example".into()), ("uuid", "saved-example".into()),
            ("type", "802-11-wireless".into()), ("interface-name", "test-wifi".into()),
        ])?),
        ("802-11-wireless".into(), value_map([("ssid", b"Example".to_vec().into()), ("mode", "infrastructure".into())])?),
        ("802-11-wireless-security".into(), value_map([("key-mgmt", "wpa-psk".into()), ("psk-flags", flags.into())])?),
    ]))
}

#[test]
fn saved_connect_delegates_credentials_without_probe_rewrite_or_duplicate_profile() -> Result<()> {
    isolated(concat!(module_path!(), "::saved_connect_delegates_credentials_without_probe_rewrite_or_duplicate_profile"), || {
        for flags in [0, 1, 2] {
            let fake = FakeNm::new([Outcome::Connected], false)?;
            fake.state.lock().unwrap().settings = saved_profile(flags)?;
            let app = Application::new(&fake.nm);
            let entries = fake.nm.network_entries_for_access_points(fake.nm.list_all_access_points()?)?;
            let request = app.connect_request_for_key(&entries[0].key, None, None, None)?;
            assert!(matches!(app.connect(&request, None, |_| Ok(()))?, ConnectOutcome::Succeeded(_)));
            // Clicking Connect again is idempotent, not a password replacement.
            assert!(matches!(app.connect(&request, None, |_| Ok(()))?, ConnectOutcome::Succeeded(_)));
            let state = fake.state.lock().unwrap();
            assert_eq!(state.activations.len(), 1);
            assert_eq!((state.secret_probes, state.updates, state.added, state.deleted), (0, 0, 0, 0));
            assert_eq!(crate::variant::setting::<&str>(&state.settings["connection"], "uuid"), Some("saved-example"));
        }
        Ok(())
    })
}

#[test]
fn missing_saved_credentials_fail_after_activation_without_creating_fallback_profiles() -> Result<()> {
    isolated(concat!(module_path!(), "::missing_saved_credentials_fail_after_activation_without_creating_fallback_profiles"), || {
        let fake = FakeNm::new([Outcome::NoSecrets], false)?;
        fake.state.lock().unwrap().settings = saved_profile(1)?;
        let app = Application::new(&fake.nm);
        let entries = fake.nm.network_entries_for_access_points(fake.nm.list_all_access_points()?)?;
        let request = app.connect_request_for_key(&entries[0].key, None, None, None)?;
        let ConnectOutcome::Failed { result, .. } = app.connect(&request, None, |_| Ok(()))? else { panic!("expected real activation failure") };
        assert_eq!(result.reason, Some(crate::model::ConnectFailureReason::PasswordUnavailable));
        let state = fake.state.lock().unwrap();
        assert_eq!(state.activations.len(), 1, "credential failures must not retry other APs");
        assert_eq!((state.secret_probes, state.updates, state.added, state.deleted), (0, 0, 0, 0));
        Ok(())
    })
}
