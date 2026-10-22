use super::*;

#[test]
fn retention_uses_native_lifetime_and_preserving_explicit_opt_in() -> Result<()> {
    isolated(
        concat!(
            module_path!(),
            "::retention_uses_native_lifetime_and_preserving_explicit_opt_in"
        ),
        || {
            let h = Harness::new()?;
            assert_eq!(
                h.nm.set_connection_remember_by_path(PATH, false)?,
                "Network details will be deleted when you disconnect."
            );
            {
                let s = h.state.lock().unwrap();
                assert_eq!(s.update_flags, 114); // IN_MEMORY | VOLATILE | BLOCK_AUTOCONNECT | NO_REAPPLY
                assert!(s.active && !s.deleted);
                assert_eq!(
                    s.reads, 0,
                    "opting out must not retrieve or rewrite credentials"
                );
            }
            assert_eq!(h.nm.saved_wifi_connections()?[0].remember, Some(false));
            // Re-enabling on the same active identity cancels native retirement.
            assert_eq!(
                h.nm.set_connection_remember_by_path(PATH, true)?,
                "Network details saved for future connections."
            );
            {
                let s = h.state.lock().unwrap();
                assert_eq!(s.retention_flags, 0);
                assert!(s.active && !s.deleted);
                assert_eq!(s.update_flags, 1);
                assert_eq!(
                    text(
                        s.written.as_ref().unwrap(),
                        "802-1x",
                        "private-key-password"
                    )
                    .as_deref(),
                    Some("keep-private-key-password")
                );
            }
            assert_eq!(h.nm.saved_wifi_connections()?[0].remember, Some(true));

            h.state.lock().unwrap().active = false;
            assert_eq!(
                h.nm.set_connection_remember_by_path(PATH, false)?,
                "Saved network details deleted. Future connections won't be remembered."
            );
            assert!(h.nm.saved_wifi_connections()?.is_empty());
            Ok(())
        },
    )
}

#[test]
fn temporary_opt_in_preserves_guards_and_only_promotes_available_credentials() -> Result<()> {
    isolated(
        concat!(
            module_path!(),
            "::temporary_opt_in_preserves_guards_and_only_promotes_available_credentials"
        ),
        || {
            for failure in [
                "none", "read", "write", "race", "agent", "staged", "external", "version",
            ] {
                let h = Harness::new()?;
                {
                    let mut s = h.state.lock().unwrap();
                    s.retention_flags = if failure == "staged" { 1 } else { 5 };
                    s.dirty = true;
                    s.filename = if failure == "external" {
                        "/usr/lib/NetworkManager/system-connections/admin"
                    } else {
                        "/run/NetworkManager/system-connections/once"
                    }
                    .into();
                    s.public.get_mut("802-1x").unwrap().insert(
                        "password-flags".into(),
                        owned_value(if failure == "agent" { 3u32 } else { 6u32 })?,
                    );
                    s.fail_read = failure == "read";
                    s.fail_write = failure == "write";
                    s.race_read = failure == "race";
                    if failure == "version" {
                        s.nm_version = "1.60.0".into();
                    }
                }
                let result = h.nm.set_connection_remember_by_path(PATH, true);
                let s = h.state.lock().unwrap();
                if failure == "none" {
                    result?;
                    let saved = s.written.as_ref().unwrap();
                    assert_eq!(
                        flags(saved, "802-1x", "password")?,
                        4,
                        "NOT_REQUIRED survives explicit opt-in"
                    );
                    assert_eq!(
                        text(saved, "802-1x", "password").as_deref(),
                        Some("old-password")
                    );
                    assert_eq!(
                        setting::<&str>(&saved["802-1x"], "domain-suffix-match"),
                        Some("example.invalid")
                    );
                } else {
                    assert!(result.is_err(), "{failure}");
                    assert!(s.written.is_none(), "{failure}");
                    assert_eq!(s.writes, usize::from(failure == "write"), "{failure}");
                }
            }
            let h = Harness::new()?;
            h.state.lock().unwrap().fail_write = true;
            assert!(h.nm.set_connection_remember_by_path(PATH, false).is_err());
            assert_eq!(h.nm.saved_wifi_connections()?[0].remember, Some(true));
            Ok(())
        },
    )
}
