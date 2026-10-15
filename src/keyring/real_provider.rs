//! Run only via test_support/keyring-provider.py (private bus, display and HOME).
use super::{Keyring, KeyringOutcome, SECRET_SERVICE_PATH, prompts};
use crate::nm::ConnectionSettings;
use crate::variant::owned_value;
use anyhow::{Context, Result, ensure};
use std::collections::HashMap;
use std::process::Command;
use std::time::{Duration, Instant};
use zbus::blocking::Proxy;
use zvariant::OwnedObjectPath;

#[test]
#[ignore = "requires isolated GNOME keyring + Gcr + Xvfb; use test_support/keyring-provider.py"]
fn timeout_cancel_and_provider_exit_preserve_real_keyring() -> Result<()> {
    ensure!(
        std::env::var("NM_KEYRING_SANDBOX").as_deref() == Ok("1"),
        "sandbox runner required"
    );
    ensure!(
        !std::path::Path::new("/run/dbus/system_bus_socket").exists(),
        "host bus must not be mounted"
    );
    let keyring = Keyring::new()?;
    // Deterministic fixture creation, using GNOME's internal test/PAM API only
    // inside the sandbox. The production client still uses standard Secret Service.
    let internal = Proxy::new(
        &keyring.client.connection,
        keyring.client.destination.as_str(),
        SECRET_SERVICE_PATH,
        "org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface",
    )?;
    let properties = HashMap::from([(
        "org.freedesktop.Secret.Collection.Label".to_string(),
        owned_value("Login")?,
    )]);
    let master = (
        &keyring.client.session,
        &[] as &[u8],
        b"synthetic-keyring-master".as_slice(),
        "text/plain",
    );
    let created: OwnedObjectPath =
        internal.call("CreateWithMasterPassword", &(properties, master))?;
    keyring
        .client
        .service_proxy()?
        .call::<_, _, ()>("SetAlias", &("default", &created))?;
    let settings = ConnectionSettings::from([(
        "connection".into(),
        crate::variant::value_map([
            ("uuid", "isolated-real-provider-test".into()),
            ("id", "Synthetic test".into()),
        ])?,
    )]);
    ensure!(matches!(
        keyring.store_secret(
            "/test",
            &settings,
            "802-11-wireless-security",
            "psk",
            "synthetic-wifi-password"
        )?,
        KeyringOutcome::Completed(())
    ));
    let collection = keyring.client.collection()?;
    let lock = || -> Result<()> {
        let _: (Vec<OwnedObjectPath>, OwnedObjectPath) = keyring
            .client
            .service_proxy()?
            .call("Lock", &(vec![collection.clone()],))?;
        Ok(())
    };
    lock()?;
    ensure!(matches!(
        keyring.lookup_secrets(
            "/test",
            &settings,
            "802-11-wireless-security",
            &["psk".into()]
        )?,
        KeyringOutcome::PromptUnsupported { .. }
    ));
    let unlock = || {
        prompts::unlock(
            &keyring.client.connection,
            &keyring.client.destination,
            vec![collection.clone()],
            Duration::from_millis(500),
        )
    };
    ensure!(
        unlock().unwrap_err().to_string().contains("timed out"),
        "must exercise a live, unanswered prompt"
    );
    for _ in 0..5 {
        let start = Instant::now();
        ensure!(unlock().is_err());
        ensure!(
            start.elapsed() < Duration::from_millis(100),
            "pending unlock was not coalesced"
        );
    }
    // Cancel through the actual GTK dialog, not Secret.Service.Prompt.Dismiss.
    let deadline = Instant::now() + Duration::from_secs(10);
    let window = loop {
        let output = Command::new("xdotool")
            .args(["search", "--onlyvisible", "--class", "gcr-prompter"])
            .output()?;
        if output.status.success() {
            break String::from_utf8(output.stdout)?
                .lines()
                .next()
                .context("prompt has no window")?
                .to_owned();
        }
        ensure!(
            Instant::now() < deadline,
            "real Gcr unlock dialog did not appear"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    ensure!(
        Command::new("xdotool")
            .args(["windowfocus", "--sync", &window, "key", "Escape"])
            .status()?
            .success()
    );
    wait_monitor(&keyring)?;
    // Provider is alive and the secret survives a fresh client session after timeout/cancel.
    internal.call_method("UnlockWithMasterPassword", &(&created, master))?;
    let fresh = Keyring::new()?;
    let KeyringOutcome::Completed(values) = fresh.lookup_secrets(
        "/new/path",
        &settings,
        "802-11-wireless-security",
        &["psk".into()],
    )?
    else {
        anyhow::bail!("saved secret missing after timeout")
    };
    ensure!(values.len() == 1 && values[0].password == "synthetic-wifi-password");
    lock()?;
    ensure!(unlock().unwrap_err().to_string().contains("timed out"));
    // Exit the isolated provider while its prompt is still live; monitor must release its slot.
    let pid: i32 = std::env::var("NM_KEYRING_TEST_PID")?.parse()?;
    rustix::process::kill_process(
        rustix::process::Pid::from_raw(pid).context("invalid test pid")?,
        rustix::process::Signal::TERM,
    )?;
    wait_monitor(&keyring)?;
    std::fs::write("/tmp/home/real-provider-completed", "ok")?;
    Ok(())
}

fn wait_monitor(keyring: &Keyring) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(5);
    while prompts::is_pending(&keyring.client.connection, &keyring.client.destination) {
        ensure!(Instant::now() < deadline, "unlock monitor did not retire");
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}
