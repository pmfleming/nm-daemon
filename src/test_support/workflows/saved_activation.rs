use crate::nm::ConnectionSettings;
use crate::variant::value_map;
use anyhow::Result;

mod lifecycle;

fn saved_profile(flags: u32) -> Result<ConnectionSettings> {
    Ok(ConnectionSettings::from([
        (
            "connection".into(),
            value_map([
                ("id", "Example".into()),
                ("uuid", "saved-example".into()),
                ("type", "802-11-wireless".into()),
                ("interface-name", "test-wifi".into()),
            ])?,
        ),
        (
            "802-11-wireless".into(),
            value_map([
                ("ssid", b"Example".to_vec().into()),
                ("mode", "infrastructure".into()),
            ])?,
        ),
        (
            "802-11-wireless-security".into(),
            value_map([("key-mgmt", "wpa-psk".into()), ("psk-flags", flags.into())])?,
        ),
    ]))
}
