pub(crate) fn wifi_qr_payload(
    auth_type: &str,
    ssid: &str,
    password: Option<&str>,
    hidden: bool,
) -> String {
    let password = password
        .map(|password| format!(";P:{}", wifi_qr_value(password)))
        .unwrap_or_default();
    let hidden = if hidden { ";H:true" } else { "" };
    format!(
        "WIFI:T:{};S:{}{}{};;",
        auth_type,
        wifi_qr_value(ssid),
        password,
        hidden
    )
}

fn wifi_qr_value(value: &str) -> String {
    let escaped: String = value
        .chars()
        .flat_map(|ch| match ch {
            '\\' | ';' | ',' | ':' | '"' => vec!['\\', ch],
            ch => vec![ch],
        })
        .collect();
    if !value.is_empty() && value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        format!("\"{escaped}\"")
    } else {
        escaped
    }
}

#[cfg(test)]
mod tests {
    use super::wifi_qr_payload;

    #[test]
    fn quotes_hex_only_values_like_networkmanager_nmcli() {
        assert_eq!(
            wifi_qr_payload("WPA", "1234", Some(&"a".repeat(64)), false),
            format!("WIFI:T:WPA;S:\"1234\";P:\"{}\";;", "a".repeat(64))
        );
    }

    #[test]
    fn escapes_mecard_delimiters() {
        assert_eq!(
            wifi_qr_payload("WPA", "Cafe;Guest", Some("pass:word"), true),
            "WIFI:T:WPA;S:Cafe\\;Guest;P:pass\\:word;H:true;;"
        );
    }
}
