pub(crate) fn wifi_qr_payload(
    auth_type: &str,
    ssid: &str,
    password: Option<&str>,
    hidden: bool,
) -> String {
    let password = password
        .map(|password| format!(";P:{}", wifi_qr_escape(password)))
        .unwrap_or_default();
    let hidden = if hidden { ";H:true" } else { "" };
    format!(
        "WIFI:T:{};S:{}{}{};;",
        auth_type,
        wifi_qr_escape(ssid),
        password,
        hidden
    )
}

fn wifi_qr_escape(value: &str) -> String {
    value
        .chars()
        .flat_map(|ch| match ch {
            '\\' | ';' | ',' | ':' | '"' => vec!['\\', ch],
            ch => vec![ch],
        })
        .collect()
}
