pub(crate) fn classify_error(message: &str) -> &'static str {
    let lower = message.to_lowercase();
    if contains_any(
        &lower,
        &[
            "parse",
            "invalid",
            "requires",
            "validation",
            "bad",
            "missing field",
        ],
    ) {
        "validation-error"
    } else if contains_any(
        &lower,
        &["networkmanager", "network manager", "d-bus", "dbus"],
    ) {
        "networkmanager-unavailable"
    } else if contains_any(&lower, &["permission", "authorization", "not authorized"]) {
        "authorization-required"
    } else if contains_any(&lower, &["not found", "no such"]) {
        "not-found"
    } else if contains_any(&lower, &["timeout", "timed out"]) {
        "timeout"
    } else {
        "internal-error"
    }
}

fn contains_any(value: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| value.contains(needle))
}
