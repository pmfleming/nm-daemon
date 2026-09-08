use std::collections::HashMap;

use anyhow::{Context, Result};
use zvariant::{DynamicType, OwnedValue, Value};

pub(crate) fn owned_value<T>(value: T) -> Result<OwnedValue>
where
    T: Into<Value<'static>> + DynamicType,
{
    OwnedValue::try_from(Value::new(value)).context("create D-Bus variant value")
}

/// Encode a heterogeneous D-Bus dictionary without cloning its input values.
pub(crate) fn value_map<const N: usize>(
    values: [(&str, Value<'_>); N],
) -> Result<HashMap<String, OwnedValue>> {
    values
        .into_iter()
        .map(|(key, value)| Ok((key.to_string(), OwnedValue::try_from(value)?)))
        .collect::<Result<_>>()
        .context("create D-Bus variant dictionary")
}

/// Read a typed property by reference; a missing or differently typed value
/// remains absent rather than being coerced or cloned.
pub(crate) fn setting<'a, T>(section: &'a HashMap<String, OwnedValue>, key: &str) -> Option<T>
where
    T: TryFrom<&'a OwnedValue>,
{
    section.get(key)?.try_into().ok()
}

pub(crate) fn value_string(value: &OwnedValue) -> Option<String> {
    <&str>::try_from(value).ok().map(str::to_string)
}

pub(crate) fn insert_string(
    section: &mut HashMap<String, OwnedValue>,
    key: &str,
    value: &str,
) -> Result<()> {
    section.insert(key.to_string(), owned_value(value.to_string())?);
    Ok(())
}

pub(crate) fn insert_optional_string(
    section: &mut HashMap<String, OwnedValue>,
    key: &str,
    value: Option<&str>,
) -> Result<()> {
    if let Some(value) = value.filter(|value| !value.is_empty()) {
        insert_string(section, key, value)?;
    }
    Ok(())
}

pub(crate) fn insert_optional_strings(
    section: &mut HashMap<String, OwnedValue>,
    values: &[(&str, Option<&str>)],
) -> Result<()> {
    values
        .iter()
        .try_for_each(|(key, value)| insert_optional_string(section, key, *value))
}

pub(crate) fn insert_optional_value<T>(
    section: &mut HashMap<String, OwnedValue>,
    key: &str,
    value: Option<T>,
) -> Result<()>
where
    T: Into<Value<'static>> + DynamicType,
{
    if let Some(value) = value {
        section.insert(key.to_string(), owned_value(value)?);
    }
    Ok(())
}

pub(crate) fn insert_optional_u32s(
    section: &mut HashMap<String, OwnedValue>,
    values: &[(&str, Option<u32>)],
) -> Result<()> {
    values
        .iter()
        .try_for_each(|(key, value)| insert_optional_value(section, key, *value))
}

#[cfg(test)]
mod tests {
    use super::{setting, value_map, value_string};

    #[test]
    fn borrowed_dictionary_values_keep_their_dbus_types() -> anyhow::Result<()> {
        let text = String::from("Example");
        let bytes = [0, 0xff, 42];
        let values = value_map([
            ("text", text.as_str().into()),
            ("ssid", bytes.as_slice().into()),
            ("enabled", true.into()),
            ("channel", 36_u32.into()),
            ("protocols", vec!["rsn"].into()),
        ])?;
        drop(text);
        assert_eq!(value_string(&values["text"]).as_deref(), Some("Example"));
        assert_eq!(value_string(&values["channel"]), None);
        assert_eq!(setting::<u32>(&values, "channel"), Some(36));
        assert_eq!(setting::<bool>(&values, "enabled"), Some(true));
        assert_eq!(setting::<bool>(&values, "channel"), None);
        assert_eq!(setting::<u32>(&values, "missing"), None);
        assert_eq!(Vec::<u8>::try_from(values["ssid"].try_clone()?)?, bytes);
        assert_eq!(
            Vec::<String>::try_from(values["protocols"].try_clone()?)?,
            ["rsn"]
        );
        Ok(())
    }
}
