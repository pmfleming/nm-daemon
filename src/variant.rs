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

/// Decode a whole string array, including variant-wrapped elements, without
/// cloning the D-Bus container. A malformed element invalidates the whole list.
pub(crate) fn setting_strings(section: &HashMap<String, OwnedValue>, key: &str) -> Vec<String> {
    section.get(key).and_then(value_list).unwrap_or_default()
}

/// Decode elements by reference, allocating only the output list, not a copy
/// of the D-Bus container. As with zvariant's owned conversion, one invalid
/// element rejects the entire list (including variant-wrapped elements).
pub(crate) fn value_list<'a, T>(value: &'a OwnedValue) -> Option<Vec<T>>
where
    T: TryFrom<&'a Value<'a>>,
    T::Error: Into<zvariant::Error>,
{
    <&zvariant::Array<'_>>::try_from(value)
        .ok()?
        .inner()
        .iter()
        .map(Value::downcast_ref)
        .collect::<Result<_, _>>()
        .ok()
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

pub(crate) fn insert_optional_values<'a, T>(
    section: &mut HashMap<String, OwnedValue>,
    values: impl IntoIterator<Item = (&'a str, Option<T>)>,
) -> Result<()>
where
    T: Into<Value<'static>> + DynamicType,
{
    values
        .into_iter()
        .try_for_each(|(key, value)| insert_optional_value(section, key, value))
}

#[cfg(test)]
mod tests {
    use super::{owned_value, setting, setting_strings, value_list, value_map, value_string};

    #[test]
    fn borrowed_string_arrays_preserve_owned_conversion_semantics() -> anyhow::Result<()> {
        use zvariant::Value;
        for value in [
            owned_value(vec!["rsn", "wpa"])?,
            owned_value(Vec::<String>::new())?,
            owned_value(vec![1_u32])?,
            owned_value("not an array")?,
            owned_value(vec![Value::from("rsn"), Value::from("wpa")])?,
            owned_value(vec![Value::from("rsn"), Value::from(1_u32)])?,
        ] {
            let expected = Vec::<String>::try_from(value.try_clone()?).unwrap_or_default();
            let values = std::collections::HashMap::from([("value".into(), value)]);
            assert_eq!(setting_strings(&values, "value"), expected);
            assert!(setting_strings(&values, "missing").is_empty());
        }
        Ok(())
    }

    #[test]
    fn borrowed_byte_arrays_preserve_owned_conversion_semantics() -> anyhow::Result<()> {
        for value in [
            owned_value(vec![0_u8, 0xff])?,
            owned_value(Vec::<u8>::new())?,
            owned_value(vec![1_u32])?,
            owned_value("not bytes")?,
            owned_value(vec![
                zvariant::Value::from(1_u8),
                zvariant::Value::from(2_u8),
            ])?,
            owned_value(vec![
                zvariant::Value::from(1_u8),
                zvariant::Value::from("bad"),
            ])?,
        ] {
            assert_eq!(
                value_list::<u8>(&value),
                Vec::<u8>::try_from(value.try_clone()?).ok()
            );
        }
        Ok(())
    }

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
