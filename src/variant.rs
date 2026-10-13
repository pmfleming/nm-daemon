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

/// Read strict D-Bus text; unlike `setting_text`, byte arrays are not accepted.
pub(crate) fn setting_string(section: &HashMap<String, OwnedValue>, key: &str) -> Option<String> {
    setting::<&str>(section, key).map(str::to_string)
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

/// Borrow string dictionary entries, rejecting the entire map on a bad key or
/// value, just like the owned conversion. In particular, never copy VPN secrets.
pub(crate) fn value_string_map(value: &OwnedValue) -> Option<HashMap<&str, &str>> {
    <&zvariant::Dict<'_, '_>>::try_from(value)
        .ok()?
        .iter()
        .map(|(key, value)| Some((key.downcast_ref().ok()?, value.downcast_ref().ok()?)))
        .collect()
}

/// NetworkManager's legacy settings also encode text as UTF-8 byte arrays.
/// Keep this distinct from strict string inspection (`value_string`).
pub(crate) fn setting_text(section: &HashMap<String, OwnedValue>, key: &str) -> Option<String> {
    section.get(key).and_then(value_text)
}

pub(crate) fn value_text(value: &OwnedValue) -> Option<String> {
    value_string(value).or_else(|| String::from_utf8(value_list(value)?).ok())
}

/// NM uses signed 32-bit values here; tolerate the older wider/unsigned forms
/// only when they fit, without truncating, parsing strings, or coercing booleans.
pub(crate) fn setting_i32(section: &HashMap<String, OwnedValue>, key: &str) -> Option<i32> {
    setting(section, key).or_else(|| {
        let wide =
            setting::<i64>(section, key).or_else(|| setting::<u32>(section, key).map(i64::from))?;
        wide.try_into().ok()
    })
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
    use super::{owned_value, setting_strings, value_list, value_string};

    #[test]
    fn settings_readers_preserve_legacy_text_and_checked_signed_integers() -> anyhow::Result<()> {
        use std::collections::HashMap;
        for (value, expected) in [
            (owned_value("text")?, Some("text")),
            (owned_value(b"text".to_vec())?, Some("text")),
            (owned_value(Vec::<u8>::new())?, Some("")),
            (owned_value(vec![0xff_u8])?, None),
            (owned_value(42_u32)?, None),
        ] {
            let strict = value_string(&value);
            let section = HashMap::from([("value".into(), value)]);
            assert_eq!(super::setting_string(&section, "value"), strict);
            assert_eq!(super::setting_text(&section, "value").as_deref(), expected);
        }
        for (value, expected) in [
            (owned_value(-1_i32)?, Some(-1)),
            (owned_value(0_i32)?, Some(0)),
            (owned_value(-1_i64)?, Some(-1)),
            (owned_value(42_u32)?, Some(42)),
            (owned_value(u32::MAX)?, None),
            (owned_value(i64::MIN)?, None),
            (owned_value("1")?, None),
            (owned_value(true)?, None),
        ] {
            assert_eq!(
                super::setting_i32(&HashMap::from([("value".into(), value)]), "value"),
                expected
            );
        }
        assert_eq!(super::setting_i32(&HashMap::new(), "missing"), None);
        assert_eq!(super::setting_text(&HashMap::new(), "missing"), None);
        Ok(())
    }

    #[test]
    fn container_readers_preserve_values_and_reject_wrong_or_mixed_types() -> anyhow::Result<()> {
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

        use std::collections::HashMap;
        for value in [
            owned_value(HashMap::from([
                ("password", "secret"),
                ("password-flags", "1"),
            ]))?,
            owned_value(HashMap::<String, String>::new())?,
            owned_value(HashMap::<u32, u32>::new())?,
            owned_value(HashMap::from([("key", Value::from("value"))]))?,
            owned_value(HashMap::from([
                ("good", Value::from("text")),
                ("bad", Value::from(1_u32)),
            ]))?,
            owned_value(HashMap::from([(1_u32, "bad key")]))?,
            owned_value("not a dictionary")?,
        ] {
            let expected = HashMap::<String, String>::try_from(value.try_clone()?).ok();
            let actual = super::value_string_map(&value).map(|entries| {
                entries
                    .into_iter()
                    .map(|(key, value)| (key.to_string(), value.to_string()))
                    .collect()
            });
            assert_eq!(actual, expected);
        }

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
}
