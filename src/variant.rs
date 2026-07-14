use std::collections::HashMap;

use anyhow::{Context, Result};
use zvariant::{DynamicType, OwnedValue, Value};

pub(crate) fn owned_value<T>(value: T) -> Result<OwnedValue>
where
    T: Into<Value<'static>> + DynamicType,
{
    OwnedValue::try_from(Value::new(value)).context("create D-Bus variant value")
}

pub(crate) fn value_string(value: &OwnedValue) -> Option<String> {
    String::try_from(value.clone()).ok()
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

pub(crate) fn insert_optional_u32(
    section: &mut HashMap<String, OwnedValue>,
    key: &str,
    value: Option<u32>,
) -> Result<()> {
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
        .try_for_each(|(key, value)| insert_optional_u32(section, key, *value))
}
