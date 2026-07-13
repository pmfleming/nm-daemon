use anyhow::{Result, bail};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};
use zvariant::OwnedObjectPath;

use super::{display_ssid, validate_bssid, validate_ssid_bytes};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Ssid {
    bytes: Vec<u8>,
    display: String,
}

impl Ssid {
    pub(crate) fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        validate_ssid_bytes(&bytes)?;
        let display = display_ssid(&bytes);
        Ok(Self { bytes, display })
    }

    pub(crate) fn from_display(display: String) -> Result<Self> {
        Self::from_bytes(display.into_bytes())
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.display
    }
}

impl std::fmt::Display for Ssid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.display)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub(crate) struct Bssid(String);

impl Bssid {
    pub(crate) fn parse(value: String) -> Result<Self> {
        validate_bssid(&value)?;
        Ok(Self(value.replace('-', ":").to_ascii_uppercase()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::ops::Deref for Bssid {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl std::fmt::Display for Bssid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Bssid {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

impl std::str::FromStr for Bssid {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        Self::parse(value.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub(crate) struct InterfaceName(String);

impl InterfaceName {
    pub(crate) fn parse(value: String) -> Result<Self> {
        if value.is_empty()
            || value.len() > 15
            || value
                .chars()
                .any(|character| character.is_whitespace() || matches!(character, '/' | '\0'))
        {
            bail!("invalid network interface name '{value}'");
        }
        Ok(Self(value))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::ops::Deref for InterfaceName {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl std::fmt::Display for InterfaceName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for InterfaceName {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

impl std::str::FromStr for InterfaceName {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        Self::parse(value.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub(crate) struct NmObjectPath(String);

impl NmObjectPath {
    pub(crate) fn parse(value: String) -> Result<Self> {
        OwnedObjectPath::try_from(value.as_str())
            .map_err(anyhow::Error::from)
            .map(|_| Self(value))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::ops::Deref for NmObjectPath {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl std::fmt::Display for NmObjectPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for NmObjectPath {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

impl std::str::FromStr for NmObjectPath {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        Self::parse(value.to_string())
    }
}
