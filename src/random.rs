//! Cryptographically secure randomness for generated hotspot credentials.
//!
//! The kernel CSPRNG is read directly so no additional dependency is needed and
//! generated secrets never come from a predictable source.

use std::fs::File;
use std::io::Read;

use anyhow::{Context, Result, bail};

/// Alphabet without characters that are easily confused when a passphrase is
/// read off a screen and typed on another device.
const PASSPHRASE_ALPHABET: &[u8] = b"abcdefghijkmnopqrstuvwxyz23456789";

pub(crate) fn random_bytes(len: usize) -> Result<Vec<u8>> {
    let mut buffer = vec![0_u8; len];
    File::open("/dev/urandom")
        .context("open /dev/urandom")?
        .read_exact(&mut buffer)
        .context("read /dev/urandom")?;
    Ok(buffer)
}

/// Uniformly samples the passphrase alphabet using rejection sampling, so the
/// generated secret has no modulo bias.
pub(crate) fn random_passphrase(len: usize) -> Result<String> {
    if len == 0 {
        bail!("passphrase length must be positive");
    }
    let alphabet_len = PASSPHRASE_ALPHABET.len() as u8;
    let limit = u8::MAX - (u8::MAX % alphabet_len);
    let mut passphrase = String::with_capacity(len);
    while passphrase.len() < len {
        for byte in random_bytes(len * 2)? {
            if byte >= limit {
                continue;
            }
            passphrase.push(PASSPHRASE_ALPHABET[usize::from(byte % alphabet_len)] as char);
            if passphrase.len() == len {
                break;
            }
        }
    }
    Ok(passphrase)
}

pub(crate) fn random_uuid_v4() -> Result<String> {
    let mut bytes = random_bytes(16)?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    ))
}

#[cfg(test)]
mod tests {
    use super::{PASSPHRASE_ALPHABET, random_passphrase, random_uuid_v4};

    #[test]
    fn passphrases_use_the_unambiguous_alphabet_and_requested_length() {
        let passphrase = random_passphrase(16).expect("passphrase");
        assert_eq!(passphrase.len(), 16);
        assert!(
            passphrase
                .bytes()
                .all(|byte| PASSPHRASE_ALPHABET.contains(&byte))
        );
        assert_ne!(passphrase, random_passphrase(16).expect("passphrase"));
    }

    #[test]
    fn zero_length_passphrases_are_rejected_rather_than_returning_an_empty_secret() {
        assert!(random_passphrase(0).is_err());
    }

    #[test]
    fn uuids_are_version_4_variant_1_and_unique() {
        let uuid = random_uuid_v4().expect("uuid");
        assert_eq!(uuid.len(), 36);
        assert_eq!(&uuid[14..15], "4");
        assert!(["8", "9", "a", "b"].contains(&&uuid[19..20]));
        assert_ne!(uuid, random_uuid_v4().expect("uuid"));
    }
}
