use failure::Error;
use num::BigUint;
use pretty_good::{Key, Packet};

use database;

pub(crate) fn find_subkey(packets_bytes: &[u8], subkey_id: &BigUint) -> Result<Key, Error> {
    let packets = Packet::all_from_bytes(&packets_bytes)?;
    let mut subkeys = packets.into_iter().filter_map(|packet| match packet {
        Packet::SecretKey(key) | Packet::SecretSubkey(key) => key.fingerprint()
            .map(|key_fingerprint| {
                if BigUint::from_bytes_be(&key_fingerprint) == *subkey_id {
                    Some(key)
                } else {
                    None
                }
            })
            .unwrap_or(None),
        _ => None,
    });

    let subkey = match subkeys.next() {
        Some(s) => s,
        None => bail!("Subkey {} was not found in given PGP key.", subkey_id),
    };

    if subkeys.next().is_some() {
        bail!("More than one matching subkey found. Is your PGP key valid?");
    }

    Ok(subkey)
}

pub(crate) fn store_key(
    database_url: &str,
    hsm_id: u16,
    key_id: u64,
    threshold: i32,
) -> Result<(), Error> {
    let database = database::Configuration::new(database_url);
    database.insert_secret_key(i32::from(hsm_id), key_id as i64, threshold)
}
