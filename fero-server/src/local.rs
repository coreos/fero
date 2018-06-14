// Copyright 2018 CoreOS, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::fs::File;
use std::io::Read;
use std::mem::drop;
use std::path::Path;
use std::str;
use std::thread;
use std::time::{Duration, Instant};

use diesel::{sqlite::SqliteConnection, Connection};
use diesel_migrations::run_pending_migrations;
use failure::Error;
use gag::Gag;
use libyubihsm::{Capability, ObjectType, ReturnCode, Yubihsm};
use num::BigUint;
use pretty_good::{Key, Packet};
use secstr::SecStr;

use database;
use fero_proto::log::*;
use hsm::Hsm;
use logging;

const DEFAULT_HSM_AUTHKEY_ID: u16 = 1;
const DEFAULT_HSM_PASSWORD: &'static str = "password";

pub(crate) struct LocalIdentification {
    pub(crate) secret_key: u64,
    _priv: (),
}

pub(crate) fn find_secret_subkey(packets_bytes: &[u8], subkey_id: &BigUint) -> Result<Key, Error> {
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

pub(crate) fn find_keyid(packets_bytes: &[u8]) -> Result<u64, Error> {
    let packets = Packet::all_from_bytes(&packets_bytes)?;
    let key_id = packets
        .into_iter()
        .filter_map(|packet| match packet {
            Packet::PublicKey(key)
            | Packet::PublicSubkey(key)
            | Packet::SecretKey(key)
            | Packet::SecretSubkey(key) => Some(key.id()),
            _ => None,
        })
        .next();

    key_id.ok_or(format_err!("No key ID found"))?
}

pub(crate) fn store_key(
    database: &database::Configuration,
    hsm_id: u16,
    key_id: u64,
    threshold: i32,
) -> Result<(), Error> {
    database.insert_secret_key(i32::from(hsm_id), key_id as i64, threshold)
}

pub(crate) fn import_secret(
    hsm: &Hsm,
    filename: &Path,
    subkey: &BigUint,
    database: &str,
    threshold: i32,
) -> Result<(), Error> {
    let mut key_bytes = Vec::new();
    File::open(filename)?.read_to_end(&mut key_bytes)?;
    let subkey = find_secret_subkey(&key_bytes, subkey)?;

    let db_conf = database::Configuration::new(database);

    let interior_result = hsm
        .put_rsa_key(&subkey)
        .and_then(|hsm_id| store_key(&db_conf, hsm_id, subkey.id()?, threshold));

    match interior_result {
        Ok(_) => logging::log_operation(
            hsm,
            &db_conf,
            OperationType::AddSecret,
            OperationResult::Success,
            None,
        ),
        Err(_) => logging::log_operation(
            hsm,
            &db_conf,
            OperationType::AddSecret,
            OperationResult::Failure,
            None,
        ),
    }.unwrap_or_else(|e| panic!("Failed to log operation: {}", e));

    interior_result
}

pub(crate) fn store_user(hsm: &Hsm, database_url: &str, key_id: u64, key: &[u8]) -> Result<(), Error> {
    let database = database::Configuration::new(database_url);
    let interior_result = database.insert_user_key(key_id, key);

    match interior_result {
        Ok(_) => logging::log_operation(
            hsm,
            &database,
            OperationType::AddUser,
            OperationResult::Success,
            None,
        ),
        Err(_) => logging::log_operation(
            hsm,
            &database,
            OperationType::AddUser,
            OperationResult::Failure,
            None,
        ),
    }.unwrap_or_else(|e| panic!("Failed to log operation: {}", e));

    interior_result
}

pub(crate) fn set_user_weight(
    database_url: &str,
    user_key: u64,
    secret_key: u64,
    weight: i32,
) -> Result<(), Error> {
    let database = database::Configuration::new(database_url);
    let authed_database = database.local_authenticate(LocalIdentification {
        secret_key,
        _priv: (),
    })?;

    let user_key_obj = authed_database
        .get_user_key(user_key)?
        .ok_or(format_err!("No such user"))?;

    authed_database.upsert_user_key_weight(secret_key, user_key_obj, weight)
}

pub(crate) fn provision(
    database_url: &str,
    hsm_connector_url: &str,
    admin_authkey_password: SecStr,
    app_authkey_password: SecStr,
) -> Result<(), Error> {
    File::create(database_url)?;
    let conn = SqliteConnection::establish(database_url)?;

    // Diesel likes to shout about each migration as it performs them. This is espcially obnoxious
    // in `cargo test`, since a new database is provisioned for each test, so use `Gag` here to
    // shut Diesel up.
    let gag = Gag::stdout()?;
    run_pending_migrations(&conn)?;
    drop(gag);

    info!("Created and migrated database.");

    let yubihsm = Yubihsm::new()?;
    let connector = yubihsm.connector().connect(hsm_connector_url)?;
    let session = connector.create_session_from_password(
        DEFAULT_HSM_AUTHKEY_ID,
        DEFAULT_HSM_PASSWORD,
        true
    )?;
    // As soon as the YubiHSM tries to reset, it reboots and vanishes out from underneath the
    // connector, which dutifully reports this as a NetError. If we receive a NetError here, ignore
    // it.
    if let Err(e) = session.reset() {
        match e.downcast::<ReturnCode>() {
            Ok(ReturnCode::NetError) => {}
            Ok(other) => bail!(other),
            Err(cast_e) => bail!(cast_e),
        }
    };

    // It takes the device a bit to reboot, so retry the connection until it succeeds.
    let mut backoff_ms = 15;
    let reconnect_start = Instant::now();
    let connector = loop {
        match yubihsm.connector().connect(hsm_connector_url) {
            Ok(connector) => break Ok(connector),
            Err(e) => {
                if reconnect_start.elapsed().as_secs() > 5 {
                    break Err(e);
                }
                thread::sleep(Duration::from_millis(backoff_ms));
                backoff_ms *= 2;
            }
        };
    }?;

    let session = connector.create_session_from_password(1, "password", true)?;
    let default_authkey = session.get_object_info(1, ObjectType::AuthKey)?;
    session.create_authkey(
        2,
        "fero_admin",
        &default_authkey.domains,
        &default_authkey.capabilities,
        &default_authkey.delegated_capabilities,
        str::from_utf8(&admin_authkey_password.unsecure())?,
    )?;
    info!("Created admin AuthKey with object ID 2.");
    session.create_authkey(
        3,
        "fero_app",
        &default_authkey.domains,
        &[
            Capability::PutAsymmetric,
            Capability::GetOption,
            Capability::PutOption,
            Capability::Audit,
            Capability::AsymmetricSignPkcs,
        ],
        &[Capability::AsymmetricSignPkcs],
        str::from_utf8(&app_authkey_password.unsecure())?,
    )?;
    info!("Created application AuthKey with object ID 3.");
    session.delete_object(1, ObjectType::AuthKey)?;
    info!("Deleted default AuthKey.");

    Ok(())
}
