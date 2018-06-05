use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::thread;
use std::time::Duration;

use failure::Error;
use gpgme::{Context, CreateKeyFlags, ExportMode, Protocol};
use libyubihsm::{ReturnCode, Yubihsm};
use num::BigUint;
use pretty_good::Packet;
use protobuf::repeated::RepeatedField;
use secstr::SecStr;
use tempfile::{NamedTempFile, TempDir};

use database::Configuration;
use fero_proto::fero::*;
use hsm;
use local;
use service::FeroService;

const DEFAULT_CONNECTOR_URL: &str = "http://127.0.0.1:12345";
const ADMIN_PASSWORD: &str = "admin";
const APP_PASSWORD: &str = "application";

/// The data and keys required to run a test. It is assumed that each valid user has a weight of 1
/// for the specified secret, and so at least `n` valid users are required to successfully perform
/// an operation with a `threshold` of `n`.
struct TestEnvironment {
    directory: TempDir,
    secret_id: u64,
    valid_users: Vec<u64>,
    invalid_users: Vec<u64>,
    fero_service: FeroService,
}

/// Attempt to provision the device and database with known credentials:
/// * Admin authkey (id 2) with password ADMIN_PASSWORD
/// * Application authkey (id 3) with password APP_PASSWORD
/// * Database located at `database_file`
fn do_provision(database_path: &str) -> Result<(), Error> {
    local::provision(
        database_path,
        DEFAULT_CONNECTOR_URL,
        SecStr::from(ADMIN_PASSWORD),
        SecStr::from(APP_PASSWORD),
    )?;

    Ok(())
}

/// Attempt to reset the device at the conclusion of a test. This should not fail, as it is only
/// called after the successful completion of a test.
fn try_reset_device() -> bool {
    let yubihsm = Yubihsm::new().unwrap();
    let connector = yubihsm.connector().connect(DEFAULT_CONNECTOR_URL).unwrap();
    let sess = connector
        .create_session_from_password(2, ADMIN_PASSWORD, true)
        .unwrap();

    match sess.reset() {
        Ok(_) => true,
        Err(e) => match e.downcast::<ReturnCode>() {
            Ok(ReturnCode::NetError) => {
                thread::sleep(Duration::from_millis(1000));
                true
            }
            Ok(_) | Err(_) => false,
        },
    }
}

/// Create and export to disk a single GPG key.
fn create_gpg_key(gpg: &mut Context, tmpdir: &TempDir, uid: &str) -> Result<NamedTempFile, Error> {
    let gpg_key = gpg.create_key_with_flags(uid, "RSA", None, CreateKeyFlags::NOPASSWD)?;
    let gpg_key = gpg.find_key(gpg_key.fingerprint_raw().unwrap())?;

    let mut gpg_key_data: Vec<u8> = Vec::new();
    gpg.export_keys(&[gpg_key], ExportMode::SECRET, &mut gpg_key_data)?;

    let mut tmpfile = NamedTempFile::new_in(tmpdir.path())?;
    tmpfile.as_file_mut().write_all(&gpg_key_data)?;

    Ok(tmpfile)
}

/// Set up the environment for a single test. The resulting configuration will have a single secret
/// stored in fero with the specified threshold, and will have the specified number of valid users
/// (each with a weight of 1) for the secret, and the specified number of invalid users.
fn setup_environment(
    threshold: i32,
    num_valid_users: usize,
    num_invalid_users: usize,
) -> Result<TestEnvironment, Error> {
    let directory = TempDir::new()?;
    let database_path_owned = directory.path().join("fero.db");
    let database_path = database_path_owned.to_str().unwrap();
    do_provision(database_path)?;

    let hsm = hsm::Hsm::new(DEFAULT_CONNECTOR_URL, 3, APP_PASSWORD)?;

    let mut gpg = Context::from_protocol(Protocol::OpenPgp)?;
    gpg.set_engine_home_dir(directory.path().as_os_str().as_bytes())?;

    let secret_gpg_key = create_gpg_key(&mut gpg, &directory, "Fero Test Secret")?;
    let mut secret_gpg_key_data = Vec::new();
    File::open(secret_gpg_key.path())?.read_to_end(&mut secret_gpg_key_data)?;
    let secret_id = match Packet::from_bytes(&secret_gpg_key_data)? {
        (Packet::SecretKey(key), _) => {
            local::import_secret(
                &hsm,
                secret_gpg_key.path(),
                &BigUint::from_bytes_be(&key.fingerprint()?),
                database_path,
                threshold,
            )?;

            key.id()?
        }
        _ => panic!("Exported GPG key didn't contain a SecretKey!"),
    };

    let valid_users = (0..num_valid_users)
        .map(|i| {
            let gpg_key = create_gpg_key(&mut gpg, &directory, &format!("Fero User {}", i))?;
            let mut key_bytes = Vec::new();
            File::open(gpg_key.path())?.read_to_end(&mut key_bytes)?;
            let key_id = local::find_keyid(&key_bytes)?;

            local::store_user(database_path, key_id, &key_bytes)?;
            local::set_user_weight(database_path, key_id, secret_id, 1)?;

            Ok(key_id)
        })
        .collect::<Result<Vec<_>, Error>>()?;

    let invalid_users = (0..num_invalid_users)
        .map(|i| {
            let gpg_key = create_gpg_key(&mut gpg, &directory, &format!("Invalid User {}", i))?;
            let mut key_bytes = Vec::new();
            File::open(gpg_key.path())?.read_to_end(&mut key_bytes)?;
            let key_id = local::find_keyid(&key_bytes)?;

            Ok(key_id)
        })
        .collect::<Result<Vec<_>, Error>>()?;

    let fero_service = FeroService::new(Configuration::new(database_path), hsm);

    Ok(TestEnvironment {
        directory,
        secret_id,
        valid_users,
        invalid_users,
        fero_service,
    })
}

#[test]
fn provision() {
    let database_file = NamedTempFile::new().unwrap();

    do_provision(database_file.path().to_str().unwrap()).unwrap();

    let yubihsm = Yubihsm::new().unwrap();
    let connector = yubihsm.connector().connect(DEFAULT_CONNECTOR_URL).unwrap();
    assert!(
        connector
            .create_session_from_password(3, APP_PASSWORD, true)
            .is_ok()
    );

    assert!(try_reset_device(), "Couldn't reset device after testing!");
}

#[test]
fn sign() {
    let env = setup_environment(1, 1, 0).unwrap();

    let artifact = "Test payload. This should be signed successfully.".as_bytes();

    let mut gpg = Context::from_protocol(Protocol::OpenPgp).unwrap();
    gpg.set_engine_home_dir(env.directory.path().as_os_str().as_bytes())
        .unwrap();

    let mut signature = Vec::new();
    let signer = gpg.find_key(format!("{:x}", env.valid_users[0])).unwrap();
    gpg.add_signer(&signer).unwrap();
    gpg.sign_detached(artifact, &mut signature).unwrap();

    let mut ident = Identification::new();
    ident.set_secretKeyId(env.secret_id);
    ident.set_signatures(RepeatedField::from_vec(vec![signature]));

    let output = env.fero_service.sign_payload(&ident, artifact).unwrap();

    let signatures = gpg.verify_detached(&output, artifact).unwrap();
    let signature = signatures.signatures().next().unwrap();
    assert_eq!(
        signature.fingerprint_raw().unwrap(),
        gpg.find_key(format!("{:x}", env.secret_id))
            .unwrap()
            .fingerprint_raw()
            .unwrap()
    );

    assert!(try_reset_device(), "Couldn't reset device after testing!");
}
