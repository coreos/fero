use std::os::unix::ffi::OsStrExt;
use std::thread;
use std::time::Duration;

use failure::Error;
use libyubihsm::{ReturnCode, Yubihsm};
use secstr::SecStr;
use tempfile::NamedTempFile;

use local;

const DEFAULT_CONNECTOR_URL: &str = "http://127.0.0.1:12345";
const ADMIN_PASSWORD: &str = "admin";
const APP_PASSWORD: &str = "application";

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
