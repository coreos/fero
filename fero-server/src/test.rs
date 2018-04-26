use libyubihsm::{ReturnCode, Session, Yubihsm};
use secstr::SecStr;
use tempfile::NamedTempFile;

use local;

const DEFAULT_CONNECTOR_URL: &str = "http://127.0.0.1:12345";

fn try_reset_device(sess: Session) -> bool {
    match sess.reset() {
        Ok(_) => true,
        Err(e) => match e.downcast::<ReturnCode>() {
            Ok(ReturnCode::NetError) => true,
            Ok(_) | Err(_) => false,
        },
    }
}

#[test]
fn provision() {
    let admin_password = "admin";
    let app_password = "application";
    let database_file = NamedTempFile::new().unwrap();

    local::provision(
        database_file.path().to_str().unwrap(),
        DEFAULT_CONNECTOR_URL,
        SecStr::from(admin_password),
        SecStr::from(app_password),
    ).unwrap();

    let yubihsm = Yubihsm::new().unwrap();
    let connector = yubihsm.connector().connect(DEFAULT_CONNECTOR_URL).unwrap();
    let admin_session = connector
        .create_session_from_password(2, admin_password, true)
        .unwrap();
    assert!(
        connector
            .create_session_from_password(3, app_password, true)
            .is_ok()
    );

    assert!(try_reset_device(admin_session), "Couldn't reset device after testing!");
}
