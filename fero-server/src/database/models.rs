use byteorder::{BigEndian, ByteOrder};
use chrono::naive::NaiveDateTime;
use rand::{self, Rng};
use sha2::{Sha256, Digest};

use database::schema::{fero_logs, hsm_logs, secrets, users, user_secret_weights};
use fero_proto::log;

#[derive(Queryable)]
pub struct SecretKey {
    pub id: i32,
    pub key_id: Option<i64>,
    pub threshold: i32,
    pub hsm_id: i32,
    pub name: String,
}

#[derive(Queryable)]
pub struct UserKey {
    pub id: i32,
    pub key_id: i64,
    pub key_data: Vec<u8>,
}

#[derive(Queryable)]
pub struct UserKeyWeight {
    pub id: i32,
    pub user_id: i32,
    pub secret_id: i32,
    pub weight: i32,
}

#[derive(Queryable)]
pub struct FeroLog {
    pub id: i32,
    pub request_type: log::OperationType,
    pub timestamp: NaiveDateTime,
    pub result: log::OperationResult,
    pub hsm_index_start: i32,
    pub hsm_index_end: i32,
    pub identification: Option<Vec<u8>>,
    pub hash: Vec<u8>,
}

#[derive(Queryable)]
pub struct HsmLog {
    pub id: i32,
    pub hsm_index: i32,
    pub command: i32,
    pub data_length: i32,
    pub session_key: i32,
    pub target_key: i32,
    pub second_key: i32,
    pub result: i32,
    pub systick: i32,
    pub hash: Vec<u8>,
}

#[derive(Insertable)]
#[table_name = "secrets"]
pub struct NewSecret {
    pub key_id: Option<i64>,
    pub threshold: i32,
    pub hsm_id: i32,
    pub name: String,
}

#[derive(Insertable)]
#[table_name = "users"]
pub struct NewUserKey<'a> {
    pub key_id: i64,
    pub key_data: &'a [u8],
}

#[derive(Insertable)]
#[table_name = "user_secret_weights"]
pub struct NewWeight {
    pub user_id: i32,
    pub secret_id: i32,
    pub weight: i32,
}

#[derive(Insertable)]
#[table_name = "fero_logs"]
pub struct NewFeroLog {
    pub request_type: log::OperationType,
    pub timestamp: NaiveDateTime,
    pub result: log::OperationResult,
    pub hsm_index_start: i32,
    pub hsm_index_end: i32,
    pub identification: Option<Vec<u8>>,
    pub hash: Vec<u8>,
}

impl Default for NewFeroLog {
    fn default() -> Self {
        let mut hasher = Sha256::default();
        let mut rng = rand::thread_rng();

        let mut buf = [0u8; 8];
        for _ in 0..4 {
            BigEndian::write_u64(&mut buf, rng.next_u64());
            hasher.input(&buf);
        }

        let hash: &[u8] = &hasher.result();

        NewFeroLog {
            request_type: log::OperationType::Sign,
            timestamp: NaiveDateTime::from_timestamp(0, 0),
            result: log::OperationResult::Success,
            hsm_index_start: 0,
            hsm_index_end: 0,
            identification: None,
            hash: Vec::from(hash),
        }
    }
}

#[derive(Insertable)]
#[table_name = "hsm_logs"]
pub struct NewHsmLog {
    pub hsm_index: i32,
    pub command: i32,
    pub data_length: i32,
    pub session_key: i32,
    pub target_key: i32,
    pub second_key: i32,
    pub result: i32,
    pub systick: i32,
    pub hash: Vec<u8>,
}
