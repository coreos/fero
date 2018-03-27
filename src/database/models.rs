use database::schema::{secrets, users, user_secret_weights};

#[derive(Queryable)]
pub struct SecretKey {
    pub id: i32,
    pub key_id: i64,
    pub threshold: i32,
}

#[derive(Queryable)]
pub struct UserKey {
    pub id: i32,
    pub key_id: i64,
}

#[derive(Queryable)]
pub struct UserKeyWeight {
    pub id: i32,
    pub user_id: i32,
    pub secret_id: i32,
    pub weight: i32,
}

#[derive(Insertable)]
#[table_name = "secrets"]
pub struct NewSecret {
    pub key_id: i64,
    pub threshold: i32,
}

#[derive(Insertable)]
#[table_name = "users"]
pub struct NewUserKey {
    pub key_id: i64,
}

#[derive(Insertable)]
#[table_name = "user_secret_weights"]
pub struct NewWeight {
    pub user_id: i32,
    pub secret_id: i32,
    pub weight: i32,
}
