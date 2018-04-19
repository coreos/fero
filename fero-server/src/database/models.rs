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

use database::schema::{secrets, users, user_secret_weights};

#[derive(Queryable)]
pub struct SecretKey {
    pub id: i32,
    pub key_id: i64,
    pub threshold: i32,
    pub hsm_id: i32,
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

#[derive(Insertable)]
#[table_name = "secrets"]
pub struct NewSecret {
    pub key_id: i64,
    pub threshold: i32,
    pub hsm_id: i32,
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
