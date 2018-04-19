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

mod models;
mod schema;

use std::collections::HashSet;
use std::os::unix::ffi::OsStrExt;

use diesel::{self, Connection};
use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use failure::Error;
use gpgme::{Context, Protocol};
use tempfile::TempDir;

use fero_proto::fero::*;
use self::models::*;

#[derive(Clone)]
pub struct Configuration {
    connection_string: String,
}

impl Configuration {
    pub fn new(connection_string: &str) -> Configuration {
        Configuration { connection_string: connection_string.to_string() }
    }

    pub fn authenticate(
        &self,
        ident: &Identification,
        payload: &[u8],
    ) -> Result<(AuthenticatedConnection, Vec<u8>), Error> {
        let conn = SqliteConnection::establish(&self.connection_string)?;

        let secret = schema::secrets::dsl::secrets
            .filter(schema::secrets::columns::key_id.eq(ident.secretKeyId as i64))
            .load::<SecretKey>(&conn)?
            .pop()
            .ok_or(format_err!("No secret key found ({})", ident.secretKeyId))?;

        let applicable_users = schema::users::table
            .select(schema::users::all_columns)
            .inner_join(schema::user_secret_weights::table)
            .filter(schema::user_secret_weights::columns::secret_id.eq(secret.id))
            .load::<UserKey>(&conn)?;

        let mut gpg = Context::from_protocol(Protocol::OpenPgp)?;
        let gpg_homedir = TempDir::new()?;
        gpg.set_engine_home_dir(gpg_homedir.path().as_os_str().as_bytes())?;

        for user in applicable_users {
            gpg.import(user.key_data)?;
        }

        let mut ids = HashSet::new();
        for signature in &ident.signatures {
            let mut data = Vec::new();
            let verification = gpg.verify_opaque(signature, &mut data)?;

            // TODO can verify_opaque verify the payload?
            if data != payload {
                continue;
            }

            for signature in verification.signatures() {
                // It seems gpgme is not filling in the .key() field here, so we retrieve it from
                // gpgme via the fingerprint of the signature.
                if let Ok(signing_key) = gpg.find_key(signature.fingerprint().unwrap()) {
                    ids.insert(u64::from_str_radix(signing_key.id().unwrap(), 16)? as i64);
                }
                // TODO
                //ids.insert(signature.key().unwrap().primary_key().unwrap().id().chain_err(|| "Failed to read key id")?);
            }
        }

        let mut weight = 0;
        for id in ids {
            // TODO use JOIN
            if let Some(user) = schema::users::dsl::users
                .filter(schema::users::columns::key_id.eq(id))
                .load::<UserKey>(&conn)?
                .pop() {
                weight += schema::user_secret_weights::dsl::user_secret_weights
                    .filter(schema::user_secret_weights::columns::secret_id.eq(
                        secret.id,
                    ))
                    .filter(schema::user_secret_weights::columns::user_id.eq(user.id))
                    .load::<UserKeyWeight>(&conn)?
                    .pop()
                    .map(|w| w.weight)
                    .unwrap_or(0)
            }

        }

        if weight >= secret.threshold {
            Ok((AuthenticatedConnection { connection: conn, secret_key: ident.secretKeyId }, payload.to_vec()))
        } else {
            bail!("Signatures do not meet threshold");
        }
    }

    pub fn insert_user_key(&self, key_id: u64, key_data: &[u8]) -> Result<(), Error> {
        let conn = SqliteConnection::establish(&self.connection_string)?;

        diesel::insert_into(schema::users::dsl::users)
            .values(&NewUserKey { key_id: key_id as i64, key_data })
            .execute(&conn)
            .map(|_| ())
            .map_err(|e| e.into())
    }

    pub fn insert_secret_key(&self, hsm_id: i32, key_id: i64, threshold: i32) -> Result<(), Error> {
        let conn = SqliteConnection::establish(&self.connection_string)?;

        diesel::insert_into(schema::secrets::dsl::secrets)
            .values(&NewSecret { key_id, hsm_id, threshold })
            .execute(&conn)
            .map(|_| ())
            .map_err(|e| e.into())
    }
}

pub struct AuthenticatedConnection {
    secret_key: u64,
    connection: SqliteConnection,
}

impl AuthenticatedConnection {
    pub fn get_hsm_key_id(&self) -> Result<u16, Error> {
        schema::secrets::dsl::secrets
            .filter(schema::secrets::columns::key_id.eq(self.secret_key as i64))
            .load::<SecretKey>(&self.connection)?
            .pop()
            .map(|key| key.hsm_id as u16)
            .ok_or(format_err!("Secret key deleted while in use?"))
    }

    pub fn get_user_key(&self, key_id: u64) -> Result<Option<UserKey>, Error> {
        Ok(schema::users::dsl::users
            .filter(schema::users::columns::key_id.eq(key_id as i64))
            .load::<UserKey>(&self.connection)?
            .pop())
    }

    pub fn upsert_user_key_weight(&self, secret_key_id: u64, user: UserKey, weight: i32) -> Result<(), Error> {
        let secret = schema::secrets::dsl::secrets
            .filter(schema::secrets::columns::key_id.eq(secret_key_id as i64))
            .load::<SecretKey>(&self.connection)?
            .pop()
            .ok_or(format_err!("No such secret key"))?;

        if schema::user_secret_weights::dsl::user_secret_weights
            .filter(schema::user_secret_weights::dsl::user_id.eq(user.id))
            .filter(schema::user_secret_weights::dsl::secret_id.eq(secret.id))
            .load::<UserKeyWeight>(&self.connection)?
            .pop()
            .is_some()
        {
            diesel::update(
                schema::user_secret_weights::dsl::user_secret_weights
                    .filter(schema::user_secret_weights::dsl::user_id.eq(user.id))
                    .filter(schema::user_secret_weights::dsl::secret_id.eq(secret.id)),
            ).set(schema::user_secret_weights::dsl::weight.eq(weight))
                .execute(&self.connection)
                .map(|_| ())
                .map_err(|e| e.into())
        } else {
            diesel::insert_into(schema::user_secret_weights::dsl::user_secret_weights)
                .values(&NewWeight {
                    user_id: user.id,
                    secret_id: secret.id,
                    weight: weight,
                })
                .execute(&self.connection)
                .map(|_| ())
                .map_err(|e| e.into())
        }
    }

    pub fn set_secret_key_threshold(&self, secret_key_id: u64, threshold: i32) -> Result<(), Error> {
        diesel::update(
            schema::secrets::dsl::secrets.filter(
                schema::secrets::columns::key_id.eq(secret_key_id as i64)))
            .set(schema::secrets::dsl::threshold.eq(threshold))
            .execute(&self.connection)
            .map(|_| ())
            .map_err(|e| e.into())
    }
}
