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

pub(crate) mod models;
mod schema;

use std::collections::HashSet;
use std::os::unix::ffi::OsStrExt;

use diesel::{self, Connection};
use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use failure::Error;
use gpgme::{Context, Protocol, SignatureSummary};
use tempfile::TempDir;

use fero_proto::fero::Identification;
use self::models::*;
use super::local::LocalIdentification;

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
            .filter(schema::secrets::columns::name.eq(ident.get_secretKeyName()))
            .load::<SecretKey>(&conn)?
            .pop()
            .ok_or(format_err!("No secret key found ({})", ident.get_secretKeyName()))?;

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
            let verification = gpg.verify_detached(signature, payload)?;

            for signature in verification.signatures() {
                // Valid signatures here actually should always have empty summaries, since the
                // user keys we import above are not signed by a key trusted by our brand-new
                // keyring, so all user keys have unknown validity. This check is primarily here to
                // catch signatures over the wrong payload (SignatureSummary::RED), but this is the
                // most technically-correct check (barring adding some extra plumbing above to
                // generate a trusted key and sign each user key we import for each signing
                // operation).
                if !signature.summary().is_empty() &&
                    signature.summary() != SignatureSummary::GREEN &&
                    signature.summary() != SignatureSummary::VALID
                {
                    continue;
                }

                // It seems gpgme is not filling in the .key() field here, so we retrieve it from
                // gpgme via the fingerprint of the signature.
                let fingerprint = signature
                    .fingerprint()
                    .map_err(|_| format_err!("Failed to get signature fingerprint"))?;
                if let Ok(signing_key) = gpg.find_key(fingerprint) {
                    let signing_key_id = signing_key.id().map_err(|_| {
                        format_err!("Failed to get signing key's ID from fingerprint")
                    })?;
                    ids.insert(u64::from_str_radix(signing_key_id, 16)? as i64);
                }
            }
        }

        let mut weight = 0;
        for id in ids {
            weight += schema::user_secret_weights::table
                .select(schema::user_secret_weights::columns::weight)
                .inner_join(schema::users::table)
                .filter(schema::user_secret_weights::columns::secret_id.eq(secret.id))
                .filter(schema::users::columns::key_id.eq(id))
                .load(&conn)?
                .pop()
                .unwrap_or(0);
        }

        if weight >= secret.threshold {
            Ok((AuthenticatedConnection {
                connection: conn,
                secret_key: secret.key_id.map(|id| id as u64),
                secret_name: String::from(ident.get_secretKeyName()),
            }, payload.to_vec()))
        } else {
            bail!("Signatures do not meet threshold");
        }
    }

    pub(crate) fn local_authenticate(
        &self,
        local_ident: LocalIdentification,
    ) -> Result<AuthenticatedConnection, Error> {
        Ok(AuthenticatedConnection {
            secret_key: local_ident.secret_key,
            secret_name: local_ident.name,
            connection: SqliteConnection::establish(&self.connection_string)?,
        })
    }

    pub fn insert_user_key(&self, key_id: u64, key_data: &[u8]) -> Result<(), Error> {
        let conn = SqliteConnection::establish(&self.connection_string)?;

        diesel::insert_into(schema::users::dsl::users)
            .values(&NewUserKey { key_id: key_id as i64, key_data })
            .execute(&conn)
            .map(|_| ())
            .map_err(|e| e.into())
    }

    pub fn insert_secret_key(&self, hsm_id: i32, key_id: Option<i64>, name: &str, threshold: i32) -> Result<(), Error> {
        let conn = SqliteConnection::establish(&self.connection_string)?;

        diesel::insert_into(schema::secrets::dsl::secrets)
            .values(&NewSecret { key_id: key_id, hsm_id, name: String::from(name), threshold })
            .execute(&conn)
            .map(|_| ())
            .map_err(|e| e.into())
    }

    pub fn fero_logs_since(&self, idx: i32) -> Result<Vec<FeroLog>, Error> {
        let conn = SqliteConnection::establish(&self.connection_string)?;

        schema::fero_logs::dsl::fero_logs
            .order(schema::fero_logs::columns::id.asc())
            .filter(schema::fero_logs::columns::id.gt(idx))
            .load::<FeroLog>(&conn)
            .map_err(|e| e.into())
    }

    pub fn associated_hsm_logs(&self, fero_log: &FeroLog) -> Result<Vec<HsmLog>, Error> {
        let conn = SqliteConnection::establish(&self.connection_string)?;

        schema::hsm_logs::dsl::hsm_logs
            .order(schema::hsm_logs::columns::hsm_index.asc())
            .filter(schema::hsm_logs::columns::hsm_index.gt(fero_log.hsm_index_start))
            .filter(schema::hsm_logs::columns::hsm_index.le(fero_log.hsm_index_end))
            .load::<HsmLog>(&conn)
            .map_err(|e| e.into())
    }

    pub fn last_hsm_log_entry(&self) -> Result<Option<HsmLog>, Error> {
        let conn = SqliteConnection::establish(&self.connection_string)?;

        Ok(schema::hsm_logs::dsl::hsm_logs
            .order(schema::hsm_logs::columns::hsm_index.asc())
            .load::<HsmLog>(&conn)?
            .pop())
    }

    pub fn last_fero_log_entry(&self) -> Result<Option<FeroLog>, Error> {
        let conn = SqliteConnection::establish(&self.connection_string)?;

        Ok(schema::fero_logs::dsl::fero_logs
            .order(schema::fero_logs::columns::id.asc())
            .load::<FeroLog>(&conn)?
            .pop())
    }

    fn last_id(&self, conn: &SqliteConnection) -> Result<Option<i32>, Error> {
        no_arg_sql_function!(last_insert_rowid, diesel::sql_types::Integer);
        Ok(diesel::select(last_insert_rowid)
           .load::<i32>(conn)?
           .pop())
    }

    pub fn insert_hsm_logs(&self, hsm_logs: Vec<NewHsmLog>) -> Result<Option<i32>, Error> {
        let conn = SqliteConnection::establish(&self.connection_string)?;

        conn.transaction(|| {
            for log in hsm_logs {
                diesel::insert_into(schema::hsm_logs::dsl::hsm_logs)
                    .values(&log)
                    .execute(&conn)?;
            }

            self.last_id(&conn)
        })
    }

    pub fn insert_fero_log(&self, fero_log: NewFeroLog) -> Result<(), Error> {
        let conn = SqliteConnection::establish(&self.connection_string)?;

        diesel::insert_into(schema::fero_logs::dsl::fero_logs)
            .values(&fero_log)
            .execute(&conn)
            .map(|_| ())
            .map_err(|e| e.into())
    }
}

pub struct AuthenticatedConnection {
    secret_key: Option<u64>,
    secret_name: String,
    connection: SqliteConnection,
}

impl AuthenticatedConnection {
    pub(crate) fn get_pgp_key_id(&self) -> Option<u64> {
        self.secret_key
    }

    pub fn get_hsm_key_id(&self) -> Result<u16, Error> {
        schema::secrets::dsl::secrets
            .filter(schema::secrets::columns::name.eq(&self.secret_name))
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

    pub fn upsert_user_key_weight(&self, user: UserKey, weight: i32) -> Result<(), Error> {
        let secret = schema::secrets::dsl::secrets
            .filter(schema::secrets::columns::name.eq(&self.secret_name))
            .load::<SecretKey>(&self.connection)?
            .pop()
            .ok_or(format_err!("No secret key found ({})", self.secret_name))?;

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
