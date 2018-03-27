mod models;
mod schema;

use diesel;
use diesel::Connection;
use diesel::prelude::*;
use diesel::sqlite::SqliteConnection;
use errors::*;
use gpgme::{Context, Protocol};
use self::models::*;
use std::collections::HashSet;
pub use types::fero::*;



//type UserKeyId u64;
//type SecretKeyId u64;

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
    ) -> Result<(AuthenticatedConnection, Vec<u8>)> {
        let conn = SqliteConnection::establish(&self.connection_string)
            .chain_err(|| "Failed to connect to the database")?;

        let secret = schema::secrets::dsl::secrets
            .filter(schema::secrets::columns::key_id.eq(ident.secretKeyId as i64))
            .load::<SecretKey>(&conn)
            .chain_err(|| "Failed to query secret keys")?
            .pop()
            .ok_or(format!("No secret key found ({})", ident.secretKeyId))?;

        let mut gpg = Context::from_protocol(Protocol::OpenPgp).unwrap();
        let mut ids = HashSet::new();
        let mut data = Vec::new();
        for signature in &ident.signatures {
            let verification = gpg.verify_opaque(signature, &mut data).chain_err(
                || "Failed to verify signature",
            )?;

            // TODO can verify_opaque verify the payload?
            if data != payload {
                return Err("Signature received was for incorrect payload".into());
            }

            for signature in verification.signatures() {
                // It seems gpgme is not filling in the .key() field here, so we retrieve it from
                // gpgme via the fingerprint of the signature.
                let signing_key = gpg.find_key(signature.fingerprint().unwrap()).unwrap();
                ids.insert(i64::from_str_radix(signing_key.id().unwrap(), 16)?);
                // TODO
                //ids.insert(signature.key().unwrap().primary_key().unwrap().id().chain_err(|| "Failed to read key id")?);
            }
        }

        let mut weight = 0;
        for id in ids {
            // TODO use JOIN
            let user = schema::users::dsl::users
                .filter(schema::users::columns::key_id.eq(id))
                .load::<UserKey>(&conn)
                .chain_err(|| "Failed to query user keys")?
                .pop()
                .ok_or("No such user key")?;

            weight += schema::user_secret_weights::dsl::user_secret_weights
                .filter(schema::user_secret_weights::columns::secret_id.eq(
                    secret.id,
                ))
                .filter(schema::user_secret_weights::columns::user_id.eq(user.id))
                .load::<UserKeyWeight>(&conn)
                .chain_err(|| "Failed to query user key weight")?
                .pop()
                .map(|w| w.weight)
                .unwrap_or(0)
        }

        if weight >= secret.threshold {
            Ok((AuthenticatedConnection { connection: conn }, data))
        } else {
            Err("Signatures do not meet threshold".into())
        }
    }
}

pub struct AuthenticatedConnection {
    connection: SqliteConnection,
}

impl AuthenticatedConnection {
    pub fn upsert_user_key(&self, key_id: u64) -> Result<UserKey> {
        if let Some(key) = schema::users::dsl::users
            .filter(schema::users::columns::key_id.eq(key_id as i64))
            .load::<UserKey>(&self.connection)
            .chain_err(|| "Failed to query user keys")?
            .pop()
        {
            Ok(key)
        } else {
            diesel::insert_into(schema::users::dsl::users)
                .values(&NewUserKey { key_id: key_id as i64 })
                .execute(&self.connection)
                .chain_err(|| "Failed to insert user key")?;

            schema::users::dsl::users
                .filter(schema::users::columns::key_id.eq(key_id as i64))
                .load::<UserKey>(&self.connection)
                .chain_err(|| "Failed to query user keys")?
                .pop()
                .ok_or("Failed to fetch user key".into())
        }
    }

    pub fn upsert_user_key_weight(&self, secret_key_id: u64, user: UserKey, weight: i32) -> Result<()> {
        let secret = schema::secrets::dsl::secrets
            .filter(schema::secrets::columns::key_id.eq(secret_key_id as i64))
            .load::<SecretKey>(&self.connection)
            .chain_err(|| "Failed to query secret keys")?
            .pop()
            .ok_or("No such secret key")?;

        if schema::user_secret_weights::dsl::user_secret_weights
            .filter(schema::user_secret_weights::dsl::user_id.eq(user.id))
            .filter(schema::user_secret_weights::dsl::secret_id.eq(secret.id))
            .load::<UserKeyWeight>(&self.connection)
            .chain_err(|| "Failed to query weights")?
            .pop()
            .is_some()
        {
            diesel::update(
                schema::user_secret_weights::dsl::user_secret_weights
                    .filter(schema::user_secret_weights::dsl::user_id.eq(user.id))
                    .filter(schema::user_secret_weights::dsl::secret_id.eq(secret.id)),
            ).set(schema::user_secret_weights::dsl::weight.eq(weight))
                .execute(&self.connection)
                .chain_err(|| "Failed to update user key weight")
                .map(|_| ())
        } else {
            diesel::insert_into(schema::user_secret_weights::dsl::user_secret_weights)
                .values(&NewWeight {
                    user_id: user.id,
                    secret_id: secret.id,
                    weight: weight,
                })
                .execute(&self.connection)
                .chain_err(|| "Failed to insert user key weight")
                .map(|_| ())
        }
    }
}
