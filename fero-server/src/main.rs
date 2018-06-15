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

extern crate byteorder;
extern crate chrono;
#[macro_use]
extern crate diesel;
extern crate diesel_migrations;
#[macro_use]
extern crate failure;
extern crate fero_proto;
extern crate futures;
extern crate gag;
extern crate gpgme;
extern crate grpcio;
extern crate libyubihsm;
#[macro_use]
extern crate log;
extern crate loggerv;
extern crate num;
extern crate pretty_good;
extern crate protobuf;
extern crate rpassword;
extern crate secstr;
extern crate rand;
extern crate sha2;
#[macro_use]
extern crate structopt;
extern crate tempfile;
extern crate yasna;

mod database;
mod hsm;
mod local;
mod logging;
mod service;
#[cfg(test)]
mod test;

use std::fs::File;
use std::io::{self, Read};
use std::num::ParseIntError;
use std::path::PathBuf;
use std::str;
use std::sync::Arc;
use std::thread;

use failure::Error;
use futures::sync::oneshot;
use futures::Future;
use grpcio::{Environment, Server, ServerBuilder};
use num::{bigint::ParseBigIntError, BigUint, Num};
use secstr::SecStr;
use structopt::StructOpt;

use fero_proto::fero_grpc::create_fero;

#[derive(StructOpt)]
#[structopt(name = "fero-server")]
struct Opt {
    #[structopt(short = "v", parse(from_occurrences))]
    /// Verbosity.
    verbosity: u64,
    #[structopt(short = "d", long = "database", default_value = "fero.db")]
    /// Path to the sqlite database.
    database: String,
    #[structopt(short = "c", long = "connector-url", default_value = "http://127.0.0.1:12345")]
    /// URL for the HSM connector.
    hsm_connector_url: String,
    #[structopt(subcommand)]
    command: FeroServerCommand,
}

#[derive(StructOpt)]
enum FeroServerCommand {
    #[structopt(name = "serve")]
    /// Start a fero server.
    Serve(ServeCommand),
    #[structopt(name = "add-secret")]
    /// Enroll a secret with fero.
    AddSecret(AddSecretCommand),
    #[structopt(name = "add-user")]
    /// Add a user to fero.
    AddUser(AddUserCommand),
    #[structopt(name = "set-user-weight")]
    /// Set a user's weight for a particular secret.
    SetUserWeight(SetUserWeightCommand),
    #[structopt(name = "provision")]
    /// Perform first-time initialization to set up a fero server.
    Provision(ProvisionCommand),
}

#[derive(StructOpt)]
struct ServeCommand {
    #[structopt(short = "a", long = "address", default_value = "0.0.0.0")]
    /// The server's address.
    address: String,
    #[structopt(short = "p", long = "port", default_value = "50051")]
    /// The server's port.
    port: u16,
    #[structopt(short = "k", long = "authkey")]
    /// YubiHSM2 AuthKey to use.
    hsm_authkey: u16,
    #[structopt(short = "w", long = "password")]
    /// Password for the HSM AuthKey.
    hsm_password: Option<String>,
}

#[derive(StructOpt)]
struct AddSecretCommand {
    #[structopt(short = "f", long = "file", parse(from_os_str))]
    /// File containing the GPG private key to add.
    file: PathBuf,
    #[structopt(short = "s", long = "subkey", parse(try_from_str = "parse_biguint"))]
    /// Fingerprint of which subkey to add.
    subkey: BigUint,
    #[structopt(short = "t", long = "threshold", default_value = "100")]
    /// Threshold to associate with the new secret.
    threshold: i32,
    #[structopt(short = "n", long = "name")]
    /// Name for the new secret.
    name: String,
    #[structopt(short = "k", long = "authkey")]
    /// YubiHSM2 AuthKey to use.
    hsm_authkey: u16,
    #[structopt(short = "w", long = "password")]
    /// Password for the HSM AuthKey.
    hsm_password: Option<String>,
}

#[derive(StructOpt)]
struct AddUserCommand {
    #[structopt(short = "f", long = "file", parse(from_os_str))]
    /// File containing the user's GPG public key to add.
    file: PathBuf,
    #[structopt(short = "k", long = "authkey")]
    /// YubiHSM2 AuthKey to use.
    hsm_authkey: u16,
    #[structopt(short = "w", long = "password")]
    /// Password for the HSM AuthKey.
    hsm_password: Option<String>,
}

#[derive(StructOpt)]
struct SetUserWeightCommand {
    #[structopt(short = "u", long = "user", parse(try_from_str = "parse_hex"))]
    /// PGP key ID for the user.
    user: u64,
    #[structopt(short = "n", long = "name")]
    /// Name of the secret.
    secret: String,
    #[structopt(short = "e", long = "weight")]
    /// New weight.
    weight: i32,
}

#[derive(StructOpt)]
struct ProvisionCommand {
    #[structopt(short = "y", long = "yes")]
    /// Confirm that you want to freshly provision the database and HSM.
    confirm: bool,
}

fn parse_hex(s: &str) -> Result<u64, ParseIntError> {
    if s.starts_with("0x") {
        u64::from_str_radix(&s[2..], 16)
    } else {
        u64::from_str_radix(s, 16)
    }
}

fn parse_biguint(s: &str) -> Result<BigUint, ParseBigIntError> {
    if s.starts_with("0x") {
        BigUint::from_str_radix(&s[2..], 16)
    } else {
        BigUint::from_str_radix(s, 16)
    }
}

fn create_server(
    address: &str,
    port: u16,
    database: &str,
    hsm_connector: &str,
    hsm_authkey: u16,
    hsm_password: &str,
) -> Result<Server, Error> {
    ServerBuilder::new(Arc::new(Environment::new(1)))
        .register_service(create_fero(service::FeroService::new(
            database::Configuration::new(database),
            hsm::Hsm::new(hsm_connector, hsm_authkey, hsm_password)?,
        )))
        .bind(address, port)
        .build()
        .map_err(|e| e.into())
}

pub fn main() -> Result<(), Error> {
    let opts = Opt::from_args();

    loggerv::init_with_verbosity(opts.verbosity)?;

    match opts.command {
        FeroServerCommand::Serve(serve_opts) => {
            let hsm_password = match serve_opts.hsm_password {
                Some(hsm_password) => SecStr::from(hsm_password),
                None => SecStr::from(
                    rpassword::prompt_password_stdout("Password for HSM AuthKey: ")?
                ),
            };

            let mut server = create_server(
                &serve_opts.address,
                serve_opts.port,
                &opts.database,
                &opts.hsm_connector_url,
                serve_opts.hsm_authkey,
                str::from_utf8(hsm_password.unsecure())?,
            )?;

            server.start();
            let (tx, rx) = oneshot::channel();
            thread::spawn(move || {
                warn!("Press ENTER to exit...");
                let _ = io::stdin().read(&mut [0]).unwrap();
                tx.send(())
            });
            let _ = rx.wait();
            server.shutdown().wait()?;
        }
        FeroServerCommand::AddSecret(enroll_opts) => {
            let hsm_password = match enroll_opts.hsm_password {
                Some(hsm_password) => SecStr::from(hsm_password),
                None => SecStr::from(
                    rpassword::prompt_password_stdout("Password for HSM AuthKey: ")?
                ),
            };

            let hsm = hsm::Hsm::new(
                &opts.hsm_connector_url,
                enroll_opts.hsm_authkey,
                str::from_utf8(hsm_password.unsecure())?,
            )?;

            local::import_pgp_secret(
                &hsm,
                &enroll_opts.file,
                &enroll_opts.subkey,
                &opts.database,
                &enroll_opts.name,
                enroll_opts.threshold,
            )?;
        }
        FeroServerCommand::AddUser(user_opts) => {
            let hsm_password = match user_opts.hsm_password {
                Some(hsm_password) => SecStr::from(hsm_password),
                None => SecStr::from(
                    rpassword::prompt_password_stdout("Password for HSM AuthKey: ")?
                ),
            };

            let hsm = hsm::Hsm::new(
                &opts.hsm_connector_url,
                user_opts.hsm_authkey,
                str::from_utf8(hsm_password.unsecure())?,
            )?;

            let mut key_bytes = Vec::new();
            File::open(&user_opts.file)?.read_to_end(&mut key_bytes)?;
            let key_id = local::find_keyid(&key_bytes)?;

            local::store_user(&hsm, &opts.database, key_id, &key_bytes)?;
        }
        FeroServerCommand::SetUserWeight(weight_opts) => {
            local::set_user_weight(
                &opts.database,
                weight_opts.user,
                &weight_opts.secret,
                weight_opts.weight,
            )?;
        }
        FeroServerCommand::Provision(provision_opts) => {
            if !provision_opts.confirm {
                error!("Provisioning the HSM is destructive! Pass the `-y` option to fero-server to confirm you want to do this.");
                return Ok(());
            }

            let admin_key_password = SecStr::from(rpassword::prompt_password_stdout(
                "Password for new administrative HSM AuthKey: ",
            )?);
            let admin_password_confirm = SecStr::from(rpassword::prompt_password_stdout(
                "Confirm administrative AuthKey password: ",
            )?);
            if admin_key_password != admin_password_confirm {
                bail!("Passwords do not match.");
            }

            let app_key_password = SecStr::from(rpassword::prompt_password_stdout(
                "Password for new application HSM AuthKey: ",
            )?);
            let app_password_confirm = SecStr::from(rpassword::prompt_password_stdout(
                "Confirm application AuthKey password: ",
            )?);
            if app_key_password != app_password_confirm {
                bail!("Passwords do not match.");
            }

            local::provision(
                &opts.database,
                &opts.hsm_connector_url,
                admin_key_password,
                app_key_password,
            )?;
        }
    }

    Ok(())
}
