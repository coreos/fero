extern crate byteorder;
#[macro_use]
extern crate diesel;
#[macro_use]
extern crate failure;
extern crate fero_proto;
extern crate futures;
extern crate gpgme;
extern crate grpcio;
extern crate libyubihsm;
#[macro_use]
extern crate log;
extern crate loggerv;
extern crate num;
extern crate pretty_good;
extern crate protobuf;
#[macro_use]
extern crate structopt;
extern crate tempfile;
extern crate yasna;

mod database;
mod hsm;
mod local;
mod service;

use std::fs::File;
use std::io::{self, Read};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

use failure::Error;
use futures::sync::oneshot;
use futures::Future;
use grpcio::{Environment, Server, ServerBuilder};
use num::{bigint::ParseBigIntError, BigUint, Num};
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
    #[structopt(short = "k", long = "authkey")]
    /// YubiHSM2 AuthKey to use.
    hsm_authkey: u16,
    #[structopt(short = "w", long = "password")]
    /// Password for the HSM AuthKey.
    hsm_password: String,
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
}

#[derive(StructOpt)]
struct ServeCommand {
    #[structopt(short = "a", long = "address", default_value = "0.0.0.0")]
    /// The server's address.
    address: String,
    #[structopt(short = "p", long = "port", default_value = "50051")]
    /// The server's port.
    port: u16,
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
}

#[derive(StructOpt)]
struct AddUserCommand {
    #[structopt(short = "f", long = "file", parse(from_os_str))]
    /// File containing the user's GPG public key to add.
    file: PathBuf,
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

pub fn main() {
    if let Err(e) = run() {
        println!("{:?}", e);
        ::std::process::exit(1);
    }
}

fn run() -> Result<(), Error> {
    let opts = Opt::from_args();

    loggerv::init_with_verbosity(opts.verbosity)?;

    match opts.command {
        FeroServerCommand::Serve(serve_opts) => {
            let mut server = create_server(
                &serve_opts.address,
                serve_opts.port,
                &opts.database,
                &opts.hsm_connector_url,
                opts.hsm_authkey,
                &opts.hsm_password,
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
            let mut key_bytes = Vec::new();
            File::open(&enroll_opts.file)?.read_to_end(&mut key_bytes)?;
            let subkey = local::find_secret_subkey(&key_bytes, &enroll_opts.subkey)?;

            let hsm = hsm::Hsm::new(
                &opts.hsm_connector_url,
                opts.hsm_authkey,
                &opts.hsm_password,
            )?;
            let hsm_id = hsm.put_rsa_key(&subkey)?;

            local::store_key(&opts.database, hsm_id, subkey.id()?, enroll_opts.threshold)?;
        }
        FeroServerCommand::AddUser(user_opts) => {
            let mut key_bytes = Vec::new();
            File::open(&user_opts.file)?.read_to_end(&mut key_bytes)?;
            let key_id = local::find_keyid(&key_bytes)?;

            local::store_user(&opts.database, key_id, &key_bytes)?;
        }
    }

    Ok(())
}
