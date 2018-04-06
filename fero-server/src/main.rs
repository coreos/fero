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
extern crate yasna;

mod database;
mod hsm;
mod service;

use std::io::{self, Read};
use std::sync::Arc;
use std::thread;

use failure::Error;
use futures::Future;
use futures::sync::oneshot;
use grpcio::{Environment, Server, ServerBuilder};
use structopt::StructOpt;

use fero_proto::fero_grpc::create_fero;

#[derive(StructOpt)]
#[structopt(name = "fero-server")]
struct Opt {
    #[structopt(short = "a", long = "address", default_value = "0.0.0.0")]
    /// The server's address.
    address: String,
    #[structopt(short = "p", long = "port", default_value = "50051")]
    /// The server's port.
    port: u16,
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
            hsm::HsmSigner::new(hsm_connector, hsm_authkey, hsm_password)?,
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

    let mut server = create_server(
        &opts.address,
        opts.port,
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

    Ok(())
}
