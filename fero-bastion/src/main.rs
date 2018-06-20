extern crate chrono;
extern crate failure;
extern crate fero_proto;
extern crate futures;
extern crate grpcio;
#[macro_use]
extern crate log;
extern crate loggerv;
extern crate protobuf;
#[macro_use]
extern crate structopt;

mod service;

use std::io::{self, Read};
use std::sync::Arc;
use std::thread;

use failure::Error;
use futures::{Future, sync::oneshot};
use grpcio::{Environment, ServerBuilder, Server};
use structopt::StructOpt;

use fero_proto::fero_grpc::create_fero;
use service::*;

#[derive(StructOpt)]
#[structopt(name = "fero-bastion")]
struct Opt {
    #[structopt(short = "a", long = "address", default_value = "0.0.0.0")]
    /// The address to listen on.
    address: String,
    #[structopt(short = "p", long = "port", default_value = "50051")]
    /// The port to listen on.
    port: u16,
    #[structopt(short = "v", parse(from_occurrences))]
    /// Verbosity.
    verbosity: u64,
    #[structopt(short = "s", long = "server-address")]
    /// The address of the server to make requests to.
    server_address: String,
    #[structopt(short = "r", long = "server-port", default_value = "50051")]
    /// The port of the server to make requests to.
    server_port: u16,
}

fn create_bastion(
    address: &str,
    port: u16,
    server_address: &str,
    server_port: u16,
) -> Result<Server, Error> {
    ServerBuilder::new(Arc::new(Environment::new(1)))
        .register_service(create_fero(FeroBastion::new(server_address, server_port)))
        .bind(address, port)
        .build()
        .map_err(|e| e.into())
}

pub fn main() -> Result<(), Error> {
    let opts = Opt::from_args();

    loggerv::init_with_verbosity(opts.verbosity)?;

    let mut bastion = create_bastion(
        &opts.address,
        opts.port,
        &opts.server_address,
        opts.server_port,
    )?;

    bastion.start();
    let (tx, rx) = oneshot::channel();
    thread::spawn(move || {
        warn!("Press ENTER to exit...");
        let _ = io::stdin().read(&mut [0]).unwrap();
        tx.send(())
    });
    let _ = rx.wait();
    bastion.shutdown().wait()?;

    Ok(())
}
