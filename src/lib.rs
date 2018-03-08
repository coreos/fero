#[macro_use]
extern crate diesel;
#[macro_use]
extern crate failure;
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
extern crate yasna;

mod bastion;
mod database;
mod hsm;
mod service;
mod types;

use std::sync::Arc;

use failure::Error;
use grpcio::{Environment, Server, ServerBuilder};

pub use types::fero::*;
pub use types::fero_grpc::*;

pub fn create_server(
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

pub fn create_bastion(
    address: &str,
    port: u16,
    server_address: &str,
    server_port: u16,
) -> Result<Server, Error> {
    ServerBuilder::new(Arc::new(Environment::new(1)))
        .register_service(create_fero(bastion::FeroBastion::new(
            server_address,
            server_port,
        )))
        .bind(address, port)
        .build()
        .map_err(|e| e.into())
}
