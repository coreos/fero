#[macro_use]
extern crate diesel;
#[macro_use]
extern crate error_chain;
extern crate futures;
extern crate gpgme;
extern crate grpcio;
#[macro_use]
extern crate log;
extern crate loggerv;
extern crate protobuf;

mod database;
pub mod errors;
mod service;
mod types;

use errors::*;
use grpcio::{Environment, Server, ServerBuilder};
use std::sync::Arc;
pub use types::fero::*;
pub use types::fero_grpc::*;

pub fn create_server(address: &str, port: u16, database: &str) -> Result<Server> {
    ServerBuilder::new(Arc::new(Environment::new(1)))
        .register_service(create_fero(service::FeroService::new(
            database::Configuration::new(database),
        )))
        .bind(address, port)
        .build()
        .chain_err(|| "Failed to create gRPC server")
}
