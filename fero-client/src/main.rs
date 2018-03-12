extern crate failure;
extern crate fero_proto;
extern crate grpcio;
extern crate log;
extern crate loggerv;
extern crate protobuf;
#[macro_use]
extern crate structopt;

use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Arc;

use failure::Error;
use grpcio::{ChannelBuilder, EnvBuilder};
use protobuf::repeated::RepeatedField;
use structopt::StructOpt;

use fero_proto::fero::{Identification, SignRequest, ThresholdRequest, WeightRequest};
use fero_proto::fero_grpc::FeroClient;

#[derive(StructOpt)]
#[structopt(name = "fero-client")]
struct Opt {
    #[structopt(short = "a", long = "address", default_value = "localhost")]
    /// The server's address.
    address: String,
    #[structopt(short = "p", long = "port", default_value = "50051")]
    /// The server's port.
    port: u16,
    #[structopt(short = "v", parse(from_occurrences))]
    /// Verbosity.
    verbosity: u64,
    #[structopt(subcommand)]
    command: FeroCommand,
}

#[derive(StructOpt)]
struct SignCommand {
    #[structopt(short = "k", long = "secret-key-id")]
    /// The secret key id to sign with.
    secret_key_id: u64,
    #[structopt(short = "f", long = "file", parse(from_os_str))]
    /// The file to sign.
    file: PathBuf,
    #[structopt(short = "s", long = "signature", parse(from_os_str))]
    /// The user signatures to authorize signing.
    signatures: Vec<PathBuf>,
    #[structopt(short = "o", long = "output", parse(from_os_str))]
    /// The file to place the signature in.
    output: PathBuf,
}

#[derive(StructOpt)]
struct ThresholdCommand {
    #[structopt(short = "k", long = "secret-key-id")]
    /// The secret key id to update.
    secret_key_id: u64,
    #[structopt(short = "t", long = "threshold")]
    /// The new threshold to set.
    threshold: i32,
    #[structopt(short = "s", long = "signature", parse(from_os_str))]
    /// The user signatures to authorize the operation.
    signatures: Vec<PathBuf>,
}

#[derive(StructOpt)]
struct WeightCommand {
    #[structopt(short = "k", long = "secret-key-id")]
    /// The secret key id to update.
    secret_key_id: u64,
    #[structopt(short = "u", long = "user-id")]
    /// The user whose weight is to be updated.
    user_id: u64,
    #[structopt(short = "w", long = "weight")]
    /// The new weight.
    weight: i32,
    #[structopt(short = "s", long = "signature", parse(from_os_str))]
    /// The user signatures to authorize the operation.
    signatures: Vec<PathBuf>,
}

#[derive(StructOpt)]
enum FeroCommand {
    #[structopt(name = "sign")]
    /// Sign the given file.
    Sign(SignCommand),
    #[structopt(name = "threshold")]
    /// Update the threshold for a given secret key.
    Threshold(ThresholdCommand),
    #[structopt(name = "weight")]
    /// Update a given user's weight for a given secret key.
    Weight(WeightCommand),
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

    let env = Arc::new(EnvBuilder::new().build());
    let ch = ChannelBuilder::new(env).connect(&format!("{}:{}", opts.address, opts.port));
    let client = FeroClient::new(ch);

    match opts.command {
        FeroCommand::Sign(sign_opts) => {
            let mut ident = Identification::new();
            ident.set_secretKeyId(sign_opts.secret_key_id);
            let mut signatures_contents = Vec::new();
            for filename in sign_opts.signatures {
                let mut file = File::open(filename)?;
                let mut contents = Vec::new();
                file.read_to_end(&mut contents)?;
                signatures_contents.push(contents);
            }
            ident.set_signatures(RepeatedField::from_vec(signatures_contents));

            let mut req = SignRequest::new();
            req.set_identification(ident);
            req.set_payload({
                let mut file = File::open(sign_opts.file)?;
                let mut contents = Vec::new();
                file.read_to_end(&mut contents)?;
                contents
            });

            let reply = client.sign_payload(&req)?;
            let mut output = File::create(sign_opts.output)?;
            output.write_all(&reply.get_payload().to_vec())?;

            Ok(())
        }
        FeroCommand::Threshold(threshold_opts) => {
            let mut req = ThresholdRequest::new();
            req.set_threshold(threshold_opts.threshold);

            client.set_secret_key_threshold(&req).map(|_| ())?;

            Ok(())
        }
        FeroCommand::Weight(weight_opts) => {
            let mut ident = Identification::new();
            ident.set_secretKeyId(weight_opts.secret_key_id);

            let mut req = WeightRequest::new();
            req.set_identification(ident);
            req.set_userKeyId(weight_opts.user_id);
            req.set_weight(weight_opts.weight);

            client.set_user_key_weight(&req).map(|_| ())?;

            Ok(())
        }
    }
}
