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
extern crate failure;
extern crate fero_proto;
extern crate grpcio;
#[macro_use]
extern crate log;
extern crate loggerv;
extern crate protobuf;
#[macro_use]
extern crate structopt;

use std::fs::File;
use std::io::{Read, Write};
use std::num::ParseIntError;
use std::path::PathBuf;
use std::sync::Arc;

use byteorder::{BigEndian, WriteBytesExt};
use failure::Error;
use grpcio::{ChannelBuilder, EnvBuilder};
use protobuf::repeated::RepeatedField;
use structopt::StructOpt;

use fero_proto::fero::{Identification, LogRequest, SignRequest, ThresholdRequest, WeightRequest};
use fero_proto::fero_grpc::FeroClient;
use fero_proto::log::FeroLogEntry;

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
    #[structopt(short = "k", long = "secret-key")]
    /// The name of the secret key to sign with.
    secret_key_name: String,
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
    #[structopt(short = "k", long = "secret-key-id", parse(try_from_str = "parse_hex"))]
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
struct ThresholdPayloadCommand {
    #[structopt(short = "k", long = "secret-key-id", parse(try_from_str = "parse_hex"))]
    /// The secret key id to update.
    secret_key_id: u64,
    #[structopt(short = "t", long = "threshold")]
    /// The new threshold to set.
    threshold: i32,
    #[structopt(short = "f", long = "file", parse(from_os_str))]
    /// The file to output the payload into.
    file: PathBuf,
}

#[derive(StructOpt)]
struct WeightCommand {
    #[structopt(short = "k", long = "secret-key-id", parse(try_from_str = "parse_hex"))]
    /// The secret key id to update.
    secret_key_id: u64,
    #[structopt(short = "u", long = "user-id", parse(try_from_str = "parse_hex"))]
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
struct WeightPayloadCommand {
    #[structopt(short = "k", long = "secret-key-id", parse(try_from_str = "parse_hex"))]
    /// The secret key id to update.
    secret_key_id: u64,
    #[structopt(short = "u", long = "user-id", parse(try_from_str = "parse_hex"))]
    /// The user whose weight is to be updated.
    user_id: u64,
    #[structopt(short = "w", long = "weight")]
    /// The new weight.
    weight: i32,
    #[structopt(short = "f", long = "file", parse(from_os_str))]
    /// The file to output the payload into.
    file: PathBuf,
}

#[derive(StructOpt)]
struct GetLogCommand {
    #[structopt(short = "s", long = "since")]
    /// Only retrieve logs created since this log index.
    since: i32,
}

#[derive(StructOpt)]
enum FeroCommand {
    #[structopt(name = "sign")]
    /// Sign the given file.
    Sign(SignCommand),
    #[structopt(name = "threshold-payload")]
    /// Generate a signable payload for a threshold request.
    ThresholdPayload(ThresholdPayloadCommand),
    #[structopt(name = "threshold")]
    /// Update the threshold for a given secret key.
    Threshold(ThresholdCommand),
    #[structopt(name = "weight-payload")]
    /// Generate a signable payload for a weight request.
    WeightPayload(WeightPayloadCommand),
    #[structopt(name = "weight")]
    /// Update a given user's weight for a given secret key.
    Weight(WeightCommand),
    #[structopt(name = "get-logs")]
    /// Get the audit logs from the server.
    GetLogs(GetLogCommand),
}

fn parse_hex(s: &str) -> Result<u64, ParseIntError> {
    if s.starts_with("0x") {
        u64::from_str_radix(&s[2..], 16)
    } else {
        u64::from_str_radix(s, 16)
    }
}

fn build_signatures(signature_files: &[PathBuf]) -> Result<Vec<Vec<u8>>, Error> {
    let mut signatures_contents = Vec::new();

    for filename in signature_files {
        let mut file = File::open(filename)?;
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)?;
        signatures_contents.push(contents);
    }

    Ok(signatures_contents)
}

pub fn main() -> Result<(), Error> {
    let opts = Opt::from_args();

    loggerv::init_with_verbosity(opts.verbosity)?;

    let env = Arc::new(EnvBuilder::new().build());
    let ch = ChannelBuilder::new(env).connect(&format!("{}:{}", opts.address, opts.port));
    let client = FeroClient::new(ch);

    match opts.command {
        FeroCommand::Sign(sign_opts) => {
            let mut ident = Identification::new();
            ident.set_secretKeyName(sign_opts.secret_key_name);
            ident.set_signatures(RepeatedField::from_vec(build_signatures(&sign_opts.signatures)?));

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
        }
        FeroCommand::ThresholdPayload(threshold_opts) => {
            let mut payload = Vec::new();
            payload.write_u64::<BigEndian>(threshold_opts.secret_key_id)?;
            payload.write_i32::<BigEndian>(threshold_opts.threshold)?;

            let mut file = File::create(threshold_opts.file)?;
            file.write_all(&payload)?;
        }
        FeroCommand::Threshold(threshold_opts) => {
            let mut ident = Identification::new();
            ident.set_secretKeyId(threshold_opts.secret_key_id);
            ident.set_signatures(RepeatedField::from_vec(build_signatures(&threshold_opts.signatures)?));

            let mut req = ThresholdRequest::new();
            req.set_identification(ident);
            req.set_threshold(threshold_opts.threshold);

            client.set_secret_key_threshold(&req).map(|_| ())?;
        }
        FeroCommand::WeightPayload(weight_opts) => {
            let mut payload = Vec::new();
            payload.write_u64::<BigEndian>(weight_opts.secret_key_id)?;
            payload.write_u64::<BigEndian>(weight_opts.user_id)?;
            payload.write_i32::<BigEndian>(weight_opts.weight)?;

            let mut file = File::create(weight_opts.file)?;
            file.write_all(&payload)?;
        }
        FeroCommand::Weight(weight_opts) => {
            let mut ident = Identification::new();
            ident.set_secretKeyId(weight_opts.secret_key_id);
            ident.set_signatures(RepeatedField::from_vec(build_signatures(&weight_opts.signatures)?));

            let mut req = WeightRequest::new();
            req.set_identification(ident);
            req.set_userKeyId(weight_opts.user_id);
            req.set_weight(weight_opts.weight);

            client.set_user_key_weight(&req).map(|_| ())?;
        }
        FeroCommand::GetLogs(log_opts) => {
            let mut req = LogRequest::new();
            req.set_minIndex(log_opts.since);

            let reply = client.get_logs(&req)?;
            for log in reply.get_logs() {
                println!("{}", log);
            }

            let logs = reply.get_logs().into_iter().map(FeroLogEntry::from).collect::<Vec<_>>();
            match FeroLogEntry::verify(&logs) {
                Ok(_) => {
                    if reply.get_logs()[0].id != 1 {
                        warn!("Log verification OK, but initial log index was missing.");
                    } else {
                        info!("Log verification OK.");
                    }
                }
                Err(e) => error!("Log verification failed!\nDetails: {}", e),
            }
        }
    }

    Ok(())
}
