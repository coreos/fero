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

#[macro_use]
extern crate clap;
extern crate failure;
extern crate fero;
extern crate futures;
extern crate grpcio;
#[macro_use]
extern crate log;
extern crate loggerv;
extern crate protobuf;

use std::io::{self, Read};
use std::str::FromStr;
use std::thread;

use clap::{App, Arg};
use failure::Error;
use futures::{Future, sync::oneshot};

pub fn main() {
    if let Err(e) = run() {
        println!("{:?}", e);
        ::std::process::exit(1);
    }
}

fn run() -> Result<(), Error> {
    let args = App::new(crate_name!())
        .version(crate_version!())
        .about(crate_description!())
        .arg(
            Arg::with_name("ADDRESS")
                .short("a")
                .long("address")
                .takes_value(true)
                .default_value("localhost")
                .help("The address on which to listen"),
        )
        .arg(
            Arg::with_name("PORT")
                .short("p")
                .long("port")
                .takes_value(true)
                .default_value("50051")
                .help("The port on which to bind"),
        )
        .arg(
            Arg::with_name("SERVER_ADDRESS")
                .short("s")
                .long("server-address")
                .takes_value(true)
                .help("The address of the server to act as bastion for."),
        )
        .arg(
            Arg::with_name("SERVER_PORT")
                .short("r")
                .long("server-port")
                .takes_value(true)
                .default_value("50051")
                .help("The port of the server to act as bastion for."),
        )
        .arg(
            Arg::with_name("VERBOSITY")
                .short("v")
                .long("verbose")
                .multiple(true)
                .help("The level of verbosity"),
        )
        .get_matches();

    loggerv::init_with_verbosity(args.occurrences_of("VERBOSITY")).unwrap();

    let address = args.value_of("ADDRESS").expect("address flag");
    let port = u16::from_str(args.value_of("PORT").expect("port flag"))?;
    let server_address = args.value_of("SERVER_ADDRESS")
        .expect("server address flag");
    let server_port = u16::from_str(args.value_of("SERVER_PORT").expect("server port flag"))?;

    let mut bastion = fero::create_bastion(address, port, server_address, server_port)?;

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
