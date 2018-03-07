#[macro_use]
extern crate clap;
extern crate diesel;
extern crate failure;
extern crate fero;
extern crate futures;
#[macro_use]
extern crate log;
extern crate loggerv;

use clap::{Arg, App};
use failure::Error;
use futures::Future;
use futures::sync::oneshot;
use std::io::{self, Read};
use std::str::FromStr;
use std::thread;

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
                .help("The address on which to listen")
                .default_value("0.0.0.0"),
        )
        .arg(
            Arg::with_name("PORT")
                .short("p")
                .long("port")
                .takes_value(true)
                .help("The port on which to bind")
                .default_value("50051"),
        )
        .arg(
            Arg::with_name("DATABASE")
                .short("d")
                .long("database")
                .takes_value(true)
                .help("The path to the sqlite database")
                .default_value("fero.db"),
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

    let mut server = fero::create_server(address, port, args.value_of("DATABASE").expect("database flag"))?;
    server.start();
    let (tx, rx) = oneshot::channel();
    thread::spawn(move || {
        warn!("Press ENTER to exit...");
        let _ = io::stdin().read(&mut [0]).unwrap();
        tx.send(())
    });
    let _ = rx.wait();
    server.shutdown().wait().map_err(|e| e.into())
}
