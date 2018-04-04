#[macro_use]
extern crate clap;
extern crate failure;
extern crate fero;
extern crate grpcio;
#[macro_use]
extern crate log;
extern crate loggerv;
extern crate protobuf;

use std::fs::File;
use std::io::{Read, Write};
use std::str::FromStr;
use std::sync::Arc;

use clap::{Arg, App, AppSettings, SubCommand};
use failure::Error;
use grpcio::{ChannelBuilder, EnvBuilder};
use protobuf::repeated::RepeatedField;

use fero::{Identification, FeroClient, SignRequest, ThresholdRequest, WeightRequest};

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
            Arg::with_name("VERBOSITY")
                .short("v")
                .long("verbose")
                .multiple(true)
                .help("The level of verbosity"),
        )
        .subcommand(
            SubCommand::with_name("sign")
                .version(crate_version!())
                .about("sign the given file")
                .arg(
                    Arg::with_name("SECRETKEYID")
                        .short("k")
                        .long("secret-key-id")
                        .takes_value(true)
                        .required(true)
                        .help("The secret key to be used when signing the file"),
                )
                .arg(
                    Arg::with_name("FILE")
                        .short("f")
                        .long("file")
                        .takes_value(true)
                        .required(true)
                        .help("The file to sign"),
                )
                .arg(
                    Arg::with_name("SIGNATURES")
                        .short("s")
                        .long("signature")
                        .takes_value(true)
                        .multiple(true)
                        .help("The user signatures authorizing the file to be signed"),
                )
                .arg(
                    Arg::with_name("OUTPUT")
                        .short("o")
                        .long("output")
                        .takes_value(true)
                        .required(true)
                        .help("The file to place the resulting signature in"),
                ),
        )
        .subcommand(
            SubCommand::with_name("threshold")
                .version(crate_version!())
                .about("set the threshold for a secret key")
                .arg(
                    Arg::with_name("SECRETKEYID")
                        .short("k")
                        .long("secret-key-id")
                        .takes_value(true)
                        .required(true)
                        .help("The secret key to be used when modifying the threshold"),
                )
                .arg(
                    Arg::with_name("THRESHOLD")
                        .short("t")
                        .long("threshold")
                        .takes_value(true)
                        .required(true)
                        .help("The new threshold value (integer) for the secret key"),
                )
                .arg(
                    Arg::with_name("SIGNATURES")
                        .short("s")
                        .long("signature")
                        .takes_value(true)
                        .multiple(true)
                        .help(
                            "The user signatures authorizing the threshold to be modified",
                        ),
                ),
        )
        .subcommand(
            SubCommand::with_name("weight")
                .version(crate_version!())
                .about("set the weight for a particular user key")
                .arg(
                    Arg::with_name("SECRETKEYID")
                        .short("k")
                        .long("secret-key-id")
                        .takes_value(true)
                        .required(true)
                        .help(
                            "The secret key to which the user key weight will be associated",
                        ),
                )
                .arg(
                    Arg::with_name("USERKEYID")
                        .short("u")
                        .long("user-key-id")
                        .takes_value(true)
                        .required(true)
                        .help("The user key to be modified"),
                )
                .arg(
                    Arg::with_name("WEIGHT")
                        .short("w")
                        .long("weight")
                        .takes_value(true)
                        .required(true)
                        .help("The new weight (integer) for the user's key"),
                )
                .arg(
                    Arg::with_name("SIGNATURES")
                        .short("s")
                        .long("signature")
                        .takes_value(true)
                        .multiple(true)
                        .help(
                            "The user signatures authorizing the threshold to be modified",
                        ),
                ),
        )
        .setting(AppSettings::SubcommandRequired)
        .get_matches();

    loggerv::init_with_verbosity(args.occurrences_of("VERBOSITY")).unwrap();

    let env = Arc::new(EnvBuilder::new().build());
    let ch = ChannelBuilder::new(env).connect(&format!(
        "{}:{}",
        args.value_of("ADDRESS").expect("address flag"),
        args.value_of("PORT").expect("port flag")
    ));
    let client = FeroClient::new(ch);

    match args.subcommand() {
        ("sign", Some(args)) => {
            let mut ident = Identification::new();
            ident.set_secretKeyId(u64::from_str(args.value_of("SECRETKEYID").expect("secret key id"))?);
            if let Some(signatures) = args.values_of("SIGNATURES") {
                let mut signatures_contents = Vec::new();
                for filename in signatures {
                    let mut file = File::open(filename)?;
                    let mut contents = Vec::new();
                    file.read_to_end(&mut contents)?;
                    signatures_contents.push(contents);
                }
                ident.set_signatures(RepeatedField::from_vec(signatures_contents));
            }

            let mut req = SignRequest::new();
            req.set_identification(ident);
            req.set_payload({
                let mut file = File::open(args.value_of("FILE").expect("file flag"))?;
                let mut contents = Vec::new();
                file.read_to_end(&mut contents)?;
                contents
            });

            let reply = client.sign_payload(&req)?;
            let mut output = File::create(args.value_of("OUTPUT").expect("output flag"))?;
            output.write_all(&reply.get_payload().to_vec())?;

            Ok(())
        }
        ("threshold", Some(args)) => {
            let mut req = ThresholdRequest::new();
            req.set_threshold(i32::from_str(
                args.value_of("THRESHOLD").expect("threshold flag"),
            )?);

            client.set_secret_key_threshold(&req).map(|_| ()).map_err(|e| e.into())
        }
        ("weight", Some(args)) => {
            let mut ident = Identification::new();
            ident.set_secretKeyId(u64::from_str(args.value_of("SECRETKEYID").expect("secret key id"))?);

            let mut req = WeightRequest::new();
            req.set_identification(ident);
            req.set_userKeyId(u64::from_str(args.value_of("USERKEYID").expect("user key id"))?);
            req.set_weight(i32::from_str(args.value_of("WEIGHT").expect("weight flag"))?);

            client.set_user_key_weight(&req).map(|_| ()).map_err(|e| e.into())
        }
        _ => panic!("subcommand expected"),
    }
}
