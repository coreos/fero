use gpgme;
use grpcio;
use std::{io, num, string};

error_chain!{
    foreign_links {
        GpgError(gpgme::Error);
        GrpcError(grpcio::Error);
        IoError(io::Error);
        ParseIntError(num::ParseIntError);
        Utf8Error(string::FromUtf8Error);
    }
}
