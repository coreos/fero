use std::fmt::{Display, Error, Formatter};

use chrono::{Local, NaiveDateTime, TimeZone};

include!(concat!(env!("OUT_DIR"), "/fero/mod.rs"));

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommandType {
    Echo,
    CreateSession,
    AuthSession,
    SessionMessage,
    GetDeviceInfo,
    Bsl,
    Reset,
    CloseSession,
    StorageStatistics,
    PutOpaque,
    GetOpaque,
    PutAuthKey,
    PutAsymmetricKey,
    GenerateAsymmetricKey,
    SignPkcs1,
    ListObjects,
    DecryptPkcs1,
    ExportWrapped,
    ImportWrapped,
    PutWrapKey,
    GetLogs,
    GetObjectInfo,
    PutOption,
    GetOption,
    GetPsuedoRandom,
    PutHmacKey,
    HmacData,
    GetPubkey,
    SignPss,
    SignEcdsa,
    DecryptEcdh,
    DeleteObject,
    DecryptOaep,
    GenerateHmacKey,
    GenerateWrapKey,
    VerifyHmac,
    SshCertify,
    PutTemplate,
    GetTemplate,
    OtpDecrypt,
    OtpAeadCreate,
    OtpAeadRandom,
    OtpAeadRewrap,
    AttestAsymmetric,
    PutOtpAeadKey,
    GenerateOtpAeadKey,
    SetLogIndex,
    WrapData,
    UnwrapData,
    SignEddsa,
    Blink,
    Error,
    Unknown,
}

impl From<u8> for CommandType {
    fn from(c: u8) -> CommandType {
        match c & 0x7f {
            0x01 => CommandType::Echo,
            0x03 => CommandType::CreateSession,
            0x04 => CommandType::AuthSession,
            0x05 => CommandType::SessionMessage,
            0x06 => CommandType::GetDeviceInfo,
            0x07 => CommandType::Bsl,
            0x08 => CommandType::Reset,
            0x40 => CommandType::CloseSession,
            0x41 => CommandType::StorageStatistics,
            0x42 => CommandType::PutOpaque,
            0x43 => CommandType::GetOpaque,
            0x44 => CommandType::PutAuthKey,
            0x45 => CommandType::PutAsymmetricKey,
            0x46 => CommandType::GenerateAsymmetricKey,
            0x47 => CommandType::SignPkcs1,
            0x48 => CommandType::ListObjects,
            0x49 => CommandType::DecryptPkcs1,
            0x4a => CommandType::ExportWrapped,
            0x4b => CommandType::ImportWrapped,
            0x4c => CommandType::PutWrapKey,
            0x4d => CommandType::GetLogs,
            0x4e => CommandType::GetObjectInfo,
            0x4f => CommandType::PutOption,
            0x50 => CommandType::GetOption,
            0x51 => CommandType::GetPsuedoRandom,
            0x52 => CommandType::PutHmacKey,
            0x53 => CommandType::HmacData,
            0x54 => CommandType::GetPubkey,
            0x55 => CommandType::SignPss,
            0x56 => CommandType::SignEcdsa,
            0x57 => CommandType::DecryptEcdh,
            0x58 => CommandType::DeleteObject,
            0x59 => CommandType::DecryptOaep,
            0x5a => CommandType::GenerateHmacKey,
            0x5b => CommandType::GenerateWrapKey,
            0x5c => CommandType::VerifyHmac,
            0x5d => CommandType::SshCertify,
            0x5e => CommandType::PutTemplate,
            0x5f => CommandType::GetTemplate,
            0x60 => CommandType::OtpDecrypt,
            0x61 => CommandType::OtpAeadCreate,
            0x62 => CommandType::OtpAeadRandom,
            0x63 => CommandType::OtpAeadRewrap,
            0x64 => CommandType::AttestAsymmetric,
            0x65 => CommandType::PutOtpAeadKey,
            0x66 => CommandType::GenerateOtpAeadKey,
            0x67 => CommandType::SetLogIndex,
            0x68 => CommandType::WrapData,
            0x69 => CommandType::UnwrapData,
            0x6a => CommandType::SignEddsa,
            0x6b => CommandType::Blink,
            0x7f => CommandType::Error,
            _ => CommandType::Unknown,
        }
    }
}

impl Display for CommandType {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "{:?}", self)
    }
}

impl Display for fero::HsmLog {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        let result = if CommandType::from(self.command as u8) == CommandType::from(self.result as u8) {
            "Success"
        } else {
            "Failure"
        };

        write!(
            f,
            "Entry {} (systick {}): {} with AuthKey = {}; target key = {} ({})",
            self.id,
            self.systick,
            CommandType::from(self.command as u8),
            self.session_key,
            self.target_key,
            result,
        )
    }
}

impl Display for fero::LogEntry_OperationType {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        match *self {
            fero::LogEntry_OperationType::SIGN => write!(f, "Sign"),
            fero::LogEntry_OperationType::THRESHOLD => write!(f, "Set Threshold"),
            fero::LogEntry_OperationType::WEIGHT => write!(f, "Set User Weight"),
            fero::LogEntry_OperationType::ADD_SECRET => write!(f, "Import Secret (local)"),
            fero::LogEntry_OperationType::ADD_USER => write!(f, "Import User (local)"),
        }
    }
}

impl Display for fero::LogEntry_OperationResult {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        match *self {
            fero::LogEntry_OperationResult::SUCCESS => write!(f, "Success"),
            fero::LogEntry_OperationResult::FAILURE => write!(f, "Failure"),
        }
    }
}

impl Display for fero::LogEntry {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        let timestamp = TimeZone::from_utc_datetime(&Local, &NaiveDateTime::from_timestamp(
            self.get_timestamp().get_seconds(),
            self.get_timestamp().get_nanos() as u32
        ));

        write!(
            f,
            "{}: {} operation ({})",
            timestamp,
            self.operation_type,
            self.result,
        )?;

        for log in self.get_hsm_logs() {
            write!(f, "\n\tHSM log: {}", log)?;
        }

        Ok(())
    }
}
