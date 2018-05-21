use std::io::{Cursor, Read};
use std::ops::Deref;

use byteorder::{BigEndian, ByteOrder, ReadBytesExt, WriteBytesExt};
use chrono::NaiveDateTime;
use failure::Error;
use protobuf::Message;
use sha2::{Sha256, Digest};

use fero::{self, Identification};

#[derive(Clone, Copy, Debug, DbEnum)]
#[repr(u8)]
pub enum OperationType {
    Sign,
    Threshold,
    Weight,
    AddSecret,
    AddUser,
}

impl From<fero::LogEntry_OperationType> for OperationType {
    fn from(ty: fero::LogEntry_OperationType) -> OperationType {
        match ty {
            fero::LogEntry_OperationType::SIGN => OperationType::Sign,
            fero::LogEntry_OperationType::THRESHOLD => OperationType::Threshold,
            fero::LogEntry_OperationType::WEIGHT => OperationType::Weight,
            fero::LogEntry_OperationType::ADD_SECRET => OperationType::AddSecret,
            fero::LogEntry_OperationType::ADD_USER => OperationType::AddUser,
        }
    }
}

#[derive(Clone, Copy, Debug, DbEnum)]
#[repr(u8)]
pub enum OperationResult {
    Success,
    Failure,
}

impl From<fero::LogEntry_OperationResult> for OperationResult {
    fn from(res: fero::LogEntry_OperationResult) -> OperationResult {
        match res {
            fero::LogEntry_OperationResult::SUCCESS => OperationResult::Success,
            fero::LogEntry_OperationResult::FAILURE => OperationResult::Failure,
        }
    }
}

#[derive(Clone, Debug)]
pub struct HsmLogEntry {
    pub hsm_index: u16,
    pub command: u8,
    pub data_length: u16,
    pub session_key: u16,
    pub target_key: u16,
    pub second_key: u16,
    pub result: u8,
    pub systick: u32,
    pub hash: Vec<u8>,
}

impl<T> From<T> for HsmLogEntry
where
    T: Deref<Target = fero::HsmLog>,
{
    fn from(log: T) -> HsmLogEntry {
        HsmLogEntry {
            hsm_index: log.id as u16,
            command: log.command as u8,
            data_length: log.data_length as u16,
            session_key: log.session_key as u16,
            target_key: log.target_key as u16,
            second_key: log.second_key as u16,
            result: log.result as u8,
            systick: log.systick,
            hash: log.hash.clone(),
        }
    }
}

impl From<HsmLogEntry> for fero::HsmLog {
    fn from(log: HsmLogEntry) -> fero::HsmLog {
        let mut proto_log = fero::HsmLog::new();

        proto_log.set_id(log.hsm_index as u32);
        proto_log.set_command(log.command as u32);
        proto_log.set_data_length(log.data_length as u32);
        proto_log.set_session_key(log.session_key as u32);
        proto_log.set_target_key(log.target_key as u32);
        proto_log.set_second_key(log.second_key as u32);
        proto_log.set_result(log.result as u32);
        proto_log.set_systick(log.systick);
        proto_log.set_hash(log.hash.clone());

        proto_log
    }
}

impl HsmLogEntry {
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();

        out.write_u16::<BigEndian>(self.hsm_index)?;
        out.push(self.command);
        out.write_u16::<BigEndian>(self.data_length)?;
        out.write_u16::<BigEndian>(self.session_key)?;
        out.write_u16::<BigEndian>(self.target_key)?;
        out.write_u16::<BigEndian>(self.second_key)?;
        out.push(self.result);
        out.write_u32::<BigEndian>(self.systick)?;
        out.extend_from_slice(&self.hash);

        Ok(out)
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<HsmLogEntry, Error> {
        let mut cursor = Cursor::new(&bytes);

        let hsm_index = cursor.read_u16::<BigEndian>()?;
        let command = cursor.read_u8()?;
        let data_length = cursor.read_u16::<BigEndian>()?;
        let session_key = cursor.read_u16::<BigEndian>()?;
        let target_key = cursor.read_u16::<BigEndian>()?;
        let second_key = cursor.read_u16::<BigEndian>()?;
        let result = cursor.read_u8()?;
        let systick = cursor.read_u32::<BigEndian>()?;

        let mut hash = [0u8; 16];
        cursor.read_exact(&mut hash)?;

        Ok(HsmLogEntry {
            hsm_index,
            command,
            data_length,
            session_key,
            target_key,
            second_key,
            result,
            systick,
            hash: hash.into_iter().cloned().collect(),
        })
    }
}

#[derive(Clone, Debug)]
pub struct FeroLogEntry {
    pub request_type: OperationType,
    pub timestamp: NaiveDateTime,
    pub result: OperationResult,
    pub hsm_logs: Vec<HsmLogEntry>,
    pub identification: Option<Identification>,
    pub hash: Vec<u8>,
}

impl FeroLogEntry {
    pub fn hash(&self, parent_log_hash: &[u8]) -> Result<Vec<u8>, Error> {
        let mut hasher = Sha256::default();

        hasher.input(&[self.request_type as u8]);

        let mut timestamp_buf = [0; 8];
        BigEndian::write_i64(&mut timestamp_buf, self.timestamp.timestamp());
        hasher.input(&timestamp_buf);

        hasher.input(&[self.result as u8]);

        for hsm_log in &self.hsm_logs {
            hasher.input(&hsm_log.to_bytes()?);
        }

        if let Some(ref ident) = self.identification {
            hasher.input(&ident.write_to_bytes().unwrap());
        }

        hasher.input(parent_log_hash);

        let hash_result: &[u8] = &hasher.result();

        Ok(Vec::from(hash_result))
    }

    pub fn verify(entries: &[FeroLogEntry]) -> Result<(), Error> {
        for i in 1..entries.len() {
            let hash = entries[i].hash(&entries[i - 1].hash)?;

            if hash != entries[i].hash {
                bail!("Failed entry: {:?}", entries[i]);
            }
        }

        Ok(())
    }
}

impl<T> From<T> for FeroLogEntry
where
    T: Deref<Target = fero::LogEntry>
{
    fn from(entry: T) -> FeroLogEntry {
        let ident = if entry.has_ident() {
            Some(entry.get_ident())
        } else {
            None
        };

        FeroLogEntry {
            request_type: entry.operation_type.into(),
            timestamp: NaiveDateTime::from_timestamp(
                entry.get_timestamp().get_seconds(),
                entry.get_timestamp().get_nanos() as u32
            ),
            result: entry.result.into(),
            identification: ident.cloned(),
            hsm_logs: entry.hsm_logs.iter().map(HsmLogEntry::from).collect(),
            hash: entry.hash.clone(),
        }
    }
}
