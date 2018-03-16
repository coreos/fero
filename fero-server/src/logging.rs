use std::ops::Deref;

use chrono::prelude::*;
use failure::Error;
use libyubihsm;
use protobuf::Message;

use database::Configuration;
use database::models::{FeroLog, NewFeroLog, NewHsmLog};
use fero_proto::fero::Identification;
use fero_proto::log::*;
use hsm::Hsm;
use logging;

impl<T> From<T> for NewHsmLog
where
    T: Deref<Target = libyubihsm::LogEntry>
{
    fn from(log: T) -> NewHsmLog {
        NewHsmLog {
            hsm_index: log.index as i32,
            command: u8::from(log.command) as i32,
            data_length: log.data_length as i32,
            session_key: log.session_key as i32,
            target_key: log.target_key as i32,
            second_key: log.second_key as i32,
            result: u8::from(log.result) as i32,
            systick: log.systick as i32,
            hash: Vec::from(log.digest()),
        }
    }
}

pub fn create_fero_log(
    request_type: OperationType,
    result: OperationResult,
    hsm_logs: &[libyubihsm::LogEntry],
    hsm_index_start: i32,
    hsm_index_end: i32,
    parent_entry: &FeroLog,
    identification: Option<Identification>,
) -> Result<NewFeroLog, Error> {
    // `HsmLogEntry` is defined in fero-proto, which can't link against libyubihsm (so can't depend
    // on libyubihsm-rs), and `LogEntry` is defined in libyubihsm, so we can't use a `From` here.
    let hsm_logs = hsm_logs
        .iter()
        .map(|log| HsmLogEntry {
            hsm_index: log.index,
            command: u8::from(log.command),
            data_length: log.data_length,
            session_key: log.session_key,
            target_key: log.target_key,
            second_key: log.second_key,
            result: u8::from(log.result),
            systick: log.systick,
            hash: Vec::from(log.digest()),
        })
        .collect::<Vec<_>>();

    let mut new_fero_log = FeroLogEntry {
        request_type,
        timestamp: Utc::now().naive_utc(),
        result,
        hsm_logs,
        identification,
        hash: Vec::new(),
    };

    new_fero_log.hash = new_fero_log.hash(&parent_entry.hash)?;

    Ok(NewFeroLog {
        request_type: new_fero_log.request_type,
        timestamp: new_fero_log.timestamp,
        result: new_fero_log.result,
        hsm_index_start,
        hsm_index_end,
        identification: new_fero_log
            .identification
            .map(|i| i.write_to_bytes().unwrap()),
        hash: new_fero_log.hash,
    })
}

pub fn log_operation(
    hsm: &Hsm,
    database: &Configuration,
    request_type: OperationType,
    result: OperationResult,
    identification: Option<Identification>,
) -> Result<(), Error> {
    let last_hsm_index = database.last_hsm_log_entry()?;

    let hsm_logs = match last_hsm_index {
        Some(ref last_hsm_index) => hsm.logs_since(last_hsm_index.hsm_index as u16)?,
        // TODO(csssuf): fail loudly here if we can't get HSM log entry 0, since we'll never be
        // able to verify the full log chain in that case
        None => hsm.logs()?,
    };
    let last_hsm_index = last_hsm_index.map(|hsm_log| hsm_log.hsm_index).unwrap_or(0);

    let new_hsm_index =
        database.insert_hsm_logs(hsm_logs.iter().map(NewHsmLog::from).collect::<Vec<_>>())?;

    hsm.set_log_index(new_hsm_index.unwrap_or(last_hsm_index) as u16)?;

    let parent_log = database.last_fero_log_entry()?;
    let parent_log = parent_log.unwrap_or_else(|| {
        // There's no concise way to bubble an Err back up through an unwrap_or_else call, and
        // this error is sufficiently fatal to panic anyway, so .expect() here for initial log
        // entry handling.
        database
            .insert_fero_log(NewFeroLog::default())
            .expect("Couldn't insert root log entry");
        database
            .last_fero_log_entry()
            .expect("Couldn't retrieve root log entry")
            .expect("Couldn't retrieve root log entry")
    });

    let new_fero_log = logging::create_fero_log(
        request_type,
        result,
        &hsm_logs,
        last_hsm_index,
        new_hsm_index.unwrap_or(last_hsm_index),
        &parent_log,
        identification,
    )?;

    database.insert_fero_log(new_fero_log)?;

    Ok(())
}
