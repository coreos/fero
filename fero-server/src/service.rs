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

use std::io::Write;

use byteorder::{BigEndian, WriteBytesExt};
use chrono::prelude::*;
use failure::Error;
use futures::Future;
use grpcio::{self, RpcContext, RpcStatus, UnarySink};
use pretty_good::{HashAlgorithm, Packet};
use protobuf::{Message, repeated::RepeatedField, well_known_types::Timestamp};

use database::Configuration;
use fero_proto::fero::*;
use fero_proto::fero_grpc::*;
use fero_proto::log::*;
use hsm::*;
use logging;

#[derive(Clone)]
pub struct FeroService {
    database: Configuration,
    signer: Hsm,
}

impl Fero for FeroService {
    fn sign_payload(&self, ctx: RpcContext, mut req: SignRequest, sink: UnarySink<SignResponse>) {
        let timestamp = NaiveDateTime::from_timestamp(
            req.get_timestamp().get_seconds(),
            req.get_timestamp().get_nanos() as u32,
        );

        let operation_result = self.sign_payload(
            req.get_identification(),
            req.get_payload(),
            req.get_sigType(),
        );

        let logged_result = match operation_result {
            Ok(_) => OperationResult::Success,
            Err(_) => OperationResult::Failure,
        };

        logging::log_operation(
            &self.signer,
            &self.database,
            OperationType::Sign,
            logged_result,
            Some(req.take_identification()),
            timestamp,
        ).unwrap_or_else(|e| panic!("Failed to log an operation: {}", e));

        match operation_result {
            Ok(signature) => {
                let mut response = SignResponse::new();
                response.set_payload(signature);
                ctx.spawn(sink.success(response).map_err(move |err| {
                    error!("failed to reply {:?}: {:?}", req, err)
                }))
            }
            Err(e) => {
                warn!("Failed to sign payload: {}", e);
                ctx.spawn(sink.fail(RpcStatus {
                    status: grpcio::RpcStatusCode::PermissionDenied,
                    details: Some(format!("{}", e)),
                }).map_err(move |err| error!("failed to reply {:?}: {:?}", req, err)))
            }
        };
    }

    fn set_secret_key_threshold(
        &self,
        ctx: RpcContext,
        mut req: ThresholdRequest,
        sink: UnarySink<ThresholdResponse>,
    ) {
        let timestamp = NaiveDateTime::from_timestamp(
            req.get_timestamp().get_seconds(),
            req.get_timestamp().get_nanos() as u32,
        );

        let operation_result = self.set_secret_key_threshold(
            req.get_identification(),
            req.get_threshold(),
        );

        let logged_result = match operation_result {
            Ok(_) => OperationResult::Success,
            Err(_) => OperationResult::Failure,
        };

        logging::log_operation(
            &self.signer,
            &self.database,
            OperationType::Threshold,
            logged_result,
            Some(req.take_identification()),
            timestamp,
        ).unwrap_or_else(|e| panic!("Failed to log an operation: {}", e));

        match operation_result {
            Ok(_) => ctx.spawn(sink.success(ThresholdResponse::new()).map_err(move |err| {
                error!("failed to reply {:?}: {:?}", req, err)
            })),
            Err(e) => ctx.spawn(sink.fail(RpcStatus {
                status: grpcio::RpcStatusCode::InvalidArgument,
                details: Some(format!("{}", e)),
            }).map_err(move |err| error!("failed to reply {:?}: {:?}", req, err))),
        }
    }

    fn set_user_key_weight(
        &self,
        ctx: RpcContext,
        mut req: WeightRequest,
        sink: UnarySink<WeightResponse>,
    ) {
        let timestamp = NaiveDateTime::from_timestamp(
            req.get_timestamp().get_seconds(),
            req.get_timestamp().get_nanos() as u32,
        );

        let operation_result = self.set_user_key_weight(
            req.get_identification(),
            req.get_userKeyId(),
            req.get_weight(),
        );

        let logged_result = match operation_result {
            Ok(_) => OperationResult::Success,
            Err(_) => OperationResult::Failure,
        };

        logging::log_operation(
            &self.signer,
            &self.database,
            OperationType::Weight,
            logged_result,
            Some(req.take_identification()),
            timestamp,
        ).unwrap_or_else(|e| panic!("Failed to log an operation: {}", e));

        match operation_result {
            Ok(_) => ctx.spawn(sink.success(WeightResponse::new()).map_err(move |err| {
                error!("failed to reply {:?}: {:?}", req, err)
            })),
            Err(e) => ctx.spawn(sink.fail(RpcStatus {
                status: grpcio::RpcStatusCode::InvalidArgument,
                details: Some(format!("{}", e)),
            }).map_err(move |err| error!("failed to reply {:?}: {:?}", req, err))),
        }
    }

    fn get_logs(&self, ctx: RpcContext, req: LogRequest, sink: UnarySink<LogResponse>) {
        match self.get_logs(req.get_minIndex()) {
            Ok(logs) => {
                let mut response = LogResponse::new();
                response.set_logs(RepeatedField::from_vec(logs));

                ctx.spawn(sink.success(response).map_err(move |err| {
                    error!("failed to reply {:?}: {:?}", req, err)
                }))
            }
            Err(err) => ctx.spawn(sink.fail(RpcStatus {
                status: grpcio::RpcStatusCode::Aborted,
                details: Some(format!("Failed to retrive logs: {}", err)),
            }).map_err(move |err| error!("failed to reply {:?}: {:?}", req, err))),
        }
    }
}

impl FeroService {
    pub fn new(database: Configuration, signer: Hsm) -> FeroService {
        FeroService { database, signer }
    }

    fn set_secret_key_threshold(
        &self,
        ident: &Identification,
        threshold: i32,
    ) -> Result<(), Error> {
        let mut payload = Vec::new();
        payload.write(ident.get_secretKeyName().as_bytes())?;
        payload.write_i32::<BigEndian>(threshold)?;

        let (conn, _) = self.database.authenticate(ident, &payload)?;

        conn.set_secret_key_threshold(ident.get_secretKeyId(), threshold)
    }

    fn set_user_key_weight(
        &self,
        ident: &Identification,
        user_key_id: u64,
        weight: i32,
    ) -> Result<(), Error> {
        let mut payload = Vec::new();
        payload.write(ident.get_secretKeyName().as_bytes())?;
        payload.write_u64::<BigEndian>(user_key_id)?;
        payload.write_i32::<BigEndian>(weight)?;

        let (conn, _) = self.database.authenticate(ident, &payload)?;

        if let Some(user) = conn.get_user_key(user_key_id)? {
            conn.upsert_user_key_weight(user, weight)
        } else {
            bail!("No such user")
        }
    }

    pub(crate) fn sign_payload(
        &self,
        ident: &Identification,
        payload: &[u8],
        sig_type: SignRequest_SignatureType,
    ) -> Result<Vec<u8>, Error>{
        let (database, data) = self.database.authenticate(ident, payload)?;

        let hsm_key = database.get_hsm_key_id()?;

        let out = match sig_type {
            SignRequest_SignatureType::PGP => match database.get_pgp_key_id() {
                Some(pgp_key_id) => self.signer
                    .create_pgp_signature(data, hsm_key, HashAlgorithm::Sha256)
                    .and_then(|mut sig| {
                        sig.set_signer(pgp_key_id);
                        Packet::Signature(sig).to_bytes()
                    })
                    .map(Vec::from)?,
                None => bail!("Tried to use non-PGP key for PGP signature"),
            }
            SignRequest_SignatureType::PKCS1V1_5 => self.signer.create_rsa_signature(data, hsm_key)?
        };

        Ok(out)
    }

    fn get_logs(&self, min_index: i32) -> Result<Vec<LogEntry>, Error> {
        self.database
            .fero_logs_since(min_index)?
            .iter()
            .map(|fero_db_log| -> Result<_, Error> {
                let hsm_logs = self.database
                    .associated_hsm_logs(fero_db_log)?
                    .iter()
                    .map(|hsm_db_log| {
                        let mut hsm_log = HsmLog::new();

                        hsm_log.set_id(hsm_db_log.hsm_index as u32);
                        hsm_log.set_command(hsm_db_log.command as u32);
                        hsm_log.set_data_length(hsm_db_log.data_length as u32);
                        hsm_log.set_session_key(hsm_db_log.session_key as u32);
                        hsm_log.set_target_key(hsm_db_log.target_key as u32);
                        hsm_log.set_second_key(hsm_db_log.second_key as u32);
                        hsm_log.set_result(hsm_db_log.result as u32);
                        hsm_log.set_systick(hsm_db_log.systick as u32);
                        hsm_log.set_hash(hsm_db_log.hash.clone());

                        hsm_log
                    })
                    .collect::<Vec<_>>();

                let mut entry = LogEntry::new();

                entry.set_id(fero_db_log.id);
                entry.set_operation_type(match fero_db_log.request_type {
                    OperationType::Sign => LogEntry_OperationType::SIGN,
                    OperationType::Threshold => LogEntry_OperationType::THRESHOLD,
                    OperationType::Weight => LogEntry_OperationType::WEIGHT,
                    OperationType::AddSecret => LogEntry_OperationType::ADD_SECRET,
                    OperationType::AddUser => LogEntry_OperationType::ADD_USER,
                });
                let mut timestamp = Timestamp::new();
                timestamp.set_seconds(fero_db_log.timestamp.timestamp());
                timestamp.set_nanos(fero_db_log.timestamp.timestamp_subsec_nanos() as i32);
                entry.set_timestamp(timestamp);
                entry.set_result(match fero_db_log.result {
                    OperationResult::Success => LogEntry_OperationResult::SUCCESS,
                    OperationResult::Failure => LogEntry_OperationResult::FAILURE,
                });
                if let Some(ref ident_bytes) = fero_db_log.identification {
                    let mut ident = Identification::new();
                    ident.merge_from_bytes(ident_bytes)?;
                    entry.set_ident(ident);
                }
                entry.set_hsm_logs(RepeatedField::from_vec(hsm_logs));
                entry.set_hash(fero_db_log.hash.clone());

                Ok(entry)
            })
            .collect::<Result<Vec<_>, Error>>()
    }
}
