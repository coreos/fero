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

use byteorder::{BigEndian, WriteBytesExt};
use failure::Error;
use futures::Future;
use grpcio::{self, RpcContext, RpcStatus, UnarySink};
use pretty_good::{HashAlgorithm, Packet};

use database::Configuration;
use fero_proto::fero::*;
use fero_proto::fero_grpc::*;
use hsm::*;


#[derive(Clone)]
pub struct FeroService {
    database: Configuration,
    signer: Hsm,
}

impl Fero for FeroService {
    fn sign_payload(&self, ctx: RpcContext, req: SignRequest, sink: UnarySink<SignResponse>) {
        match self.sign_payload(
            req.get_identification(),
            req.get_payload(),
        ) {
            Ok(signature) => {
                let mut response = SignResponse::new();
                response.set_payload(signature);

                ctx.spawn(sink.success(response).map_err(move |err| {
                    error!("failed to reply {:?}: {:?}", req, err)
                }))
            }
            Err(err) => {
                info!("Failed to sign payload: {}", err);
                ctx.spawn(
                    sink.fail(RpcStatus {
                        status: grpcio::RpcStatusCode::PermissionDenied,
                        details: Some("Failed to sign payload".to_string()),
                    }).map_err(move |err| error!("failed to reply {:?}: {:?}", req, err)),
                )
            }
        }
    }

    fn set_secret_key_threshold(
        &self,
        ctx: RpcContext,
        req: ThresholdRequest,
        sink: UnarySink<ThresholdResponse>,
    ) {
        match self.set_secret_key_threshold(req.get_identification(), req.get_threshold()) {
            Ok(()) => {
                ctx.spawn(sink.success(ThresholdResponse::new()).map_err(move |err| {
                    error!("failed to reply {:?}: {:?}", req, err)
                }))
            }
            Err(err) => {
                info!("Failed to update secret key threshold: {}", err);
                ctx.spawn(
                    sink.fail(RpcStatus {
                        status: grpcio::RpcStatusCode::InvalidArgument,
                        details: Some("Failed to update secret key threshold".to_string()),
                    }).map_err(move |err| error!("failed to reply {:?}: {:?}", req, err)),
                )
            }
        }
    }

    fn set_user_key_weight(
        &self,
        ctx: RpcContext,
        req: WeightRequest,
        sink: UnarySink<WeightResponse>,
    ) {
        match self.set_user_key_weight(
            req.get_identification(),
            req.get_userKeyId(),
            req.get_weight(),
        ) {
            Ok(()) => {
                ctx.spawn(sink.success(WeightResponse::new()).map_err(move |err| {
                    error!("failed to reply {:?}: {:?}", req, err)
                }))
            }
            Err(err) => {
                info!("Failed to update user key weight: {}", err);
                ctx.spawn(
                    sink.fail(RpcStatus {
                        status: grpcio::RpcStatusCode::InvalidArgument,
                        details: Some("Failed to update user key weight".to_string()),
                    }).map_err(move |err| error!("failed to reply {:?}: {:?}", req, err)),
                )
            }
        }
    }

    fn get_logs(&self, ctx: RpcContext, req: LogRequest, sink: UnarySink<LogResponse>) {
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
        payload.write_u64::<BigEndian>(ident.get_secretKeyId())?;
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
        payload.write_u64::<BigEndian>(ident.get_secretKeyId())?;
        payload.write_u64::<BigEndian>(user_key_id)?;
        payload.write_i32::<BigEndian>(weight)?;

        let (conn, _) = self.database.authenticate(ident, &payload)?;

        if let Some(user) = conn.get_user_key(user_key_id)? {
            conn.upsert_user_key_weight(ident.get_secretKeyId(), user, weight)
        } else {
            bail!("No such user")
        }
    }

    pub(crate) fn sign_payload(
        &self,
        ident: &Identification,
        payload: &[u8],
    ) -> Result<Vec<u8>, Error>{
        let (database, data) = self.database.authenticate(ident, payload)?;

        let hsm_key = database.get_hsm_key_id()?;
        let mut signature = self.signer.create_signature(data, hsm_key, HashAlgorithm::Sha256)?;
        signature.set_signer(ident.secretKeyId as u64);

        let pgp_packet = Packet::Signature(signature);
        let packet_bytes = pgp_packet.to_bytes()?;

        Ok(Vec::from(packet_bytes))
    }
}
