use failure::Error;
use futures::Future;
use gpgme::{Context, Protocol};
use grpcio::{self, RpcContext, RpcStatus, UnarySink};
use pretty_good::{HashAlgorithm, Packet};

use database::Configuration;
use hsm::*;
pub use types::fero::*;
pub use types::fero_grpc::*;


#[derive(Clone)]
pub struct FeroService {
    database: Configuration,
    signer: HsmSigner,
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
}

impl FeroService {
    pub fn new(database: Configuration, signer: HsmSigner) -> FeroService {
        FeroService { database, signer }
    }

    fn set_user_key_weight(
        &self,
        ident: &Identification,
        user_key_id: u64,
        weight: i32,
    ) -> Result<(), Error> {
        let (conn, _) = self.database.authenticate(ident, &[weight as u8])?;

        let user = conn.upsert_user_key(user_key_id as u64)?;
        conn.upsert_user_key_weight(ident.secretKeyId as u64, user, weight)
    }

    fn sign_payload(
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
