use database::Configuration;
use failure::Error;
use futures::Future;
use gpgme::{Context, Protocol};
use grpcio::{self, RpcContext, RpcStatus, UnarySink};
pub use types::fero::*;
pub use types::fero_grpc::*;


#[derive(Clone)]
pub struct FeroService {
    database: Configuration,
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
    pub fn new(database: Configuration) -> FeroService {
        FeroService { database }
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
        let (_, data) = self.database.authenticate(ident, payload)?;
        let mut output = Vec::new();

        let mut gpg = Context::from_protocol(Protocol::OpenPgp)?;
        // TODO: Non-lexical lifetimes...
        let key = gpg.find_secret_key(format!("{:x}", ident.secretKeyId))?;
        gpg.add_signer(&key)?;
        // Needs a password
        gpg.sign_detached(&data, &mut output)?;

        Ok(output)
    }
}
