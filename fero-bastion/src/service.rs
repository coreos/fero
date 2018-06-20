use std::sync::Arc;

use chrono::prelude::*;
use futures::Future;
use grpcio::{self, ChannelBuilder, EnvBuilder, RpcContext, RpcStatus, UnarySink};
use protobuf::well_known_types::Timestamp;

use fero_proto::fero::*;
use fero_proto::fero_grpc::*;

#[derive(Clone)]
pub struct FeroBastion {
    client: Arc<FeroClient>,
}

impl FeroBastion {
    pub fn new(address: &str, port: u16) -> FeroBastion {
        let env = Arc::new(EnvBuilder::new().build());
        let channel = ChannelBuilder::new(env).connect(&format!("{}:{}", address, port));
        let client = Arc::new(FeroClient::new(channel));

        FeroBastion { client }
    }
}

macro_rules! bastion_call {
    ($func:ident, $req_ty:ty, $resp_ty:ty, $err_msg:expr) => (
        fn $func(&self, ctx: RpcContext, req: $req_ty, sink: UnarySink<$resp_ty>) {
            match self.client.$func(&req) {
                Ok(response) => ctx.spawn(sink.success(response).map_err(move |err| {
                    error!("failed to reply {:?}: {:?}", req, err)
                })),
                Err(err) => {
                    info!("{}: {}", $err_msg, err);
                    ctx.spawn(
                        sink.fail(RpcStatus {
                            status: grpcio::RpcStatusCode::PermissionDenied,
                            details: Some($err_msg.to_string()),
                        }).map_err(move |err| error!("failed to reply {:?}: {:?}", req, err)),
                    )
                }
            }
        }
    )
}

macro_rules! bastion_call_with_timestamp {
    ($func:ident, $req_ty:ty, $resp_ty:ty, $err_msg:expr) => (
        fn $func(&self, ctx: RpcContext, mut req: $req_ty, sink: UnarySink<$resp_ty>) {
            let chrono_timestamp = Utc::now().naive_utc();
            let mut timestamp = Timestamp::new();
            timestamp.set_seconds(chrono_timestamp.timestamp());
            timestamp.set_nanos(chrono_timestamp.timestamp_subsec_nanos() as i32);
            req.set_timestamp(timestamp);

            match self.client.$func(&req) {
                Ok(response) => ctx.spawn(sink.success(response).map_err(move |err| {
                    error!("failed to reply {:?}: {:?}", req, err)
                })),
                Err(err) => {
                    info!("{}: {}", $err_msg, err);
                    ctx.spawn(
                        sink.fail(RpcStatus {
                            status: grpcio::RpcStatusCode::PermissionDenied,
                            details: Some($err_msg.to_string()),
                        }).map_err(move |err| error!("failed to reply {:?}: {:?}", req, err)),
                    )
                }
            }
        }
    )
}

impl Fero for FeroBastion {
    bastion_call_with_timestamp!(
        sign_payload,
        SignRequest,
        SignResponse,
        "Failed to sign payload"
    );

    bastion_call_with_timestamp!(
        set_secret_key_threshold,
        ThresholdRequest,
        ThresholdResponse,
        "Failed to update secret key threshold"
    );

    bastion_call_with_timestamp!(
        set_user_key_weight,
        WeightRequest,
        WeightResponse,
        "Failed to update user key weight"
    );

    bastion_call!(
        get_logs,
        LogRequest,
        LogResponse,
        "Failed to get audit logs"
    );
}
