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

use std::sync::Arc;

use futures::Future;
use grpcio::{self, ChannelBuilder, EnvBuilder, RpcContext, RpcStatus, UnarySink};

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

impl Fero for FeroBastion {
    bastion_call!(
        sign_payload,
        SignRequest,
        SignResponse,
        "Failed to sign payload"
    );

    bastion_call!(
        set_secret_key_threshold,
        ThresholdRequest,
        ThresholdResponse,
        "Failed to update secret key threshold"
    );

    bastion_call!(
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
