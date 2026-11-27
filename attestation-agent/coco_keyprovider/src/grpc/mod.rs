// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::enc_mods;
use anyhow::*;
use base64::Engine;
#[cfg(feature = "ccm_kbc")]
use clap::ValueEnum;
use jwt_simple::prelude::Ed25519KeyPair;
use protos::grpc::cdh::keyprovider::{
    KeyProviderKeyWrapProtocolInput, KeyProviderKeyWrapProtocolOutput,
    key_provider_service_server::{KeyProviderService, KeyProviderServiceServer},
};
use reqwest::Url;
use std::net::SocketAddr;
use std::path::PathBuf;
#[cfg(feature = "ccm_kbc")]
use std::sync::atomic::AtomicUsize;
use tokio::fs;
#[cfg(feature = "ccm_kbc")]
use tokio::sync::OnceCell;
use tonic::{Request, Response, Status, transport::Server};
use tracing::debug;
#[cfg(feature = "ccm_kbc")]
use uuid::Uuid;

use protocol::keyprovider_structs::*;

pub mod protocol;

/// How many KEKs to create in DSM for one image.
///
/// ocicrypt calls `WrapKey` once per layer, so this decides whether those calls
/// share a KEK or each create one. An explicit `keyid` parameter overrides it.
#[cfg(feature = "ccm_kbc")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum KekMode {
    /// One freshly created KEK per layer (default). Revoking one KEK in DSM
    /// makes exactly one layer undecryptable.
    #[default]
    PerLayer,

    /// One KEK for the whole image: the first layer creates it, the remaining
    /// layers reuse it. Revoking that one KEK makes the whole image
    /// undecryptable.
    Shared,
}

/// Config details for the DSM path.
#[cfg(feature = "ccm_kbc")]
pub struct DsmProvider {
    endpoint: Option<Url>,
    api_key: Option<String>,
    kek_mode: KekMode,
    kek_name: Option<String>,
    /// `(uuid, kid)` of the KEK shared by every layer in `KekMode::Shared`.
    /// `wrap_key` takes `&self` and tonic may run WrapKey calls concurrently,
    /// so `OnceCell::get_or_try_init` is what guarantees a single KEK.
    shared_kek: OnceCell<(Uuid, String)>,
    /// Suffix counter so `--kek-name foo` yields `foo-0`, `foo-1`, ... rather
    /// than N identically named sobjects.
    layer_seq: AtomicUsize,
}

pub struct KeyProvider {
    auth_private_key: Option<Ed25519KeyPair>,
    kbs: Option<Url>,
    #[cfg(feature = "ccm_kbc")]
    dsm: DsmProvider,
}

impl KeyProvider {
    pub fn new(
        auth_private_key: Option<Ed25519KeyPair>,
        kbs: Option<String>,
        #[cfg(feature = "ccm_kbc")] dsm_endpoint: Option<String>,
        #[cfg(feature = "ccm_kbc")] dsm_api_key: Option<String>,
        #[cfg(feature = "ccm_kbc")] kek_mode: KekMode,
        #[cfg(feature = "ccm_kbc")] kek_name: Option<String>,
    ) -> Result<Self> {
        let kbs = match kbs {
            Some(addr) => addr.parse().ok(),
            None => None,
        };
        #[cfg(feature = "ccm_kbc")]
        let dsm_endpoint = match dsm_endpoint {
            Some(addr) => Some(addr.parse().context("parse DSM endpoint URL")?),
            None => None,
        };

        Ok(Self {
            auth_private_key,
            kbs,
            #[cfg(feature = "ccm_kbc")]
            dsm: DsmProvider {
                endpoint: dsm_endpoint,
                api_key: dsm_api_key,
                kek_mode,
                kek_name,
                shared_kek: OnceCell::new(),
                layer_seq: AtomicUsize::new(0),
            },
        })
    }
}

#[tonic::async_trait]
impl KeyProviderService for KeyProvider {
    async fn wrap_key(
        &self,
        request: Request<KeyProviderKeyWrapProtocolInput>,
    ) -> Result<Response<KeyProviderKeyWrapProtocolOutput>, Status> {
        let input_string = String::from_utf8(
            request.into_inner().key_provider_key_wrap_protocol_input,
        )
        .map_err(|e| {
            Status::invalid_argument(format!(
                "key_provider_key_wrap_protocol_input is not legal utf8 string: {e:?}"
            ))
        })?;

        debug!("WrapKey API Request Input: {}", input_string);
        let input: KeyProviderInput = serde_json::from_str::<KeyProviderInput>(&input_string)
            .map_err(|e| {
                Status::invalid_argument(format!("parse key provider input failed: {e:?}"))
            })?;
        let optsdata = input
            .keywrapparams
            .optsdata
            .ok_or_else(|| Status::invalid_argument("illegal keywrapparams without optsdata"))?;

        let engine = base64::engine::general_purpose::STANDARD;
        let params: Vec<String> = input
            .keywrapparams
            .ec
            .ok_or_else(|| Status::invalid_argument("illegal keywrapparams without ec"))?
            .parameters
            .get("attestation-agent")
            .ok_or_else(|| {
                Status::invalid_argument("illegal encryption provider without attestation-agent")
            })?
            .iter()
            // According to
            // https://github.com/containers/ocicrypt/blob/e4a936881fb7cf4b2b8fe49e81b8232fd4c48e97/config/constructors.go#L112,
            // this Vec will only have one element anyways, but let's decode all elements of it
            // just to be sure.
            .filter_map(|p| {
                engine
                    .decode(p)
                    .ok()
                    .and_then(|st| String::from_utf8(st).ok())
            })
            .collect();

        let decoded_optsdata = engine
            .decode(optsdata)
            .map_err(|_| Status::aborted("base64 decode"))?;

        let annotation: String = {
            #[cfg(feature = "ccm_kbc")]
            {
                if let (Some(endpoint), Some(api_key)) = (&self.dsm.endpoint, &self.dsm.api_key) {
                    let policy = enc_mods::dsm::KekPolicy {
                        mode: self.dsm.kek_mode,
                        name: self.dsm.kek_name.as_deref(),
                        shared: &self.dsm.shared_kek,
                        seq: &self.dsm.layer_seq,
                    };
                    enc_mods::dsm::encrypt_optsdata(
                        endpoint,
                        api_key,
                        &decoded_optsdata,
                        params,
                        policy,
                    )
                    .await
                    .map_err(|e| Status::internal(format!("DSM encrypt failed: {e:?}")))?
                } else {
                    enc_mods::enc_optsdata_gen_anno(
                        (&self.kbs, &self.auth_private_key),
                        &decoded_optsdata,
                        params,
                    )
                    .await
                    .map_err(|e| Status::internal(format!("encrypt failed: {e:?}")))?
                }
            }
            #[cfg(not(feature = "ccm_kbc"))]
            {
                enc_mods::enc_optsdata_gen_anno(
                    (&self.kbs, &self.auth_private_key),
                    &decoded_optsdata,
                    params,
                )
                .await
                .map_err(|e| Status::internal(format!("encrypt failed: {e:?}")))?
            }
        };

        let output_struct = KeyWrapOutput {
            keywrapresults: KeyWrapResults {
                annotation: annotation.as_bytes().to_vec(),
            },
        };
        let output = serde_json::to_string(&output_struct)
            .map_err(|e| Status::internal(format!("serde json failed: {e:?}")))?
            .as_bytes()
            .to_vec();
        debug!(
            "WrapKey API output: {}",
            serde_json::to_string(&output_struct)
                .map_err(|e| Status::internal(format!("serde json failed: {e:?}")))?
        );
        let reply = KeyProviderKeyWrapProtocolOutput {
            key_provider_key_wrap_protocol_output: output,
        };
        debug!("Reply successfully!");

        Result::Ok(Response::new(reply))
    }

    async fn un_wrap_key(
        &self,
        _request: Request<KeyProviderKeyWrapProtocolInput>,
    ) -> Result<Response<KeyProviderKeyWrapProtocolOutput>, Status> {
        debug!("The UnWrapKey API is called...");
        debug!("UnWrapKey API is unimplemented!");
        Err(Status::unimplemented(
            "UnWrapKey API of sample-kbs is unimplemented!",
        ))
    }
}

pub async fn start_service(
    socket: SocketAddr,
    auth_private_key: Option<PathBuf>,
    kbs: Option<String>,
    #[cfg(feature = "ccm_kbc")] dsm_endpoint: Option<String>,
    #[cfg(feature = "ccm_kbc")] dsm_api_key_file: Option<PathBuf>,
    #[cfg(feature = "ccm_kbc")] kek_mode: KekMode,
    #[cfg(feature = "ccm_kbc")] kek_name: Option<String>,
) -> Result<()> {
    let auth_private_key = match auth_private_key {
        Some(key_path) => {
            let pem = fs::read_to_string(key_path)
                .await
                .context("open auth private key")?;

            Some(Ed25519KeyPair::from_pem(&pem)?)
        }
        None => None,
    };

    #[cfg(feature = "ccm_kbc")]
    let dsm_api_key = match dsm_api_key_file {
        Some(path) => Some(
            fs::read_to_string(&path)
                .await
                .with_context(|| format!("read DSM API key file: {}", path.display()))?
                .trim()
                .to_owned(),
        ),
        None => None,
    };

    Server::builder()
        .add_service(KeyProviderServiceServer::new(KeyProvider::new(
            auth_private_key,
            kbs,
            #[cfg(feature = "ccm_kbc")]
            dsm_endpoint,
            #[cfg(feature = "ccm_kbc")]
            dsm_api_key,
            #[cfg(feature = "ccm_kbc")]
            kek_mode,
            #[cfg(feature = "ccm_kbc")]
            kek_name,
        )?))
        .serve(socket)
        .await?;
    Ok(())
}
