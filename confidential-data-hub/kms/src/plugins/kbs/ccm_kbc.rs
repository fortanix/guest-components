// Copyright (c) Fortanix, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//

mod aa_token_client;
mod config;
mod dsm_client;
mod identity;

use super::{Kbc, ResourceUri};
use crate::{Error, Result};
use async_trait::async_trait;
use config::CcmKbcConfig;
use tracing::{info, warn};

pub struct CcmKbc {
    dsm_endpoint: Option<String>,
    dsm_app_id: Option<String>,
    aa_socket: String,
}

impl CcmKbc {
    pub(crate) async fn new(uri: &str, aa_socket: &str) -> Result<Self> {
        let cfg = CcmKbcConfig::from_env_or_cmdline()?;
        let uri = uri.trim().trim_end_matches('/');
        let dsm_endpoint = if uri.is_empty() {
            cfg.dsm_endpoint
        } else {
            info!("ccm_kbc: DSM endpoint sourced from aa_kbc_params uri");
            Some(uri.to_string())
        };

        match &dsm_endpoint {
            Some(endpoint) => info!("ccm_kbc: KBC loaded (dsm_endpoint={endpoint})"),
            None => warn!(
                "ccm_kbc: KBC loaded with no DSM endpoint configured -- set [kbc].url \
                 in cdh.toml (delivered via initdata), or pass \
                 ccm.kbc_dsm_endpoint= on the kernel cmdline"
            ),
        }

        Ok(Self {
            dsm_endpoint,
            dsm_app_id: cfg.dsm_app_id,
            aa_socket: aa_socket.to_string(),
        })
    }
}

#[async_trait]
impl Kbc for CcmKbc {
    async fn get_resource(&mut self, rid: ResourceUri) -> Result<Vec<u8>> {
        let key_uuid = identity::parse_dsm_uuid(&rid)?;
        let dsm_endpoint = self.dsm_endpoint.as_deref().ok_or_else(|| {
            Error::KbsClientError(
                "ccm_kbc: no DSM endpoint configured - set [kbc].url in cdh.toml \
                 (delivered via initdata), or pass ccm.kbc_dsm_endpoint= on the \
                 kernel cmdline"
                    .to_string(),
            )
        })?;

        let dsm_app_id = self.dsm_app_id.as_deref().ok_or_else(|| {
            Error::KbsClientError(
                "ccm_kbc: no DSM app id configured - set cdh.toml \
                 [kbc_configs.ccm_kbc].dsm_app_id, CCM_KBC_APP_ID, or ccm.kbc_app_id="
                    .to_string(),
            )
        })?;

        let credential = aa_token_client::get_ccm_as_credential(&self.aa_socket)
            .await
            .map_err(|e| Error::KbsClientError(format!("ccm_kbc: {e:#}")))?;

        let bytes = dsm_client::unwrap_key(
            dsm_endpoint,
            &credential.cert_pem,
            &credential.key_pem,
            dsm_app_id,
            key_uuid,
        )
        .await
        .map_err(|e| Error::KbsClientError(format!("ccm_kbc: DSM key export: {e:#}")))?;

        info!(
            "ccm_kbc: DSM returned {} bytes for key {key_uuid}",
            bytes.len()
        );
        Ok(bytes)
    }
}
