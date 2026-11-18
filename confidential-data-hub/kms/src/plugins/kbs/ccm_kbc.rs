// Copyright (c) Fortanix, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//

mod aa_token_client;
mod annotations;
mod config;
mod dsm_client;
mod identity;

use super::{Kbc, ResourceUri};
use crate::{Annotations, Error, Result};
use annotations::DsmCryptAnnotations;
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD};
use config::CcmKbcConfig;
use serde_json::Value;
use tracing::info;

pub struct CcmKbc {
    dsm_endpoint: String,
    dsm_app_id: String,
    aa_socket: String,
}

impl CcmKbc {
    pub(crate) async fn new(uri: &str, aa_socket: &str) -> Result<Self> {
        let cfg = CcmKbcConfig::from_env_or_cmdline()?;
        let uri = uri.trim().trim_end_matches('/');
        let dsm_endpoint = if uri.is_empty() {
            cfg.dsm_endpoint.ok_or_else(|| {
                Error::KbsClientError(
                    "ccm_kbc: no DSM endpoint configured - set [kbc].url in cdh.toml \
                     (delivered via initdata), or pass ccm.kbc_dsm_endpoint= on the \
                     kernel cmdline"
                        .to_string(),
                )
            })?
        } else {
            info!("ccm_kbc: DSM endpoint sourced from aa_kbc_params uri");
            uri.to_string()
        };

        let dsm_app_id = cfg.dsm_app_id.ok_or_else(|| {
            Error::KbsClientError(
                "ccm_kbc: no DSM app id configured - set cdh.toml \
                 [kbc_configs.ccm_kbc].dsm_app_id, CCM_KBC_APP_ID, or ccm.kbc_app_id="
                    .to_string(),
            )
        })?;

        info!("ccm_kbc: KBC loaded (dsm_endpoint={dsm_endpoint})");

        Ok(Self {
            dsm_endpoint,
            dsm_app_id,
            aa_socket: aa_socket.to_string(),
        })
    }
}

#[async_trait]
impl Kbc for CcmKbc {
    async fn get_resource(&mut self, rid: ResourceUri) -> Result<Vec<u8>> {
        let key_uuid = identity::parse_dsm_uuid(&rid)?;

        let credential = aa_token_client::get_ccm_as_credential(&self.aa_socket)
            .await
            .map_err(|e| Error::KbsClientError(format!("ccm_kbc: {e:#}")))?;

        let bytes = dsm_client::unwrap_key(
            self.dsm_endpoint.clone(),
            credential.cert_pem,
            credential.key_pem,
            self.dsm_app_id.clone(),
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

    async fn decrypt_with_kek(
        &mut self,
        rid: ResourceUri,
        ciphertext: &[u8],
        annotations: &Annotations,
    ) -> Result<Vec<u8>> {
        let kek_uuid = identity::parse_dsm_uuid(&rid)?;

        let crypt: DsmCryptAnnotations = serde_json::from_value(Value::Object(annotations.clone()))
            .map_err(|e| {
                Error::KbsClientError(format!(
                    "ccm_kbc: annotation is missing the iv/tag needed to decrypt in DSM: {e:?}"
                ))
            })?;

        let iv = STANDARD.decode(&crypt.iv).map_err(|e| {
            Error::KbsClientError(format!("ccm_kbc: annotation iv is not valid base64: {e:?}"))
        })?;
        let tag = STANDARD.decode(&crypt.tag).map_err(|e| {
            Error::KbsClientError(format!(
                "ccm_kbc: annotation tag is not valid base64: {e:?}"
            ))
        })?;

        let credential = aa_token_client::get_ccm_as_credential(&self.aa_socket)
            .await
            .map_err(|e| Error::KbsClientError(format!("ccm_kbc: {e:#}")))?;

        let plaintext = dsm_client::decrypt_key(
            self.dsm_endpoint.clone(),
            credential.cert_pem,
            credential.key_pem,
            self.dsm_app_id.clone(),
            kek_uuid,
            dsm_client::WrappedKey {
                cipher: ciphertext.to_vec(),
                iv,
                tag,
            },
        )
        .await
        .map_err(|e| Error::KbsClientError(format!("ccm_kbc: DSM decrypt: {e:#}")))?;

        info!(
            "ccm_kbc: DSM returned {} bytes plaintext for KEK {kek_uuid}",
            plaintext.len()
        );
        Ok(plaintext)
    }
}
