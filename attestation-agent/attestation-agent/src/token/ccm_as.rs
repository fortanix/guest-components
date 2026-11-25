// Copyright (c) Fortanix, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::config::{UnmeasuredCcmAsConfig, ccm_as::CcmAsConfig};
use anyhow::{Context, Result, bail};
use client::{Attest, BaremetalSevSnp, BaremetalTdx, NodeAgentClient, certificate::AppCert};
use hex::FromHex;
use kbs_types::Tee;
use serde::Serialize;
use std::sync::LazyLock;
use std::time::SystemTime;
use tokio::sync::Mutex;
use tracing::{info, warn};
use x509_cert::Certificate;
use x509_cert::der::DecodePem;

#[derive(Serialize, Clone)]
struct Message {
    cert_pem: String,
    key_pem: String,
}

// Serializes concurrent get_token() calls onto a single attestation instead of each one
// independently re-attesting — CDH fires several overlapping key requests per image decrypt.
// Reused while still valid per the cert's own dates (see cert_is_currently_valid); no separate TTL.
static CACHE: LazyLock<Mutex<Option<Message>>> = LazyLock::new(|| Mutex::new(None));

// Make sure the cert is currently valid. If it can't be parsed, treat it as invalid so
// it gets refreshed.
fn cert_is_currently_valid(cert_pem: &str) -> bool {
    match Certificate::from_pem(cert_pem.as_bytes()) {
        Ok(cert) => {
            let now = SystemTime::now();
            let validity = cert.tbs_certificate.validity;
            now >= validity.not_before.to_system_time() && now < validity.not_after.to_system_time()
        }
        Err(e) => {
            warn!(
                "ccm_as: failed to parse cached cert for validity check ({e}), treating as invalid"
            );
            false
        }
    }
}

pub struct CcmAsTokenGetter {
    ccm_domain_names: Vec<String>,
    ccm_appconfig_id: Option<String>,
}

impl CcmAsTokenGetter {
    pub fn new(config: &CcmAsConfig, unmeasured_config: Option<&UnmeasuredCcmAsConfig>) -> Self {
        Self {
            ccm_domain_names: config.ccm_domain_names.clone(),
            ccm_appconfig_id: unmeasured_config.and_then(|config| config.ccm_appconfig_id.clone()),
        }
    }

    pub async fn get_token(&self) -> Result<Vec<u8>> {
        let mut cache = CACHE.lock().await;

        if let Some(cached) = cache.as_ref() {
            if cert_is_currently_valid(&cached.cert_pem) {
                info!("ccm_as: reusing cached workload credential");
                return serde_json::to_vec(cached).context("ccm_as: serialize token");
            }
            info!("ccm_as: cached workload credential no longer valid, re-attesting");
        } else {
            info!("ccm_as: workload credential not found in cache, performing attestation");
        }

        let (cert_pem, key_pem) = self.attest_and_issue_cert().await?;
        info!("ccm_as: attested and issued a new workload credential");
        let message = Message { cert_pem, key_pem };
        *cache = Some(message.clone());
        drop(cache);

        serde_json::to_vec(&message).context("ccm_as: serialize token")
    }

    async fn attest_and_issue_cert(&self) -> Result<(String, String)> {
        let tee = attester::detect_tee_type();
        let maybe_appconfig_id_str = self
            .ccm_appconfig_id
            .as_deref()
            .map(|id| id.trim().to_owned());

        // `AppCert::request_app_cert_csr` in the `fortanix/attestation/client` crate reads the
        // workload cert's subject alt names from this env var rather than taking them as a parameter
        unsafe { std::env::set_var("APP_CERT_ALT_NAMES", self.ccm_domain_names.join(",")) };
        if let Some(appconfig_id_str) = maybe_appconfig_id_str.as_ref() {
            if <[u8; 32]>::from_hex(appconfig_id_str).is_err() {
                bail!(
                    "ccm_as: invalid SHA-256 ccm_appconfig_id: {}",
                    appconfig_id_str
                );
            }
            unsafe { std::env::set_var("APPCONFIG_ID", appconfig_id_str) };
        }
        let appconfig_id_bytes = maybe_appconfig_id_str.map(|id| id.into_bytes());

        let mut app_cert = tokio::task::spawn_blocking(AppCert::init)
            .await
            .context("ccm_as: AppCert::init task failed")?
            .context("ccm_as: AppCert::init")?;
        let na_client = NodeAgentClient::init()
            .await
            .context("ccm_as: NodeAgentClient::init")?;

        match tee {
            Tee::Snp => {
                BaremetalSevSnp::attest_and_request_app_cert(
                    &mut app_cert,
                    &na_client,
                    appconfig_id_bytes,
                )
                .await
                .context("ccm_as: SNP attest_and_request_app_cert")?;
            }
            Tee::Tdx => {
                BaremetalTdx::attest_and_request_app_cert(
                    &mut app_cert,
                    &na_client,
                    appconfig_id_bytes,
                )
                .await
                .context("ccm_as: TDX attest_and_request_app_cert")?;
            }
            other => bail!("ccm_as: unsupported TEE {other:?}"),
        }

        let cert_pem = app_cert
            .cert
            .clone()
            .ok_or_else(|| anyhow::anyhow!("ccm_as: CCM returned no workload certificate"))?;
        let key_pem = app_cert
            .key
            .write_private_pem_string()
            .context("ccm_as: export workload private key")?;

        Ok((cert_pem, key_pem))
    }
}
