// Copyright (c) Fortanix, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::config::ccm_as::CcmAsConfig;
use anyhow::{Context, Result, bail};
use client::{Attest, BaremetalSevSnp, BaremetalTdx, NodeAgentClient, certificate::AppCert};
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
    pub fn new(config: &CcmAsConfig) -> Self {
        Self {
            ccm_domain_names: config.ccm_domain_names.clone(),
            ccm_appconfig_id: config.ccm_appconfig_id.clone(),
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

        let appconfig_id = self
            .ccm_appconfig_id
            .as_deref()
            .map(|id| hex::decode(id.trim()))
            .transpose()
            .context("ccm_as: ccm_appconfig_id is not valid hex")?;

        // `AppCert::request_app_cert_csr` in the `fortanix/attestation/client` crate reads the
        // workload cert's subject alt names from this env var rather than taking them as a parameter
        unsafe { std::env::set_var("APP_CERT_ALT_NAMES", self.ccm_domain_names.join(",")) };

        tokio::task::spawn_blocking(move || -> Result<(String, String)> {
            let mut app_cert = AppCert::init().context("ccm_as: AppCert::init")?;
            let na_client = NodeAgentClient::init().context("ccm_as: NodeAgentClient::init")?;

            match tee {
                Tee::Snp => {
                    BaremetalSevSnp::attest_and_request_app_cert(
                        &mut app_cert,
                        &na_client,
                        appconfig_id,
                    )
                    .context("ccm_as: SNP attest_and_request_app_cert")?;
                }
                Tee::Tdx => {
                    BaremetalTdx::attest_and_request_app_cert(
                        &mut app_cert,
                        &na_client,
                        appconfig_id,
                    )
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
        })
        .await
        .context("ccm_as: spawn_blocking join")?
    }
}

#[cfg(test)]
mod tests {
    use super::cert_is_currently_valid;

    // Self-signed, CN=ccm_as-test. Generated once for this test; not_before/
    // not_after are baked into the cert so it doesn't depend on wall-clock
    // time at generation, only at comparison.
    const VALID_CERT: &str = "-----BEGIN CERTIFICATE-----
MIICuDCCAaCgAwIBAgIUEUdXuSfxBbbrB29OmESJOXWw7mQwDQYJKoZIhvcNAQEL
BQAwFjEUMBIGA1UEAwwLY2NtX2FzLXRlc3QwHhcNMjYwOTA2MTgwMzM4WhcNMzYw
OTA0MTgwMzM4WjAWMRQwEgYDVQQDDAtjY21fYXMtdGVzdDCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBAMRTQ6sRp3W125lHn+f/oTael9+YtNdbURuYiTkm
cMfWjYIIDgwdR1SCtYaJxhI7z8/nyb7+/KY6vla9hagCz3J06O/ebr7FhGQqxpk9
epyhuYAYjIpoz+R8AAU0O2SnruClSahfHncLp7WyxMRg9tWiQJP20dpGmxMMVgiM
IdgiE6FjLbleagDfiiLLz08xcdcOC/jCF2JYdIUF8+vUajKmjjRtSy7bdPD83+/Q
nhijENnGq49gaPyfn6lxUbkFUnKM9ByW354TPfG3D7ImaRCu9ONiU2c84/WKWkpC
FHtx3ri4moltfnXYX3AInDumEQ3WcddKfOMABxplIQbmn1UCAwEAATANBgkqhkiG
9w0BAQsFAAOCAQEABTnffpswY1VB46Ykly1/KAUVu/zcU8B5/JVxysRxl0MdBqeE
bHNimEHGeTeo+iQKr5dKsV9Eihs8rXqafuaThXBTNMiqqFaHRwNuAn3ey/96pzex
MkmLTgIoF18alo9p4ysOpiHYXRQw+r7XHu+EJetSEtFWhvBWPlh3TBrfZSBvUQjx
r1Vi/PvAUiTCvh1uqnIvmV57AdhrU0lCuqW+ZG43oTpT6UGxyVH3luPMtQLr0lXw
G1aRjT0Gp+flSjPRR6tgXZ92MhNU9F89E0MYBf+FGZB7V/hAQ7y9MJkE228EGuJX
fl1gqt2iQ9eHzcbEDISrEejTfqg5TvVh1epaww==
-----END CERTIFICATE-----";

    // Same subject, but not_before/not_after are both in the past.
    const EXPIRED_CERT: &str = "-----BEGIN CERTIFICATE-----
MIICuDCCAaCgAwIBAgIUeiTxg1V31/TkVtVXptGmPKFbCvIwDQYJKoZIhvcNAQEL
BQAwFjEUMBIGA1UEAwwLY2NtX2FzLXRlc3QwHhcNMjQwOTA3MTgwMzM4WhcNMjUw
OTA3MTgwMzM4WjAWMRQwEgYDVQQDDAtjY21fYXMtdGVzdDCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBAL2NuTI56lkMhPZZ+opzKIpBCb3T76lirVQhJyZR
f3trOkxTaxzDf3Rl7++U3qgVOcBuqqsbgix90zaZWoJs/L2NlcPuPz2WDSENkhIJ
DjoAXq+LQkQ8ulMzeNn+r7iqwMk4GgH017C/VJO4DRjavYcujfe0X0LRHblDEibf
kYeygB+qicWa8eYPFqduvPcWxJYa5OQIqZGxxoi1UtgXu7enS4bBHkyA7saKSr4i
mSmD+ITDGUduNnCzEd8gb79ycrgYmeWARuG1JoMg97NDFkmGPyRCgy72QEzP9KO6
asmc69edRpcybKpyJU+j1dBiJpmnSAJ3Opm/tLrNYo2gkwsCAwEAATANBgkqhkiG
9w0BAQsFAAOCAQEAVVhbA3h6Zk3/SlcNYdZFv4+Ur1bwoyLO+DRzG8eGt/ngaV3c
e3jpyYxblPtIQASBQ9u0MAOGEFvWtkuLIZPcJBy0HkoIb0iVo65aH1T8/mqQpi2g
F3PcZ54/xPvZipMGswBK2ZiFGxuK1sNSa0l4gDIOSEIInf2q+QdV8Gk75bSust7E
hnZ7qHFN8uXhtY8T3F2vDwuuU6FuHDKgWkcWKRenFSiGDjcRm/QqmDJvRPI05Ggp
5mTSwamJ7X0rOsTqKg6kfHSdUG2dGQj1bDgbiCwwZkaTEFjYHOaVqYcYikcHDDtA
Wn/fTpmWfQ26lDwVArEIBGVmloEEENm8Biv0gg==
-----END CERTIFICATE-----";

    #[test]
    fn currently_valid_cert_is_valid() {
        assert!(cert_is_currently_valid(VALID_CERT));
    }

    #[test]
    fn expired_cert_is_not_valid() {
        assert!(!cert_is_currently_valid(EXPIRED_CERT));
    }

    #[test]
    fn unparseable_pem_is_treated_as_not_valid() {
        assert!(!cert_is_currently_valid("not a certificate"));
    }
}
