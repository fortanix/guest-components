// Copyright (c) Fortanix, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//

// DSM client: authenticate with the CCM-issued workload certificate, then
// either export a key by UUID or have DSM decrypt a wrapped key.

use anyhow::{Context, Result};
use openssl::pkey::PKey;
use sdkms::SdkmsClient;
use sdkms::api_model::*;
use simple_hyper_client::HttpsConnector;
use simple_hyper_client::blocking::Client as HttpClient;
use uuid::Uuid;

/// Build a synchronous `SdkmsClient`.
fn build_client(
    endpoint: &str,
    cert_pem: &str,
    key_pem: &str,
    app_uuid: &str,
) -> Result<SdkmsClient> {
    let app_uuid = Uuid::parse_str(app_uuid)
        .with_context(|| format!("DSM app id is not a valid UUID: {app_uuid}"))?;
    let key_pkcs8 = PKey::private_key_from_pem(key_pem.as_bytes())
        .context("parse workload private key")?
        .private_key_to_pem_pkcs8()
        .context("convert workload private key to PKCS#8")?;

    let identity = native_tls::Identity::from_pkcs8(cert_pem.as_bytes(), &key_pkcs8)
        .context("build TLS identity from cert and key failed")?;
    let tls = native_tls::TlsConnector::builder()
        .identity(identity)
        .build()
        .context("build TLS connector failed")?;

    SdkmsClient::builder()
        .with_api_endpoint(endpoint)
        .with_http_client(HttpClient::with_connector(HttpsConnector::new(tls.into())))
        .build()
        .context("build DSM client failed")?
        .authenticate_with_cert(Some(&app_uuid))
        .context("DSM authentication with the workload certificate failed")
}

/// Export a key by UUID and return its raw value.
pub(super) async fn unwrap_key(
    endpoint: String,
    cert_pem: String,
    key_pem: String,
    app_uuid: String,
    key_uuid: Uuid,
) -> Result<Vec<u8>> {
    tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
        let client = build_client(&endpoint, &cert_pem, &key_pem, &app_uuid)?;
        client
            .export_sobject(&SobjectDescriptor::Kid(key_uuid))
            .context("DSM export_sobject")?
            .value
            .map(Vec::from)
            .context("DSM export returned no key material")
    })
    .await
    .context("DSM export operation panicked")?
}

/// The wrapped DEK and the GCM parameters DSM needs to unwrap it.
pub(super) struct WrappedKey {
    pub cipher: Vec<u8>,
    pub iv: Vec<u8>,
    pub tag: Vec<u8>,
}

/// Decrypt a DEK with the given KEK in DSM and return the plaintext.
pub(super) async fn decrypt_key(
    endpoint: String,
    cert_pem: String,
    key_pem: String,
    app_uuid: String,
    kek_uuid: Uuid,
    wrapped_key: WrappedKey,
) -> Result<Vec<u8>> {
    tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
        let client = build_client(&endpoint, &cert_pem, &key_pem, &app_uuid)?;
        let resp = client
            .decrypt(&DecryptRequest {
                key: Some(SobjectDescriptor::Kid(kek_uuid)),
                alg: Some(Algorithm::Aes),
                mode: Some(CryptMode::Symmetric(CipherMode::Gcm)),
                cipher: wrapped_key.cipher.into(),
                iv: Some(wrapped_key.iv.into()),
                ad: None,
                tag: Some(wrapped_key.tag.into()),
            })
            .context("DSM decrypt")?;
        Ok(resp.plain.into())
    })
    .await
    .context("DSM decrypt operation panicked")?
}
