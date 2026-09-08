// Copyright (c) Fortanix, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//

// DSM client: authenticate with the CCM-issued workload certificate, then
// either export a key by UUID or have DSM decrypt a wrapped key.

use anyhow::{Context, Result, bail};
use base64::Engine;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The wrapped DEK and the GCM parameters DSM needs to unwrap it.
pub(super) struct WrappedKey {
    pub cipher: Vec<u8>,
    pub iv: Vec<u8>,
    pub tag: Vec<u8>,
}

// Cert chain + private key in one PEM blob become the reqwest TLS client
// identity. DSM authenticates the mTLS handshake.
fn build_mtls_client(cert_pem: &str, key_pem: &str) -> Result<Client> {
    let mut identity_pem = String::with_capacity(cert_pem.len() + key_pem.len() + 1);
    identity_pem.push_str(cert_pem.trim_end());
    identity_pem.push('\n');
    identity_pem.push_str(key_pem);

    let identity = reqwest::Identity::from_pem(identity_pem.as_bytes())
        .context("build TLS identity from cert and key failed")?;

    Client::builder()
        .use_rustls_tls()
        .identity(identity)
        .build()
        .context("build mTLS client failed")
}

pub(super) async fn unwrap_key(
    endpoint: &str,
    cert_pem: &str,
    key_pem: &str,
    app_uuid: &str,
    key_uuid: Uuid,
) -> Result<Vec<u8>> {
    let http = build_mtls_client(cert_pem, key_pem)?;
    let token = authenticate(&http, endpoint, app_uuid).await?;
    export_sobject(&http, endpoint, &token, key_uuid).await
}

/// Decrypt a wrapped DEK with the given KEK in DSM and return the plaintext.
/// The KEK never leaves DSM - only the plaintext DEK comes back.
pub(super) async fn decrypt_key(
    endpoint: &str,
    cert_pem: &str,
    key_pem: &str,
    app_uuid: &str,
    kek_uuid: Uuid,
    wrapped_key: WrappedKey,
) -> Result<Vec<u8>> {
    let http = build_mtls_client(cert_pem, key_pem)?;
    let token = authenticate(&http, endpoint, app_uuid).await?;
    decrypt_sobject(&http, endpoint, &token, kek_uuid, wrapped_key).await
}

async fn authenticate(http: &Client, endpoint: &str, app_uuid: &str) -> Result<String> {
    let url = format!("{endpoint}/sys/v1/session/auth");
    let basic = base64::engine::general_purpose::STANDARD.encode(format!("{app_uuid}:"));

    let resp = http
        .post(&url)
        .header(reqwest::header::AUTHORIZATION, format!("Basic {basic}"))
        .send()
        .await
        .context("DSM auth POST failed")?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        bail!("DSM auth returned {status}: {body}");
    }

    #[derive(Deserialize)]
    struct AuthResp {
        access_token: String,
    }

    let auth: AuthResp = resp
        .json()
        .await
        .context("DSM auth response was not valid JSON")?;
    Ok(auth.access_token)
}

async fn export_sobject(
    http: &Client,
    endpoint: &str,
    token: &str,
    kek_uuid: Uuid,
) -> Result<Vec<u8>> {
    let url = format!("{endpoint}/crypto/v1/keys/export");

    #[derive(Serialize)]
    struct ExportReq {
        kid: String,
    }

    #[derive(Deserialize)]
    struct ExportResp {
        value: String,
    }

    let resp = http
        .post(&url)
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
        .json(&ExportReq {
            kid: kek_uuid.to_string(),
        })
        .send()
        .await
        .context("DSM export POST failed")?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        bail!("DSM export returned {status}: {body}");
    }

    let body: ExportResp = resp
        .json()
        .await
        .context("DSM export response was not valid JSON")?;

    base64::engine::general_purpose::STANDARD
        .decode(body.value.as_bytes())
        .context("DSM export 'value' was not valid base64")
}

async fn decrypt_sobject(
    http: &Client,
    endpoint: &str,
    token: &str,
    kek_uuid: Uuid,
    wrapped_key: WrappedKey,
) -> Result<Vec<u8>> {
    let url = format!("{endpoint}/crypto/v1/decrypt");
    let engine = &base64::engine::general_purpose::STANDARD;

    #[derive(Serialize)]
    struct KeyRef {
        kid: String,
    }

    #[derive(Serialize)]
    struct DecryptReq {
        key: KeyRef,
        alg: &'static str,
        mode: &'static str,
        cipher: String,
        iv: String,
        tag: String,
    }

    #[derive(Deserialize)]
    struct DecryptResp {
        plain: String,
    }

    let resp = http
        .post(&url)
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
        .json(&DecryptReq {
            key: KeyRef {
                kid: kek_uuid.to_string(),
            },
            alg: "AES",
            mode: "GCM",
            cipher: engine.encode(&wrapped_key.cipher),
            iv: engine.encode(&wrapped_key.iv),
            tag: engine.encode(&wrapped_key.tag),
        })
        .send()
        .await
        .context("DSM decrypt POST failed")?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        bail!("DSM decrypt returned {status}: {body}");
    }

    let body: DecryptResp = resp
        .json()
        .await
        .context("DSM decrypt response was not valid JSON")?;

    engine
        .decode(body.plain.as_bytes())
        .context("DSM decrypt 'plain' was not valid base64")
}
