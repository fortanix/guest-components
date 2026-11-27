// Copyright (c) Fortanix, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//
//! KEK lifecycle and DEK wrapping with Fortanix DSM.
//!
//! The KEK is created non-exportable: EXPORT is absent from its key_ops, so the
//! raw key material cannot leave DSM. Wrapping happens server-side, and the IV
//! and tag go in the annotation's `annotations` map rather than at the top
//! level.

use anyhow::*;
use base64::Engine as _;
use reqwest::Url;
use sdkms::SdkmsClient;
use sdkms::api_model::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::OnceCell;
use tracing::{debug, info, warn};
use uuid::Uuid;

use super::AnnotationPacket;
use crate::grpc::KekMode;

/// Canonical prefix of a DSM kid. `ResourceUri` requires three path segments,
/// so repo = `dsm`, type = `key`, tag = the KEK UUID.
const KID_PREFIX: &str = "kbs:///dsm/key/";

/// The two-segment form this crate used to emit. Not a valid `ResourceUri`; still
/// accepted on input so a previously recorded kid keeps working.
const LEGACY_KID_PREFIX: &str = "kbs:///dsm/";

/// The annotation's `provider`, selecting the KMS that unwraps the DEK.
/// Names the KMS, not the plugin. Must match `DecryptorProvider::Dsm`.
const DSM_PROVIDER: &str = "dsm";

/// GCM tag length, in bits for DSM's `tag_len` and in bytes for checking the
/// response. Keep the two in step.
const TAG_LEN_BITS: usize = 128;
const TAG_LEN: usize = TAG_LEN_BITS / 8;

/// Which KEK to wrap a layer's DEK with, when the caller did not name an
/// existing one via `keyid`. Borrowed from the long-lived `KeyProvider`, so
/// `shared` and `seq` persist across the per-layer `wrap_key` calls of one image.
pub(crate) struct KekPolicy<'a> {
    pub mode: KekMode,
    pub name: Option<&'a str>,
    pub shared: &'a OnceCell<(Uuid, String)>,
    pub seq: &'a AtomicUsize,
}

/// Create or look up a non-exportable KEK in DSM, have DSM wrap `optsdata` with
/// it, and return a JSON-serialized `AnnotationPacket`. Called from
/// `grpc::wrap_key` when `--dsm-endpoint` and `--dsm-api-key-file` are given.
pub(crate) async fn encrypt_optsdata(
    dsm_endpoint: &Url,
    dsm_api_key: &str,
    optsdata: &[u8],
    params: Vec<String>,
    policy: KekPolicy<'_>,
) -> Result<String> {
    let keyid = params.first().and_then(|p| parse_keyid(p));
    let engine = base64::engine::general_purpose::STANDARD;

    let dsm_uuid_str = keyid.as_deref().and_then(parse_dsm_kid);

    let (kek_uuid, kid) = match keyid.as_deref() {
        Some(keyid) if dsm_uuid_str.is_some() => {
            let uuid_str = dsm_uuid_str.expect("guarded by the match arm");
            let uuid =
                Uuid::parse_str(uuid_str).with_context(|| format!("invalid UUID in '{keyid}'"))?;
            if !keyid.starts_with(KID_PREFIX) {
                warn!(
                    "keyid '{keyid}' uses the legacy two-segment form; emitting {KID_PREFIX}{uuid}"
                );
            }
            // Always emit the canonical form, whichever was supplied.
            let kid = format!("{KID_PREFIX}{uuid}");
            info!("using existing DSM KEK {kid}");
            (uuid, kid)
        }
        Some(keyid) if keyid.starts_with("kbs:///") => bail!(
            "DSM endpoint configured but keyid is KBS-style: '{keyid}'. \
             Use '{KID_PREFIX}<uuid>' to reference an existing DSM KEK, \
             or omit keyid to auto-create."
        ),
        // An empty keyid is the same as no keyid at all. A non-empty one is a
        // desired sobject name, which takes precedence over `--kek-name`.
        other => {
            let name = other.filter(|k| !k.is_empty()).or(policy.name);
            new_kek(dsm_api_key, dsm_endpoint, &policy, name).await?
        }
    };

    // DSM does the AES-GCM encrypt; we never see the KEK.
    let (cipher, iv, tag) = encrypt_dek(
        dsm_api_key.to_owned(),
        dsm_endpoint.clone(),
        kek_uuid,
        optsdata.to_vec(),
    )
    .await?;

    // `iv` and `tag` go in `annotations`, and nowhere else. `wrap_type` is
    // omitted because the KMS branch ignores it; the algorithm is fixed by
    // `provider`.
    let mut crypt_annotations = serde_json::Map::new();
    crypt_annotations.insert("iv".to_owned(), engine.encode(iv).into());
    crypt_annotations.insert("tag".to_owned(), engine.encode(tag).into());

    let annotation = AnnotationPacket {
        kid,
        wrapped_data: engine.encode(cipher),
        iv: None,
        wrap_type: None,
        provider: Some(DSM_PROVIDER.to_owned()),
        annotations: Some(crypt_annotations),
    };
    serde_json::to_string(&annotation).map_err(|_| anyhow!("Serialize annotation failed"))
}

/// Return the UUID part of a DSM kid, or `None` if this is not one.
///
/// Accepts the canonical `kbs:///dsm/key/<uuid>` and the legacy `kbs:///dsm/<uuid>`.
/// The canonical prefix must be tried first: it is a superstring of the legacy one, so
/// stripping the legacy prefix from a canonical kid would leave `key/<uuid>`.
fn parse_dsm_kid(keyid: &str) -> Option<&str> {
    keyid
        .strip_prefix(KID_PREFIX)
        .or_else(|| keyid.strip_prefix(LEGACY_KID_PREFIX))
}

/// Parse the `keyid` field out of `key1=val1::key2=val2::...`.
fn parse_keyid(params_str: &str) -> Option<String> {
    params_str
        .split("::")
        .filter_map(|f| f.split_once('='))
        .find(|(k, _)| *k == "keyid")
        .map(|(_, v)| v.to_owned())
}

/// Resolve the KEK for this layer when no existing one was named.
async fn new_kek(
    api_key: &str,
    endpoint: &Url,
    policy: &KekPolicy<'_>,
    name: Option<&str>,
) -> Result<(Uuid, String)> {
    match policy.mode {
        // First layer here creates the KEK; concurrent calls await it.
        KekMode::Shared => policy
            .shared
            .get_or_try_init(|| create_named_kek(api_key, endpoint, name.map(str::to_owned)))
            .await
            .cloned(),

        // Names must stay distinct, or `--kek-name foo` yields N sobjects
        // all called "foo".
        KekMode::PerLayer => {
            let name = name.map(|n| format!("{n}-{}", policy.seq.fetch_add(1, Ordering::Relaxed)));
            create_named_kek(api_key, endpoint, name).await
        }
    }
}

/// Create a fresh KEK in DSM, defaulting to an auto-generated sobject name, and
/// return `(uuid, full_kid_uri)`.
async fn create_named_kek(
    api_key: &str,
    endpoint: &Url,
    name: Option<String>,
) -> Result<(Uuid, String)> {
    let name = name.unwrap_or_else(|| format!("ccm-kbc-kek-{}", Uuid::new_v4()));
    let uuid = create_kek(api_key.to_owned(), endpoint.clone(), name).await?;
    let kid = format!("{KID_PREFIX}{uuid}");
    info!("created DSM KEK {kid}");
    Ok((uuid, kid))
}

/// Build a synchronous `SdkmsClient`. Callers wrap it in `spawn_blocking`.
fn build_client(api_key: &str, dsm_endpoint: &Url) -> Result<SdkmsClient> {
    SdkmsClient::builder()
        .with_api_endpoint(dsm_endpoint.as_str())
        .with_api_key(api_key)
        .build()
        .context("build DSM client")
}

/// Create an AES-256 KEK in DSM and return its UUID. EXPORT is left out of
/// key_ops, so the raw key material cannot leave DSM.
pub(crate) async fn create_kek(api_key: String, dsm_endpoint: Url, name: String) -> Result<Uuid> {
    let log_name = name.clone();
    debug!("creating non-exportable KEK in DSM: {log_name}");
    let kid = tokio::task::spawn_blocking(move || -> Result<Uuid> {
        let client = build_client(&api_key, &dsm_endpoint)?;
        let req = SobjectRequest {
            name: Some(name),
            obj_type: Some(ObjectType::Aes),
            key_size: Some(256),
            key_ops: Some(
                KeyOperations::ENCRYPT | KeyOperations::DECRYPT | KeyOperations::APPMANAGEABLE,
            ),
            description: Some(
                "KEK for CoCo encrypted image; non-exportable; created by coco_keyprovider".into(),
            ),
            ..Default::default()
        };
        let sobject = client.create_sobject(&req).context("DSM create_sobject")?;
        sobject.kid.context("DSM did not return a kid")
    })
    .await
    .context("DSM create_sobject task panicked")??;
    info!("DSM KEK created: name={log_name} kid={kid}");
    Ok(kid)
}

/// Encrypt a DEK with the given KEK in DSM and return `(cipher, iv, tag)`.
/// AES-256-GCM, with DSM generating the IV. The three stay separate because
/// `/crypto/v1/decrypt` takes them as distinct fields, so the tag is not
/// appended to `cipher`.
pub(crate) async fn encrypt_dek(
    api_key: String,
    dsm_endpoint: Url,
    kek_uuid: Uuid,
    plain_dek: Vec<u8>,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    debug!("encrypting DEK in DSM with KEK={kek_uuid}");
    tokio::task::spawn_blocking(move || -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let plain_len = plain_dek.len();
        let client = build_client(&api_key, &dsm_endpoint)?;
        let req = EncryptRequest {
            plain: plain_dek.into(),
            alg: Algorithm::Aes,
            key: Some(SobjectDescriptor::Kid(kek_uuid)),
            mode: Some(CryptMode::Symmetric(CipherMode::Gcm)),
            iv: None, // let DSM generate
            ad: None,
            tag_len: Some(TAG_LEN_BITS),
        };
        let resp = client.encrypt(&req).context("DSM encrypt")?;
        let cipher: Vec<u8> = resp.cipher.into();
        let iv: Vec<u8> = resp
            .iv
            .context("DSM did not return iv for GCM encryption")?
            .into();

        let tag: Vec<u8> = resp
            .tag
            .context("DSM did not return tag for GCM encryption")?
            .into();
        if tag.len() != TAG_LEN {
            bail!(
                "DSM returned unexpected GCM tag length: {} bytes (expected {TAG_LEN})",
                tag.len()
            );
        }

        // GCM ciphertext matches the plaintext length and the tag is separate,
        // so anything else means DSM's response format changed. Catch it here
        // rather than on the node.
        let expected = plain_len;
        if cipher.len() != expected {
            bail!(
                "DSM wrap produced unexpected size: {} bytes (expected {expected})",
                cipher.len(),
            );
        }
        debug!(
            "DSM wrap ok: plain={plain_len}B cipher={}B iv={}B tag={}B",
            cipher.len(),
            iv.len(),
            tag.len()
        );
        Ok((cipher, iv, tag))
    })
    .await
    .context("DSM encrypt task panicked")?
}

#[cfg(test)]
mod tests {
    use super::*;
    use resource_uri::{ResourcePluginPath, ResourceUri};
    use rstest::rstest;

    const UUID: &str = "9a4f5bd3-d3d2-4e88-98c7-eedd9f04eefd";

    #[rstest]
    #[case::canonical("kbs:///dsm/key/9a4f5bd3-d3d2-4e88-98c7-eedd9f04eefd", Some(UUID))]
    #[case::legacy("kbs:///dsm/9a4f5bd3-d3d2-4e88-98c7-eedd9f04eefd", Some(UUID))]
    #[case::other_repository("kbs:///default/key/1", None)]
    #[case::kek_name("my-kek", None)]
    fn parse_dsm_kid_accepts_both_forms(#[case] keyid: &str, #[case] expected: Option<&str>) {
        assert_eq!(parse_dsm_kid(keyid), expected);
    }

    /// The whole point of the three-segment kid: it has to survive `ResourceUri`,
    /// which every consumer of the annotation deserializes the `kid` through.
    #[test]
    fn emitted_kid_is_a_valid_resource_uri() {
        let kid = format!("{KID_PREFIX}{UUID}");
        let uri = ResourceUri::try_from(&kid[..]).expect("kid must parse as a KBS resource URI");
        let path = ResourcePluginPath::try_from(uri).expect("kid must have three segments");
        assert_eq!(path.repo, "dsm");
        assert_eq!(path.r#type, "key");
        assert_eq!(path.tag, UUID);
    }

    /// The form this crate used to emit. Accepted on input, never emitted.
    #[test]
    fn legacy_kid_is_not_a_valid_resource_uri() {
        let uri = ResourceUri::try_from("kbs:///dsm/9a4f5bd3-d3d2-4e88-98c7-eedd9f04eefd")
            .expect("two-segment form still parses as a ResourceUri");
        assert!(ResourcePluginPath::try_from(uri).is_err());
    }
}
