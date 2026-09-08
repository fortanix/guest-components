// Copyright (c) Fortanix, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//

use serde::{Deserialize, Serialize};

/// Serialized [`crate::Annotations`] for the DSM decrypt-in-KMS path.
///
/// Both fields are base64, exactly as DSM returned them at wrap time and as
/// `/crypto/v1/decrypt` expects them back.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct DsmCryptAnnotations {
    /// AES-GCM initialisation vector.
    pub iv: String,
    /// AES-GCM tag, kept separate from the ciphertext.
    pub tag: String,
}
