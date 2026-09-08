// Copyright (c) Fortanix, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::{Error, Result};
use resource_uri::{ResourcePluginPath, ResourceUri};
use uuid::Uuid;

const EXPECTED_URI: &str = "kbs:///dsm/key/<uuid>";

pub(super) fn parse_dsm_uuid(rid: &ResourceUri) -> Result<Uuid> {
    let uri = rid.whole_uri();
    let bad = |detail: String| {
        Error::KbsClientError(format!(
            "ccm_kbc: invalid resource uri '{uri}': {detail}; expected {EXPECTED_URI}"
        ))
    };

    let path = ResourcePluginPath::try_from(rid.clone()).map_err(|e| bad(e.to_string()))?;

    if path.repo != "dsm" {
        return Err(bad(format!(
            "repository must be 'dsm', got '{}'",
            path.repo
        )));
    }

    if path.r#type != "key" {
        return Err(bad(format!("type must be 'key', got '{}'", path.r#type)));
    }

    Uuid::parse_str(&path.tag)
        .map_err(|e| bad(format!("tag '{}' is not a valid UUID: {e}", path.tag)))
}

#[cfg(test)]
mod tests {
    use super::parse_dsm_uuid;
    use resource_uri::ResourceUri;

    fn uri(s: &str) -> ResourceUri {
        ResourceUri::try_from(s).unwrap_or_else(|e| panic!("bad test URI '{s}': {e}"))
    }

    #[test]
    fn valid_uri_returns_the_uuid() {
        let rid = uri("kbs:///dsm/key/550e8400-e29b-41d4-a716-446655440000");
        let got = parse_dsm_uuid(&rid).unwrap();
        assert_eq!(got.to_string(), "550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn wrong_repo_is_rejected() {
        let rid = uri("kbs:///notdsm/key/550e8400-e29b-41d4-a716-446655440000");
        let err = parse_dsm_uuid(&rid).unwrap_err().to_string();
        assert!(err.contains("repository must be 'dsm'"), "{err}");
    }

    #[test]
    fn wrong_type_is_rejected() {
        let rid = uri("kbs:///dsm/notkey/550e8400-e29b-41d4-a716-446655440000");
        let err = parse_dsm_uuid(&rid).unwrap_err().to_string();
        assert!(err.contains("type must be 'key'"), "{err}");
    }

    #[test]
    fn malformed_uuid_is_rejected() {
        let rid = uri("kbs:///dsm/key/not-a-uuid");
        let err = parse_dsm_uuid(&rid).unwrap_err().to_string();
        assert!(err.contains("not a valid UUID"), "{err}");
    }

    #[test]
    fn wrong_segment_count_is_rejected() {
        let rid = uri("kbs:///dsm/key/550e8400-e29b-41d4-a716-446655440000/extra");
        assert!(parse_dsm_uuid(&rid).is_err());
    }
}
