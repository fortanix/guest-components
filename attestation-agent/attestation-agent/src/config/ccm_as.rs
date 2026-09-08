// Copyright (c) Fortanix, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//

use serde::Deserialize;

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct CcmAsConfig {
    /// Domain name(s) CCM issues the workload certificate for.
    pub ccm_domain_names: Vec<String>,

    /// Optional Fortanix AppConfig ID (hex-encoded).
    #[serde(default)]
    pub ccm_appconfig_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::CcmAsConfig;

    #[test]
    fn deserializes_multiple_domain_names_and_appconfig_id() {
        let cfg: CcmAsConfig = toml::from_str(
            r#"
            ccm_domain_names = ["fortanix.com", "example.com"]
            ccm_appconfig_id = "deadbeef"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.ccm_domain_names, vec!["fortanix.com", "example.com"]);
        assert_eq!(cfg.ccm_appconfig_id, Some("deadbeef".to_string()));
    }

    #[test]
    fn ccm_appconfig_id_defaults_to_none() {
        let cfg: CcmAsConfig = toml::from_str(r#"ccm_domain_names = ["fortanix.com"]"#).unwrap();
        assert_eq!(cfg.ccm_appconfig_id, None);
    }

    #[test]
    fn ccm_domain_names_must_be_an_array_not_a_bare_string() {
        // A bare string is exactly the initdata mistake this config format
        // invites (["fortanix.com"] vs "fortanix.com") - TOML happily
        // parses either as a value, so this has to be caught at
        // deserialize time, not assumed away.
        let result: Result<CcmAsConfig, _> = toml::from_str(r#"ccm_domain_names = "fortanix.com""#);
        assert!(result.is_err());
    }

    #[test]
    fn ccm_domain_names_is_required() {
        let result: Result<CcmAsConfig, _> = toml::from_str("");
        assert!(result.is_err());
    }
}
