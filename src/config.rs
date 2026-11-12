//! Non-secret settings: the client id per environment, the loopback ports
//! registered as redirect URIs, and the practice profiles `--org` names.
//!
//! Everything here is local to one machine. A practice profile names a
//! household's practice, so it lives in `~/.config/athena/config.json` and
//! never in the repository.

use std::collections::BTreeMap;

use pk_cli_core::transport::require_secure_url;
use pk_cli_core::CliError;
use serde::{Deserialize, Serialize};

use crate::env::Environment;

/// The redirect URIs `docs/registration.md` asks a registration to list:
/// `http://127.0.0.1:47816/callback` first, `:47817` when the first is busy.
pub const DEFAULT_REDIRECT_PORTS: [u16; 2] = [47816, 47817];

/// The built-in profile for athenahealth's Preview sandbox.
pub const SANDBOX_ORG: &str = "sandbox";

/// `~/.config/athena/config.json`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Config {
    /// Loopback ports registered as redirect URIs, tried in order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect_ports: Option<Vec<u16>>,
    /// The app's client id in each environment. Not a secret, but athenahealth's
    /// terms call it a key that is not to be shared, so it is configuration, never
    /// code.
    #[serde(default, skip_serializing_if = "ClientIds::is_empty")]
    pub client_ids: ClientIds,
    /// Practice profiles by slug.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub practices: BTreeMap<String, Practice>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ClientIds {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub production: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom: Option<String>,
}

impl ClientIds {
    fn is_empty(&self) -> bool {
        self.preview.is_none() && self.production.is_none() && self.custom.is_none()
    }

    pub fn get(&self, env: Environment) -> Option<&str> {
        match env {
            Environment::Preview => self.preview.as_deref(),
            Environment::Production => self.production.as_deref(),
            Environment::Custom => self.custom.as_deref(),
        }
    }

    pub fn set(&mut self, env: Environment, value: Option<String>) {
        let slot = match env {
            Environment::Preview => &mut self.preview,
            Environment::Production => &mut self.production,
            Environment::Custom => &mut self.custom,
        };
        *slot = value;
    }
}

/// One practice, as `--org <slug>` names it: which athenaOne practice and
/// patient-portal brand a sign-in is for. Practice id, brand id and chart
/// sharing group id together make athenahealth's site-specific FHIR base URL,
/// which is also the `aud` of the sign-in, so the patient picker offers only
/// that practice's records. Without them the sign-in is athenahealth-wide.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Practice {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default)]
    pub environment: Environment,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub practice_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub brand_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub csg_id: Option<String>,
    /// The practice's patient portal host (`<n>-<brand>.portal.athenahealth.com`),
    /// for reference: where the portal account is registered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub portal_host: Option<String>,
    /// A FHIR base URL in full, overriding the one built from the ids.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fhir_base: Option<String>,
    /// A client id for this practice alone, overriding the environment's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
}

impl Practice {
    /// athenahealth's Preview sandbox, signed in athenahealth-wide; its PHR
    /// test patient is synthetic (`docs/api.md`).
    pub fn sandbox() -> Practice {
        Practice {
            name: Some("athenahealth Preview sandbox (synthetic test patients)".into()),
            environment: Environment::Preview,
            ..Practice::default()
        }
    }

    /// The FHIR base URL: the explicit one, or the environment's
    /// site-specific base when all three ids are set, or its global base.
    pub fn fhir_base(&self) -> Result<String, CliError> {
        if let Some(base) = &self.fhir_base {
            return Ok(base.trim_end_matches('/').to_string());
        }
        let api = self.environment.api_base().ok_or_else(|| {
            CliError::Usage("a practice in the custom environment needs --fhir-base".into())
        })?;
        match (&self.practice_id, &self.brand_id, &self.csg_id) {
            (Some(p), Some(b), Some(c)) => Ok(format!("{api}/{p}/brand/{b}/csg/{c}/fhir/r4")),
            (None, None, None) => Ok(format!("{api}/fhir/r4")),
            _ => Err(CliError::Usage(
                "a practice needs all three of --practice-id, --brand-id and --csg-id, or none \
                 of them"
                    .into(),
            )),
        }
    }

    pub fn display_name(&self, slug: &str) -> String {
        self.name.clone().unwrap_or_else(|| slug.to_string())
    }

    /// Check what was set before it is saved.
    pub fn validate(&self) -> Result<(), CliError> {
        for (flag, value) in [
            ("--practice-id", &self.practice_id),
            ("--brand-id", &self.brand_id),
            ("--csg-id", &self.csg_id),
        ] {
            if let Some(v) = value {
                validate_digits(flag, v)?;
            }
        }
        if let Some(host) = &self.portal_host {
            if host.is_empty()
                || !host
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
            {
                return Err(CliError::Usage(format!(
                    "--portal-host `{host}` is not a host name"
                )));
            }
        }
        if let Some(base) = &self.fhir_base {
            require_secure_url(base)?;
        }
        if let Some(name) = &self.name {
            if name.chars().any(char::is_control) || name.len() > 200 {
                return Err(CliError::Usage(
                    "--name must be one line of at most 200 characters".into(),
                ));
            }
        }
        if self.environment == Environment::Custom && self.fhir_base.is_none() {
            return Err(CliError::Usage(
                "a practice in the custom environment needs --fhir-base".into(),
            ));
        }
        self.fhir_base().map(|_| ())
    }
}

/// A practice profile as `orgs list` shows it.
#[derive(Debug, Clone)]
pub struct Org {
    pub slug: String,
    pub practice: Practice,
    pub builtin: bool,
}

impl Config {
    /// The profile `--org` names. The built-in `sandbox` applies unless a
    /// configured profile of that name replaces it.
    pub fn practice(&self, slug: &str) -> Result<Practice, CliError> {
        if let Some(p) = self.practices.get(slug) {
            return Ok(p.clone());
        }
        if slug == SANDBOX_ORG {
            return Ok(Practice::sandbox());
        }
        Err(CliError::NotFound(format!("no practice profile `{slug}`"))
            .with_remedy("list them with `athena orgs list`, or add one with `athena config set practice <SLUG> ...`"))
    }

    /// Every profile, configured ones first, then the built-in sandbox.
    pub fn orgs(&self) -> Vec<Org> {
        let mut out: Vec<Org> = self
            .practices
            .iter()
            .map(|(slug, practice)| Org {
                slug: slug.clone(),
                practice: practice.clone(),
                builtin: false,
            })
            .collect();
        if !self.practices.contains_key(SANDBOX_ORG) {
            out.push(Org {
                slug: SANDBOX_ORG.into(),
                practice: Practice::sandbox(),
                builtin: true,
            });
        }
        out
    }

    /// The client id a sign-in to `practice` uses.
    pub fn client_id_for(&self, practice: &Practice) -> Result<String, CliError> {
        if let Some(id) = &practice.client_id {
            return Ok(id.clone());
        }
        let env = practice.environment;
        self.client_ids.get(env).map(str::to_string).ok_or_else(|| {
            CliError::Usage(format!(
                "no client id is configured for the {env} environment"
            ))
            .with_remedy(format!(
                "register athena with athenahealth (docs/registration.md), then run `athena \
                     config set client-id <ID> --env {env}`"
            ))
        })
    }

    pub fn redirect_ports(&self) -> Vec<u16> {
        match &self.redirect_ports {
            Some(ports) if !ports.is_empty() => ports.clone(),
            _ => DEFAULT_REDIRECT_PORTS.to_vec(),
        }
    }
}

/// A profile slug: 1 to 40 of `a-z`, `0-9` and `-`, starting with a letter or digit.
pub fn validate_slug(slug: &str) -> Result<(), CliError> {
    let ok = !slug.is_empty()
        && slug.len() <= 40
        && slug
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !slug.starts_with('-');
    if ok {
        Ok(())
    } else {
        Err(CliError::Usage(format!(
            "`{slug}` is not a profile name: use 1 to 40 of a-z, 0-9 and -"
        )))
    }
}

/// A client id as athenahealth issues them (Okta: letters and digits).
pub fn validate_client_id(id: &str) -> Result<(), CliError> {
    let ok = !id.is_empty()
        && id.len() <= 100
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.');
    if ok {
        Ok(())
    } else {
        Err(CliError::Usage(
            "a client id is letters, digits, `-`, `_` and `.` only".into(),
        ))
    }
}

pub fn validate_digits(flag: &str, value: &str) -> Result<(), CliError> {
    if !value.is_empty() && value.len() <= 12 && value.chars().all(|c| c.is_ascii_digit()) {
        Ok(())
    } else {
        Err(CliError::Usage(format!("{flag} takes digits only")))
    }
}

/// `47816,47817` as a list of ports.
pub fn parse_ports(value: &str) -> Result<Vec<u16>, CliError> {
    let ports: Result<Vec<u16>, _> = value.split(',').map(|p| p.trim().parse::<u16>()).collect();
    match ports {
        Ok(ports) if !ports.is_empty() && ports.iter().all(|p| *p >= 1024) => Ok(ports),
        _ => Err(CliError::Usage(
            "redirect-ports takes a comma-separated list of ports from 1024 to 65535".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn practice(p: Option<&str>, b: Option<&str>, c: Option<&str>) -> Practice {
        Practice {
            practice_id: p.map(Into::into),
            brand_id: b.map(Into::into),
            csg_id: c.map(Into::into),
            ..Practice::default()
        }
    }

    #[test]
    fn the_site_specific_base_needs_all_three_ids() {
        assert_eq!(
            practice(Some("195900"), Some("1"), Some("1"))
                .fhir_base()
                .unwrap(),
            "https://api.platform.athenahealth.com/195900/brand/1/csg/1/fhir/r4"
        );
        assert_eq!(
            practice(None, None, None).fhir_base().unwrap(),
            "https://api.platform.athenahealth.com/fhir/r4"
        );
        assert!(practice(Some("195900"), None, None).fhir_base().is_err());
    }

    #[test]
    fn the_sandbox_is_global_preview() {
        assert_eq!(
            Practice::sandbox().fhir_base().unwrap(),
            "https://api.preview.platform.athenahealth.com/fhir/r4"
        );
    }

    #[test]
    fn a_configured_profile_replaces_the_builtin_sandbox() {
        let mut cfg = Config::default();
        assert!(cfg.orgs().iter().any(|o| o.builtin));
        cfg.practices
            .insert(SANDBOX_ORG.into(), practice(None, None, None));
        assert!(cfg.orgs().iter().all(|o| !o.builtin));
        assert_eq!(
            cfg.practice(SANDBOX_ORG).unwrap().environment,
            Environment::Production
        );
    }

    #[test]
    fn a_missing_client_id_says_how_to_get_one() {
        let err = Config::default()
            .client_id_for(&Practice::sandbox())
            .unwrap_err();
        assert_eq!(err.exit_code(), 2);
        assert!(err.remedy().unwrap().contains("--env preview"));
    }

    #[test]
    fn the_config_round_trips_through_the_store() {
        let mut cfg = Config {
            redirect_ports: Some(vec![47816]),
            ..Config::default()
        };
        cfg.client_ids
            .set(Environment::Preview, Some("0oaPREVIEW".into()));
        cfg.practices.insert(
            "clinic".into(),
            practice(Some("195900"), Some("1"), Some("1")),
        );
        let loaded = store_round_trip(&cfg);
        assert_eq!(loaded, cfg);
    }

    fn store_round_trip(cfg: &Config) -> Config {
        let dir = tempfile::tempdir().unwrap();
        let store = pk_cli_config::ConfigStore::new("athena")
            .with_override(Some(dir.path().join("config.json")));
        store.save(cfg).unwrap();
        store.load().unwrap()
    }

    #[test]
    fn slugs_and_ports_are_checked() {
        assert!(validate_slug("my-clinic").is_ok());
        assert!(validate_slug("My Clinic").is_err());
        assert!(validate_slug("-x").is_err());
        assert_eq!(parse_ports("47816, 47817").unwrap(), vec![47816, 47817]);
        assert!(parse_ports("80").is_err());
        assert!(parse_ports("").is_err());
    }
}
