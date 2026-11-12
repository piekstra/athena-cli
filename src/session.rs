//! Signed-in patients: the token set in the keychain, one item per
//! (practice profile, patient), and a non-secret index of which items exist.
//!
//! The index (`sessions.json` beside the config, owner-only) lets `patients
//! list` and `--patient <label>` work without reading the keychain, which on
//! macOS costs a permission prompt per item for each new build.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use pk_cli_core::{CliError, Reason};
use pk_cli_secrets::CredentialStore;
use serde::{Deserialize, Serialize};

use crate::env::Environment;
use crate::oauth::TokenResponse;

/// The keychain service. `ATHENA_KEYCHAIN_SERVICE` overrides it for tests
/// only, so no test or `make verify` step reads the owner's real items.
pub const KEYCHAIN_SERVICE: &str = "piekstra.athena";
pub const KEYCHAIN_SERVICE_ENV: &str = "ATHENA_KEYCHAIN_SERVICE";

/// athenahealth: a refresh token expires 90 days after the most recent token
/// request that used or generated it.
pub const REFRESH_LIFETIME_SECS: i64 = 90 * 24 * 60 * 60;

/// Renew an access token this long before it expires.
const EXPIRY_MARGIN_SECS: i64 = 60;

/// One patient's tokens at one practice profile: one keychain JSON item.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct TokenSet {
    pub access_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// When the access token expires (Unix seconds).
    pub expires_at: i64,
    /// The scopes granted, sent again on every refresh (athenahealth requires it).
    pub scope: String,
    /// The FHIR `Patient.id` the sign-in chose.
    pub patient: String,
    pub client_id: String,
    pub fhir_base: String,
    pub token_endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// The id token's `fhirUser`: who signed in (a Patient, or a RelatedPerson
    /// for a caregiver).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fhir_user: Option<String>,
    /// The last token request that used or produced the refresh token.
    pub refreshed_at: i64,
}

impl fmt::Debug for TokenSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenSet")
            .field("access_token", &"<redacted>")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .field("expires_at", &self.expires_at)
            .field("fhir_base", &self.fhir_base)
            .finish_non_exhaustive()
    }
}

impl TokenSet {
    /// A token set from a code exchange.
    pub fn from_response(response: TokenResponse, grant: Grant, now: i64) -> TokenSet {
        TokenSet {
            expires_at: now + response.expires_in.unwrap_or(3600),
            access_token: response.access_token,
            refresh_token: response.refresh_token,
            scope: response.scope.unwrap_or_default(),
            patient: grant.patient,
            client_id: grant.client_id,
            fhir_base: grant.fhir_base,
            token_endpoint: grant.token_endpoint,
            revocation_endpoint: grant.revocation_endpoint,
            issuer: grant.issuer,
            fhir_user: grant.fhir_user,
            refreshed_at: now,
        }
    }

    /// The set after a refresh grant: a new refresh token replaces the old one
    /// only when the answer carries one.
    pub fn renewed(mut self, response: TokenResponse, now: i64) -> TokenSet {
        self.access_token = response.access_token;
        self.expires_at = now + response.expires_in.unwrap_or(3600);
        if let Some(rt) = response.refresh_token {
            self.refresh_token = Some(rt);
        }
        if let Some(scope) = response.scope {
            self.scope = scope;
        }
        self.refreshed_at = now;
        self
    }

    pub fn access_expired(&self, now: i64) -> bool {
        now + EXPIRY_MARGIN_SECS >= self.expires_at
    }

    /// When the refresh token lapses, by athenahealth's documented 90 days.
    pub fn refresh_expires_at(&self) -> Option<i64> {
        self.refresh_token
            .as_ref()
            .map(|_| self.refreshed_at + REFRESH_LIFETIME_SECS)
    }

    /// Whether a read can still succeed without a new sign-in.
    pub fn usable(&self, now: i64) -> bool {
        !self.access_expired(now) || self.refresh_expires_at().is_some_and(|at| at > now)
    }

    /// When a new sign-in will be needed.
    pub fn signin_expires_at(&self) -> i64 {
        self.refresh_expires_at().unwrap_or(self.expires_at)
    }
}

/// What a code exchange was for: everything in a [`TokenSet`] that the
/// token answer does not carry.
pub struct Grant {
    pub patient: String,
    pub client_id: String,
    pub fhir_base: String,
    pub token_endpoint: String,
    pub revocation_endpoint: Option<String>,
    pub issuer: Option<String>,
    pub fhir_user: Option<String>,
}

/// `<org>/<patient>`, the keychain account of one token set.
pub fn key(org: &str, patient: &str) -> String {
    format!("{org}/{patient}")
}

/// Where token sets live.
pub trait TokenStore {
    fn get(&self, key: &str) -> Result<Option<TokenSet>, CliError>;
    fn set(&self, key: &str, tokens: &TokenSet) -> Result<(), CliError>;
    fn delete(&self, key: &str) -> Result<bool, CliError>;
}

/// The OS keychain, service `piekstra.athena`.
pub struct KeychainStore {
    store: CredentialStore,
}

impl KeychainStore {
    pub fn new() -> Self {
        let service = std::env::var(KEYCHAIN_SERVICE_ENV)
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| KEYCHAIN_SERVICE.to_string());
        KeychainStore {
            store: CredentialStore::new(service),
        }
    }
}

impl Default for KeychainStore {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenStore for KeychainStore {
    fn get(&self, key: &str) -> Result<Option<TokenSet>, CliError> {
        self.store.get_json(key).map_err(|e| {
            if e.is_auth() {
                e
            } else {
                e.because(Reason::CredentialUnreadable)
            }
        })
    }

    fn set(&self, key: &str, tokens: &TokenSet) -> Result<(), CliError> {
        self.store.set_json(key, tokens)
    }

    fn delete(&self, key: &str) -> Result<bool, CliError> {
        self.store.delete(key)
    }
}

/// Token sets in memory, for tests.
#[derive(Default)]
pub struct MemoryStore {
    items: RefCell<BTreeMap<String, TokenSet>>,
}

impl TokenStore for MemoryStore {
    fn get(&self, key: &str) -> Result<Option<TokenSet>, CliError> {
        Ok(self.items.borrow().get(key).cloned())
    }

    fn set(&self, key: &str, tokens: &TokenSet) -> Result<(), CliError> {
        self.items.borrow_mut().insert(key.into(), tokens.clone());
        Ok(())
    }

    fn delete(&self, key: &str) -> Result<bool, CliError> {
        Ok(self.items.borrow_mut().remove(key).is_some())
    }
}

/// One signed-in patient, as the index records it. No token, no name.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionEntry {
    pub org: String,
    pub patient: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// `self` when the signed-in person is the patient, `proxy` for a caregiver.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relationship: Option<String>,
    pub environment: Environment,
    pub fhir_base: String,
    pub stored_at: String,
    /// When a new sign-in will be needed (RFC 3339), as of the last token
    /// request athena made: the refresh token's 90 days, or the access token's
    /// hour without one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signin_expires_at: Option<String>,
}

impl SessionEntry {
    pub fn key(&self) -> String {
        key(&self.org, &self.patient)
    }
}

/// `sessions.json`: which token sets exist.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SessionIndex {
    #[serde(default)]
    pub sessions: Vec<SessionEntry>,
}

impl SessionIndex {
    pub fn load(path: &Path) -> Result<SessionIndex, CliError> {
        match std::fs::read_to_string(path) {
            Ok(text) => serde_json::from_str(&text).map_err(|e| {
                CliError::Other(format!("{} is not a session index: {e}", path.display()))
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(SessionIndex::default()),
            Err(e) => Err(CliError::Other(format!("reading {}: {e}", path.display()))),
        }
    }

    /// Write owner-only, through a temporary file renamed into place.
    pub fn save(&self, path: &Path) -> Result<(), CliError> {
        let text = serde_json::to_string_pretty(self)
            .map_err(|e| CliError::Other(format!("encoding the session index: {e}")))?;
        write_private(path, text.as_bytes())
    }

    /// Add or replace the entry for (org, patient).
    pub fn upsert(&mut self, entry: SessionEntry) {
        self.sessions
            .retain(|s| !(s.org == entry.org && s.patient == entry.patient));
        self.sessions.push(entry);
    }

    pub fn remove(&mut self, org: &str, patient: &str) -> bool {
        let before = self.sessions.len();
        self.sessions
            .retain(|s| !(s.org == org && s.patient == patient));
        before != self.sessions.len()
    }

    /// The entries `--org` and `--patient` select (each optional).
    pub fn matching(&self, patient: Option<&str>, org: Option<&str>) -> Vec<&SessionEntry> {
        self.sessions
            .iter()
            .filter(|s| org.is_none_or(|o| s.org == o))
            .filter(|s| patient.is_none_or(|p| s.patient == p || s.label.as_deref() == Some(p)))
            .collect()
    }

    /// Exactly one signed-in patient, by id or label, optionally within one
    /// practice profile. With no `--patient`, the only one there is.
    pub fn resolve(
        &self,
        patient: Option<&str>,
        org: Option<&str>,
    ) -> Result<SessionEntry, CliError> {
        let found = self.matching(patient, org);
        match (found.len(), patient) {
            (1, _) => Ok(found[0].clone()),
            (0, None) if self.sessions.is_empty() => {
                Err(CliError::Auth("no patient is signed in".into())
                    .because(Reason::NoCredential)
                    .with_remedy("sign in with `athena auth login --org <ORG>`"))
            }
            (0, Some(p)) => Err(CliError::NotFound(format!(
                "no signed-in patient has the id or label `{p}`{}",
                org.map(|o| format!(" at `{o}`")).unwrap_or_default()
            ))
            .with_remedy("list them with `athena patients list`")),
            (0, None) => Err(CliError::NotFound(format!(
                "no patient is signed in at `{}`",
                org.unwrap_or_default()
            ))
            .with_remedy("list them with `athena patients list`")),
            (_, _) => Err(CliError::Usage(
                "more than one signed-in patient matches: name one with --patient <ID|LABEL> \
                 and, if needed, --org <ORG>"
                    .into(),
            )),
        }
    }
}

/// Write `bytes` to `path` readable by the owner alone, replacing it whole.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    use std::io::Write;
    let dir = path
        .parent()
        .ok_or_else(|| CliError::Other(format!("{} has no directory", path.display())))?;
    std::fs::create_dir_all(dir)
        .map_err(|e| CliError::Other(format!("creating {}: {e}", dir.display())))?;
    let tmp = dir.join(format!(
        ".{}.tmp-{}",
        path.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
        std::process::id()
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&tmp)
        .map_err(|e| CliError::Other(format!("writing {}: {e}", tmp.display())))?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|e| CliError::Other(format!("writing {}: {e}", tmp.display())))?;
    std::fs::rename(&tmp, path)
        .map_err(|e| CliError::Other(format!("replacing {}: {e}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(org: &str, patient: &str, label: Option<&str>) -> SessionEntry {
        SessionEntry {
            org: org.into(),
            patient: patient.into(),
            label: label.map(Into::into),
            relationship: None,
            environment: Environment::Preview,
            fhir_base: "https://example.invalid/fhir/r4".into(),
            stored_at: "2026-01-01T00:00:00Z".into(),
            signin_expires_at: None,
        }
    }

    fn tokens(refresh: Option<&str>, now: i64) -> TokenSet {
        TokenSet {
            access_token: "access-1".into(),
            refresh_token: refresh.map(Into::into),
            expires_at: now + 3600,
            scope: "openid".into(),
            patient: "a-1.E-1".into(),
            client_id: "client".into(),
            fhir_base: "https://example.invalid/fhir/r4".into(),
            token_endpoint: "https://example.invalid/token".into(),
            revocation_endpoint: None,
            issuer: None,
            fhir_user: None,
            refreshed_at: now,
        }
    }

    #[test]
    fn a_patient_resolves_by_id_or_label() {
        let mut index = SessionIndex::default();
        index.upsert(entry("clinic", "a-1.E-1", Some("kid-one")));
        index.upsert(entry("clinic", "a-1.E-2", Some("kid-two")));
        assert_eq!(
            index.resolve(Some("kid-two"), None).unwrap().patient,
            "a-1.E-2"
        );
        assert_eq!(
            index
                .resolve(Some("a-1.E-1"), Some("clinic"))
                .unwrap()
                .patient,
            "a-1.E-1"
        );
        assert_eq!(index.resolve(None, None).unwrap_err().exit_code(), 2);
        assert_eq!(
            index.resolve(Some("nobody"), None).unwrap_err().exit_code(),
            4
        );
        assert_eq!(
            SessionIndex::default()
                .resolve(None, None)
                .unwrap_err()
                .exit_code(),
            3
        );
    }

    #[test]
    fn upsert_replaces_the_same_patient() {
        let mut index = SessionIndex::default();
        index.upsert(entry("clinic", "a-1.E-1", Some("old")));
        index.upsert(entry("clinic", "a-1.E-1", Some("new")));
        assert_eq!(index.sessions.len(), 1);
        assert_eq!(index.sessions[0].label.as_deref(), Some("new"));
        assert!(index.remove("clinic", "a-1.E-1"));
        assert!(!index.remove("clinic", "a-1.E-1"));
    }

    #[test]
    fn a_refresh_keeps_the_old_refresh_token_when_none_comes_back() {
        let now = 1_000_000;
        let set = tokens(Some("refresh-1"), now);
        let renewed = set.renewed(
            TokenResponse {
                access_token: "access-2".into(),
                expires_in: Some(300),
                refresh_token: None,
                scope: None,
                id_token: None,
                patient: None,
            },
            now + 10,
        );
        assert_eq!(renewed.refresh_token.as_deref(), Some("refresh-1"));
        assert_eq!(renewed.expires_at, now + 310);
        assert_eq!(renewed.refreshed_at, now + 10);
        assert_eq!(renewed.scope, "openid");
    }

    #[test]
    fn usability_follows_the_refresh_token() {
        let now = 1_000_000;
        let mut set = tokens(None, now);
        set.expires_at = now - 1;
        assert!(!set.usable(now));
        set.refresh_token = Some("r".into());
        assert!(set.usable(now));
        assert!(!set.usable(now + REFRESH_LIFETIME_SECS + 1));
    }

    #[test]
    fn debug_never_prints_a_token() {
        let text = format!("{:?}", tokens(Some("refresh-secret"), 0));
        assert!(!text.contains("access-1"));
        assert!(!text.contains("refresh-secret"));
    }

    #[test]
    fn the_index_is_written_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sessions.json");
        let mut index = SessionIndex::default();
        index.upsert(entry("clinic", "a-1.E-1", None));
        index.save(&path).unwrap();
        assert_eq!(SessionIndex::load(&path).unwrap(), index);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
}
