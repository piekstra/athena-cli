//! Signed-in patients: one `pk_med_smart::SmartSession` in the keychain per
//! (practice profile, patient), at account `smart/<org>/<patient>`, and a
//! non-secret index of which items exist.
//!
//! The index (`sessions.json` beside the config, owner-only) lets `patients
//! list` and `--patient <label>` work without reading the keychain, which on
//! macOS costs a permission prompt per item for each new build.

use std::path::Path;
use std::sync::Arc;

use pk_cli_auth::token::DEFAULT_SKEW_SECS;
use pk_cli_core::{CliError, Reason};
use pk_cli_secrets::CredentialStore;
use pk_med_smart::{SessionStore, SmartSession};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::env::Environment;

/// The keychain service. `ATHENA_KEYCHAIN_SERVICE` overrides it for tests
/// only, so no test or `make verify` step reads the owner's real items.
pub const KEYCHAIN_SERVICE: &str = "piekstra.athena";
pub const KEYCHAIN_SERVICE_ENV: &str = "ATHENA_KEYCHAIN_SERVICE";

/// athenahealth: a refresh token expires 90 days after the most recent token
/// request that used or generated it.
pub const REFRESH_LIFETIME_SECS: u64 = 90 * 24 * 60 * 60;

/// Where a session keeps athenahealth's revocation endpoint, for `auth
/// logout` (`SmartSession::extra`, which renewals carry over).
pub const REVOCATION_ENDPOINT: &str = "revocation_endpoint";

/// `smart/<org>/<patient>`, the keychain account of one sign-in.
pub fn key(org: &str, patient: &str) -> String {
    pk_med_smart::account(org, patient)
}

/// Where sessions live, shareable with the FHIR client's bearer source.
pub type Store = Arc<dyn SessionStore + Send + Sync>;

/// The keychain service in use: `piekstra.athena`, or the test override.
pub fn service() -> String {
    std::env::var(KEYCHAIN_SERVICE_ENV)
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| KEYCHAIN_SERVICE.to_string())
}

/// The raw keychain store, for `auth logout`'s v0.2.x items.
pub fn credential_store() -> CredentialStore {
    CredentialStore::new(service())
}

/// The OS keychain, service `piekstra.athena`.
pub fn keychain() -> Store {
    Arc::new(Keychain(credential_store()))
}

/// `pk_med_smart`'s keychain store, with a read that fails for any reason
/// but a refused or missing credential tagged `CredentialUnreadable`, the
/// code `auth status` has reported since v0.1.0.
struct Keychain(CredentialStore);

impl SessionStore for Keychain {
    fn load(&self, account: &str) -> Result<Option<SmartSession>, CliError> {
        self.0.load(account).map_err(|e| {
            if e.is_auth() {
                e
            } else {
                e.because(Reason::CredentialUnreadable)
            }
        })
    }
    fn save(&self, session: &SmartSession) -> Result<(), CliError> {
        self.0.save(session)
    }
    fn delete(&self, account: &str) -> Result<bool, CliError> {
        SessionStore::delete(&self.0, account)
    }
}

/// The stored session at `account`, or exit 3 naming the sign-in to redo.
pub fn load(store: &dyn SessionStore, entry: &SessionEntry) -> Result<SmartSession, CliError> {
    store.load(&entry.key())?.ok_or_else(|| {
        CliError::Auth(format!(
            "the keychain holds no sign-in for {} at {}",
            entry.patient, entry.org
        ))
        .because(Reason::NoCredential)
        .with_remedy(sign_in_again(&entry.org))
    })
}

/// The remedy of a refused or missing sign-in.
pub fn sign_in_again(org: &str) -> String {
    format!("sign in again with `athena auth login --org {org}`")
}

/// When the refresh token lapses, by athenahealth's documented 90 days from
/// the last grant (`tokens.obtained_at`).
pub fn refresh_expires_at(session: &SmartSession) -> Option<u64> {
    session
        .tokens
        .refresh_token
        .as_ref()
        .map(|_| session.tokens.obtained_at + REFRESH_LIFETIME_SECS)
}

/// Whether a read can still succeed without a new sign-in: not refused, and
/// an access token in date or a refresh token that is.
pub fn usable(session: &SmartSession, now: u64) -> bool {
    session.refused_at.is_none()
        && (!session.tokens.is_expired(now, DEFAULT_SKEW_SECS)
            || refresh_expires_at(session).is_some_and(|at| at > now))
}

/// When a new sign-in will be needed (Unix seconds): when athenahealth
/// refused the last grant, else the refresh token's 90 days, else the access
/// token's hour.
pub fn signin_expires_at(session: &SmartSession) -> u64 {
    session.refused_at.unwrap_or_else(|| {
        refresh_expires_at(session)
            .or(session.tokens.expires_at)
            .unwrap_or(session.tokens.obtained_at)
    })
}

/// The revocation endpoint discovered at sign-in, if athenahealth named one.
pub fn revocation_endpoint(session: &SmartSession) -> Option<&str> {
    session
        .extra
        .get(REVOCATION_ENDPOINT)
        .and_then(Value::as_str)
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
    /// The keychain account of this sign-in.
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

/// A synthetic session, for tests in this crate.
#[cfg(test)]
pub(crate) fn test_session(
    org: &str,
    patient: &str,
    revocation: Option<&str>,
    now: u64,
) -> SmartSession {
    let mut extra = serde_json::Map::new();
    if let Some(endpoint) = revocation {
        extra.insert(REVOCATION_ENDPOINT.into(), endpoint.into());
    }
    serde_json::from_value(serde_json::json!({
        "format": 1,
        "organization": org,
        "patient": patient,
        "fhir_base": "http://127.0.0.1:9/fhir/r4",
        "token_endpoint": "http://127.0.0.1:9/oauth2/v1/token",
        "client_id": "client",
        "scope": "openid",
        "tokens": {
            "access_token": "access-1",
            "token_type": "Bearer",
            "refresh_token": null,
            "expires_at": now + 3600,
            "scope": "openid",
            "obtained_at": now,
        },
        "extra": extra,
    }))
    .expect("a synthetic session")
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
    fn usability_follows_the_refresh_token_and_a_refusal() {
        let now = 1_000_000;
        let mut s = test_session("clinic", "a-1.E-1", None, now);
        s.tokens.expires_at = Some(now - 1);
        assert!(!usable(&s, now));
        assert_eq!(signin_expires_at(&s), now - 1);
        s.tokens.refresh_token = Some("r".into());
        assert!(usable(&s, now));
        assert!(!usable(&s, now + REFRESH_LIFETIME_SECS + 1));
        assert_eq!(signin_expires_at(&s), now + REFRESH_LIFETIME_SECS);
        s.refused_at = Some(now + 5);
        assert!(!usable(&s, now));
        assert_eq!(signin_expires_at(&s), now + 5);
    }

    #[test]
    fn the_account_is_pk_med_smarts() {
        let s = test_session("clinic", "a-1.E-1", None, 0);
        assert_eq!(s.account(), "smart/clinic/a-1.E-1");
        assert_eq!(entry("clinic", "a-1.E-1", None).key(), s.account());
        let store = pk_med_smart::MemoryStore::default();
        store.save(&s).unwrap();
        assert!(store.load("smart/clinic/a-1.E-1").unwrap().is_some());
        assert!(store.delete("smart/clinic/a-1.E-1").unwrap());
    }

    #[test]
    fn the_revocation_endpoint_rides_in_extra() {
        let s = test_session(
            "clinic",
            "a-1.E-1",
            Some("https://example.invalid/revoke"),
            0,
        );
        assert_eq!(
            revocation_endpoint(&s),
            Some("https://example.invalid/revoke")
        );
        let text = serde_json::to_string(&s).unwrap();
        let back: SmartSession = serde_json::from_str(&text).unwrap();
        assert_eq!(
            revocation_endpoint(&back),
            Some("https://example.invalid/revoke")
        );
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
