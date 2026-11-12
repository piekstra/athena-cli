//! `auth logout` for one signed-in patient: revoke its tokens and delete its
//! sign-in, and do the same for a v0.2.x item at `<org>/<patient>`. Since
//! v0.3.0 nothing else reaches that item.

use std::fmt;

use pk_cli_auth::refresh_lock::RefreshLock;
use pk_cli_core::CliError;
use pk_cli_secrets::{CredentialStore, Secret};
use pk_med_smart::{SessionStore, SmartSession};
use serde::Deserialize;

use crate::http::Http;
use crate::oauth;
use crate::session;

/// The two keychain operations a v0.2.x item needs, as a seam for tests.
pub trait LegacyItems {
    fn get(&self, account: &str) -> Result<Option<Secret>, CliError>;
    fn delete(&self, account: &str) -> Result<bool, CliError>;
}

impl LegacyItems for CredentialStore {
    fn get(&self, account: &str) -> Result<Option<Secret>, CliError> {
        CredentialStore::get(self, account)
    }
    fn delete(&self, account: &str) -> Result<bool, CliError> {
        CredentialStore::delete(self, account)
    }
}

/// The keychain account v0.2.x used.
pub fn legacy_account(org: &str, patient: &str) -> String {
    format!("{org}/{patient}")
}

/// What a v0.2.x item (its own token JSON) holds for a revocation. `Debug`
/// shows no token.
#[derive(Deserialize)]
pub struct LegacySignIn {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    pub client_id: String,
    #[serde(default)]
    pub revocation_endpoint: Option<String>,
}

impl fmt::Debug for LegacySignIn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LegacySignIn")
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}

/// How one patient's sign-out went.
#[derive(Debug)]
pub struct SignedOut {
    /// A stored item was deleted, and no v0.2.x item was left behind.
    pub credential_removed: bool,
    /// Every revocation tried for the patient's items succeeded, and at
    /// least one was tried.
    pub revoked: bool,
    /// The v0.2.x item could not be read or deleted (a denied Keychain
    /// prompt): the patient stays in the index so `auth logout` can retry.
    pub left_behind: Option<CliError>,
}

/// Revoke and delete the sign-in at `smart/<org>/<patient>` in `store`, under
/// `lock` so a renewal in another process cannot store it again, then the
/// v0.2.x item in `legacy`. An item that does not read as a v0.2.x sign-in is
/// deleted without a revocation. The error names neither an account nor a
/// value.
pub fn sign_out(
    http: &dyn Http,
    lock: &RefreshLock,
    store: &dyn SessionStore,
    legacy: &dyn LegacyItems,
    org: &str,
    patient: &str,
) -> Result<SignedOut, CliError> {
    let key = session::key(org, patient);
    let mut revocations = Vec::new();
    if let Ok(Some(stored)) = store.load(&key) {
        revocations.push(revoke_all(http, &stored));
    }
    let mut found = lock.forget(|| store.delete(&key))?;
    let account = legacy_account(org, patient);
    let left_behind = (|| {
        let Some(item) = legacy.get(&account)? else {
            return Ok(());
        };
        if let Ok(old) = serde_json::from_str::<LegacySignIn>(item.expose()) {
            revocations.push(revoke_legacy(http, &old));
        }
        found |= legacy.delete(&account)?;
        Ok(())
    })()
    .err()
    .map(|e: CliError| {
        CliError::Keychain(format!(
            "the v0.2.x sign-in at {org} could not be removed ({})",
            e.code()
        ))
    });
    Ok(SignedOut {
        credential_removed: found && left_behind.is_none(),
        revoked: !revocations.is_empty() && revocations.iter().all(|ok| *ok),
        left_behind,
    })
}

/// Revoke the refresh and access tokens, best effort.
fn revoke_all(http: &dyn Http, stored: &SmartSession) -> bool {
    let Some(endpoint) = session::revocation_endpoint(stored) else {
        return false;
    };
    let tokens = &stored.tokens;
    revoke_each(
        http,
        endpoint,
        &stored.client_id,
        tokens.refresh_token.as_deref(),
        &tokens.access_token,
        "",
    )
}

/// [`revoke_all`] for a v0.2.x sign-in.
fn revoke_legacy(http: &dyn Http, old: &LegacySignIn) -> bool {
    let Some(endpoint) = &old.revocation_endpoint else {
        return false;
    };
    revoke_each(
        http,
        endpoint,
        &old.client_id,
        old.refresh_token.as_deref(),
        &old.access_token,
        "v0.2.x ",
    )
}

fn revoke_each(
    http: &dyn Http,
    endpoint: &str,
    client_id: &str,
    refresh: Option<&str>,
    access: &str,
    which: &str,
) -> bool {
    let mut ok = true;
    let tokens = refresh
        .map(|t| (t, "refresh_token"))
        .into_iter()
        .chain([(access, "access_token")]);
    for (token, hint) in tokens {
        if let Err(e) = oauth::revoke(http, endpoint, client_id, token, hint) {
            let name = hint.replace('_', " ");
            eprintln!(
                "warning: revoking the {which}{name} failed: {}",
                e.message()
            );
            ok = false;
        }
    }
    ok
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_legacy_sign_in_reads_for_its_revocation_and_hides_its_tokens() {
        let item: LegacySignIn = serde_json::from_value(serde_json::json!({
            "access_token": "access-secret",
            "refresh_token": "refresh-secret",
            "expires_at": 1,
            "scope": "openid",
            "patient": "a-1.E-1",
            "client_id": "client",
            "fhir_base": "https://example.invalid/fhir/r4",
            "token_endpoint": "https://example.invalid/token",
            "revocation_endpoint": "https://example.invalid/revoke",
            "refreshed_at": 1
        }))
        .unwrap();
        assert_eq!(
            item.revocation_endpoint.as_deref(),
            Some("https://example.invalid/revoke")
        );
        let shown = format!("{item:?}");
        assert!(!shown.contains("secret"), "{shown}");
        assert_eq!(legacy_account("clinic", "a-1.E-1"), "clinic/a-1.E-1");
    }
}
