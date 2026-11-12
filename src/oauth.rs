//! Token revocation (RFC 7009) for `auth logout`.
//!
//! The sign-in itself, the code exchange and every renewal are
//! medical-common's `pk_med_smart` over cli-common's `pk_cli_auth::oauth`;
//! neither revokes, so athena keeps this one request.

use pk_cli_core::CliError;

use crate::http::{form, request, Http};

/// Revoke `token` (`hint`: `refresh_token` or `access_token`) at athenahealth's
/// revocation endpoint, as the public client `client_id`.
pub fn revoke(
    http: &dyn Http,
    endpoint: &str,
    client_id: &str,
    token: &str,
    hint: &str,
) -> Result<(), CliError> {
    let body = form(&[
        ("token", token),
        ("token_type_hint", hint),
        ("client_id", client_id),
    ]);
    let response = http.call(
        request("POST", endpoint)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Accept", "application/json")
            .body(body),
    )?;
    if response.is_success() {
        Ok(())
    } else {
        Err(CliError::Upstream(format!(
            "athenahealth's revocation endpoint answered HTTP {}",
            response.status
        )))
    }
}
