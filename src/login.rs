//! `auth login`: a SMART standalone patient launch in the system browser.
//!
//! The browser opens athena's own page on the loopback listener, which
//! carries athenahealth's "Log in with athenahealth" button (athenahealth
//! requires it of patient-facing apps). The button goes to athenahealth's
//! authorize endpoint with `aud` set to the practice's FHIR base, PKCE, state
//! and nonce. The person signs in with their athenahealth patient account and
//! picks one patient record: their own, or a child's when they are its
//! caregiver. athenahealth's answer comes back to the listener, and athena
//! trades the code for tokens.

use std::time::Duration;

use pk_cli_core::CliError;

use crate::config::Practice;
use crate::env::Environment;
use crate::http::Http;
use crate::oauth::{self, html_escape, AuthorizeRequest, Loopback, Pkce};
use crate::session::{Grant, TokenSet};
use crate::smart::{self, SmartConfiguration};

/// athenahealth's assets for the button, from its "Log in with athenahealth"
/// guidelines.
const BUTTON_CSS: &str = "https://identity-static-assets.platform.athenahealth.com/login-with-athenahealth/latest/css/ah-login-button.min.css";
const BUTTON_LOGO: &str = "https://identity-static-assets.platform.athenahealth.com/login-with-athenahealth/latest/img/athenahealth_logo_white.svg";

/// What a sign-in needs from the command line and the config.
pub struct Request<'a> {
    pub practice: &'a Practice,
    pub org_name: &'a str,
    pub client_id: &'a str,
    pub ports: &'a [u16],
    pub timeout: Duration,
}

/// A finished sign-in, not yet stored.
pub struct Outcome {
    pub tokens: TokenSet,
    pub relationship: Option<&'static str>,
}

/// The steps before the browser opens: discovery, the listener, the URL.
pub struct Pending {
    smart: SmartConfiguration,
    listener: Loopback,
    pkce: Pkce,
    state: String,
    nonce: String,
    fhir_base: String,
    page: String,
    client_id: String,
    timeout: Duration,
}

/// Discover the server, bind the listener and build the start page.
pub fn prepare(http: &dyn Http, request: &Request<'_>) -> Result<Pending, CliError> {
    let fhir_base = request.practice.fhir_base()?;
    let smart = smart::discover(http, &fhir_base)?;
    let pkce = Pkce::generate()?;
    let state = oauth::random_urlsafe(32)?;
    let nonce = oauth::random_urlsafe(32)?;
    let listener = Loopback::bind_first(request.ports)?;
    let redirect_uri = listener.redirect_uri();
    let scope = smart::scope_string();
    let url = AuthorizeRequest {
        endpoint: &smart.authorization_endpoint,
        client_id: request.client_id,
        redirect_uri: &redirect_uri,
        scope: &scope,
        state: &state,
        nonce: &nonce,
        aud: &fhir_base,
        code_challenge: &pkce.challenge,
    }
    .url();
    let page = start_page(&url, request.org_name, request.practice.environment);
    Ok(Pending {
        smart,
        listener,
        pkce,
        state,
        nonce,
        fhir_base,
        page,
        client_id: request.client_id.to_string(),
        timeout: request.timeout,
    })
}

impl Pending {
    /// The page to open in the browser.
    pub fn start_url(&self) -> String {
        self.listener.start_url()
    }

    /// Wait for the callback, then trade the code for tokens.
    pub fn finish(self, http: &dyn Http, now: i64) -> Result<Outcome, CliError> {
        let code = self.listener.wait_for_code(
            &self.page,
            &self.state,
            self.smart.issuer.as_deref(),
            self.timeout,
        )?;
        let redirect_uri = self.listener.redirect_uri();
        let response = oauth::exchange_code(
            http,
            &self.smart.token_endpoint,
            &self.client_id,
            &code,
            &redirect_uri,
            &self.pkce.verifier,
        )?;
        let patient = response.patient.clone().ok_or_else(|| {
            CliError::Upstream(
                "athenahealth's answer named no patient: the sign-in must pick one patient record"
                    .into(),
            )
        })?;
        validate_patient_id(&patient)?;
        let claims = response.id_token.as_deref().and_then(oauth::jwt_claims);
        if let Some(claims) = &claims {
            if claims.get("nonce").and_then(|n| n.as_str()) != Some(self.nonce.as_str()) {
                return Err(CliError::Auth(
                    "the sign-in's id token did not belong to this login (nonce mismatch); start \
                     again"
                        .into(),
                ));
            }
        }
        let fhir_user = claims
            .as_ref()
            .and_then(|c| c.get("fhirUser"))
            .and_then(|u| u.as_str())
            .map(str::to_string);
        let relationship = smart::relationship(fhir_user.as_deref(), &patient);
        let tokens = TokenSet::from_response(
            response,
            Grant {
                patient,
                client_id: self.client_id.clone(),
                fhir_base: self.fhir_base.clone(),
                token_endpoint: self.smart.token_endpoint.clone(),
                revocation_endpoint: self.smart.revocation_endpoint.clone(),
                issuer: self.smart.issuer.clone(),
                fhir_user,
            },
            now,
        );
        Ok(Outcome {
            tokens,
            relationship,
        })
    }
}

/// A patient id is used in keychain accounts, file names and URLs, so it is
/// held to FHIR's id rule: `[A-Za-z0-9\-\.]{1,64}`.
pub fn validate_patient_id(id: &str) -> Result<(), CliError> {
    let ok = !id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.');
    if ok {
        Ok(())
    } else {
        Err(CliError::Upstream(
            "athenahealth's answer named a patient id that is not a FHIR id".into(),
        ))
    }
}

/// athena's start page: the button for athenahealth's environments, a plain
/// link otherwise.
pub fn start_page(authorize_url: &str, org_name: &str, environment: Environment) -> String {
    let href = html_escape(authorize_url);
    let org = html_escape(org_name);
    let (head, button) = if environment.is_athenahealth() {
        (
            format!("<link rel=\"stylesheet\" href=\"{BUTTON_CSS}\">"),
            format!(
                "<a id=\"signin\" href=\"{href}\" class=\"btn athenahealthsignin logo_white\" \
                 style=\"text-decoration:none\"><div class=\"ah_login_left_div\">Log in with</div>\
                 <div class=\"ah_login_right_div\"><img class=\"logo\" alt=\"athenahealth\" \
                 title=\"athenahealth\" src=\"{BUTTON_LOGO}\"></div></a>"
            ),
        )
    } else {
        (
            String::new(),
            format!("<a id=\"signin\" href=\"{href}\">Sign in</a>"),
        )
    };
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>athena: sign in</title>{head}\
         <meta name=\"referrer\" content=\"no-referrer\"><style>body{{font-family:system-ui,\
         sans-serif;max-width:34rem;margin:4rem auto;padding:0 1rem;line-height:1.5}}</style>\
         </head><body><h1>Sign in to {org}</h1><p>Sign in with the patient portal account. If \
         you are a caregiver, pick the one patient record this sign-in is for; sign in again for \
         each other one.</p><p>{button}</p></body></html>"
    )
}

/// Open `url` in the system browser.
pub fn open_browser(url: &str) -> Result<(), CliError> {
    let program = if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    std::process::Command::new(program)
        .arg(url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|e| CliError::Other(format!("opening the browser with `{program}`: {e}")))
        .and_then(|status| {
            if status.success() {
                Ok(())
            } else {
                Err(CliError::Other(format!(
                    "`{program}` could not open the browser"
                )))
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_start_page_carries_the_button_and_an_escaped_url() {
        let page = start_page(
            "https://api.preview.platform.athenahealth.com/oauth2/v1/authorize?a=1&b=<x>",
            "Clinic <One>",
            Environment::Preview,
        );
        assert!(page.contains("athenahealthsignin"));
        assert!(page.contains("a=1&amp;b=&lt;x&gt;"));
        assert!(page.contains("Clinic &lt;One&gt;"));
        let plain = start_page("http://127.0.0.1:1/authorize", "Mock", Environment::Custom);
        assert!(!plain.contains("identity-static-assets"));
    }

    #[test]
    fn patient_ids_are_fhir_ids() {
        assert!(validate_patient_id("a-195900.E-60178").is_ok());
        assert!(validate_patient_id("../x").is_err());
        assert!(validate_patient_id("").is_err());
    }
}
