//! OAuth 2.0 authorization code with PKCE for a public native client, and
//! the loopback listener that receives the code.
//!
//! athenahealth's authorization server is Okta behind
//! `api.platform.athenahealth.com/oauth2/v1/*`. Its rules, from its own
//! documentation (`docs/api.md`): PKCE S256 for a client without a secret;
//! a redirect URI that exactly matches a registered one (so the listener
//! binds fixed, registered ports rather than an ephemeral one); `offline_access`
//! for a refresh token; and a refresh grant that must carry `scope`.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use pk_cli_core::transport::HttpResponse;
use pk_cli_core::{CliError, Reason};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::http::{form, request, Http};

/// `n` random bytes from the OS, base64url without padding.
pub fn random_urlsafe(n: usize) -> Result<String, CliError> {
    let mut buf = vec![0u8; n];
    getrandom::fill(&mut buf)
        .map_err(|e| CliError::Other(format!("the system random source failed: {e}")))?;
    Ok(URL_SAFE_NO_PAD.encode(buf))
}

/// A PKCE verifier and its S256 challenge.
pub struct Pkce {
    pub verifier: String,
    pub challenge: String,
}

impl Pkce {
    /// 48 random bytes: a 64-character verifier, inside RFC 7636's 43 to 128.
    pub fn generate() -> Result<Pkce, CliError> {
        let verifier = random_urlsafe(48)?;
        let challenge = s256_challenge(&verifier);
        Ok(Pkce {
            verifier,
            challenge,
        })
    }
}

pub fn s256_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// What goes on the authorize request.
pub struct AuthorizeRequest<'a> {
    pub endpoint: &'a str,
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub scope: &'a str,
    pub state: &'a str,
    pub nonce: &'a str,
    /// The FHIR base URL: athenahealth reads it to choose which practice (or
    /// none, for an athenahealth-wide sign-in) the patient picker covers.
    pub aud: &'a str,
    pub code_challenge: &'a str,
}

impl AuthorizeRequest<'_> {
    pub fn url(&self) -> String {
        let query = form(&[
            ("response_type", "code"),
            ("client_id", self.client_id),
            ("redirect_uri", self.redirect_uri),
            ("scope", self.scope),
            ("state", self.state),
            ("nonce", self.nonce),
            ("aud", self.aud),
            ("code_challenge", self.code_challenge),
            ("code_challenge_method", "S256"),
        ]);
        let sep = if self.endpoint.contains('?') {
            '&'
        } else {
            '?'
        };
        format!("{}{sep}{query}", self.endpoint)
    }
}

/// The authorization code from a callback request target
/// (`/callback?code=...&state=...`), after checking `state` and, when the
/// server sends one (RFC 9207), `iss`.
pub fn code_from_callback(
    target: &str,
    expected_state: &str,
    expected_issuer: Option<&str>,
) -> Result<String, CliError> {
    let query = target.split_once('?').map_or("", |(_, q)| q);
    if let Some(error) = query_param(query, "error") {
        let detail = query_param(query, "error_description")
            .map(|d| format!(": {}", clip(&d, 200)))
            .unwrap_or_default();
        let what = if error == "access_denied" {
            "the sign-in was cancelled or access was not granted".to_string()
        } else {
            format!(
                "athenahealth refused the sign-in ({}{detail})",
                clip(&error, 60)
            )
        };
        return Err(CliError::Auth(what).because(Reason::CredentialRefused));
    }
    match query_param(query, "state") {
        Some(state) if state == expected_state => {}
        _ => {
            return Err(CliError::Auth(
                "the sign-in answer did not belong to this login (state mismatch); start again"
                    .into(),
            ))
        }
    }
    if let (Some(iss), Some(expected)) = (query_param(query, "iss"), expected_issuer) {
        if iss != expected {
            return Err(CliError::Auth(
                "the sign-in answer came from an unexpected issuer; start again".into(),
            ));
        }
    }
    query_param(query, "code")
        .filter(|c| !c.is_empty())
        .ok_or_else(|| CliError::Auth("the sign-in answer carried no authorization code".into()))
}

/// The first value of `key` in a query string, percent-decoded.
pub fn query_param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        (percent_decode(k) == key).then(|| percent_decode(v))
    })
}

/// `%XX` and `+` decoded; an invalid escape is kept as written.
pub fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => match (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                (Some(hi), Some(lo)) => {
                    out.push(hi << 4 | lo);
                    i += 2;
                }
                _ => out.push(b'%'),
            },
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn clip(s: &str, max: usize) -> String {
    let clean: String = s.chars().filter(|c| !c.is_control()).collect();
    if clean.chars().count() <= max {
        clean
    } else {
        clean.chars().take(max).collect::<String>() + "…"
    }
}

/// What a token endpoint answers with. `Debug` names fields, never values.
#[derive(Clone, PartialEq)]
pub struct TokenResponse {
    pub access_token: String,
    pub expires_in: Option<i64>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    pub id_token: Option<String>,
    /// The SMART launch context: the patient the sign-in chose.
    pub patient: Option<String>,
}

impl std::fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenResponse")
            .field("expires_in", &self.expires_in)
            .field("refresh_token", &self.refresh_token.is_some())
            .field("scope", &self.scope)
            .field("patient", &self.patient.is_some())
            .finish_non_exhaustive()
    }
}

/// Read a token endpoint's answer, mapping OAuth errors onto exit codes:
/// a refused grant or client is 3 (sign in again), a busy or failing server 5.
pub fn parse_token_response(response: &HttpResponse) -> Result<TokenResponse, CliError> {
    let body: Option<Map<String, Value>> = serde_json::from_str(&response.body).ok();
    if !response.is_success() {
        let error = body
            .as_ref()
            .and_then(|b| b.get("error"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let status = response.status;
        return Err(match (status, error) {
            (429, _) | (500..=599, _) => CliError::Upstream(format!(
                "athenahealth's token endpoint answered HTTP {status}; try again later"
            )),
            (_, "invalid_grant") => {
                CliError::Auth("athenahealth no longer accepts this sign-in (invalid_grant)".into())
                    .because(Reason::CredentialRefused)
                    .with_remedy("sign in again with `athena auth login --org <ORG>`")
            }
            (_, "invalid_client") | (_, "unauthorized_client") => CliError::Auth(format!(
                "athenahealth does not accept this client id ({error})"
            ))
            .with_remedy(
                "check the client id with `athena config show` against the app in athenahealth's \
                 Developer Portal",
            ),
            (_, e) if !e.is_empty() => CliError::Auth(format!(
                "athenahealth refused the token request ({})",
                clip(e, 60)
            )),
            _ => CliError::Upstream(format!(
                "athenahealth's token endpoint answered HTTP {status}"
            )),
        });
    }
    let body = body.ok_or_else(|| {
        CliError::Upstream(
            "athenahealth's token endpoint answered with something other than JSON".into(),
        )
    })?;
    let text = |name: &str| body.get(name).and_then(Value::as_str).map(str::to_string);
    let access_token = text("access_token")
        .filter(|t| !t.is_empty())
        .ok_or_else(|| CliError::Upstream("the token answer carried no access token".into()))?;
    // athenahealth's own examples send `expires_in` as a number and as a string.
    let expires_in = match body.get("expires_in") {
        Some(Value::Number(n)) => n.as_i64(),
        Some(Value::String(s)) => s.trim().parse().ok(),
        _ => None,
    };
    Ok(TokenResponse {
        access_token,
        expires_in,
        refresh_token: text("refresh_token").filter(|t| !t.is_empty()),
        scope: text("scope"),
        id_token: text("id_token"),
        patient: text("patient").filter(|p| !p.is_empty()),
    })
}

fn post_form(http: &dyn Http, url: &str, body: String) -> Result<HttpResponse, CliError> {
    http.call(
        request("POST", url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Accept", "application/json")
            .body(body),
    )
}

/// Trade an authorization code for tokens (public client: no secret, the
/// PKCE verifier instead).
pub fn exchange_code(
    http: &dyn Http,
    token_endpoint: &str,
    client_id: &str,
    code: &str,
    redirect_uri: &str,
    verifier: &str,
) -> Result<TokenResponse, CliError> {
    let body = form(&[
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", client_id),
        ("code_verifier", verifier),
    ]);
    parse_token_response(&post_form(http, token_endpoint, body)?)
}

/// A refresh grant. athenahealth requires `scope`, a subset of what was
/// granted; the whole granted set is sent.
pub fn refresh_grant(
    http: &dyn Http,
    token_endpoint: &str,
    client_id: &str,
    refresh_token: &str,
    scope: &str,
) -> Result<TokenResponse, CliError> {
    let mut pairs = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", client_id),
    ];
    if !scope.is_empty() {
        pairs.push(("scope", scope));
    }
    parse_token_response(&post_form(http, token_endpoint, form(&pairs))?)
}

/// Revoke a token (RFC 7009). The server answers 200 whether or not it knew it.
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
    let response = post_form(http, endpoint, body)?;
    if response.is_success() {
        Ok(())
    } else {
        Err(CliError::Upstream(format!(
            "athenahealth's revocation endpoint answered HTTP {}",
            response.status
        )))
    }
}

/// The claims of a JWT, read without checking its signature. Used only for
/// tokens received straight from the token endpoint over TLS (OpenID Connect
/// Core §3.1.3.7 allows TLS server validation in place of the signature),
/// and only for `nonce` and `fhirUser`.
pub fn jwt_claims(token: &str) -> Option<Map<String, Value>> {
    let payload = token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// The loopback end of the redirect: a listener on one of the registered
/// ports of 127.0.0.1, serving a start page at `/` and taking the callback at
/// `/callback`.
pub struct Loopback {
    listener: TcpListener,
    port: u16,
}

impl Loopback {
    /// The first of `ports` that is free.
    pub fn bind_first(ports: &[u16]) -> Result<Loopback, CliError> {
        let mut last_error = None;
        for &port in ports {
            match TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port))) {
                Ok(listener) => {
                    let port = listener
                        .local_addr()
                        .map_err(|e| CliError::Other(format!("reading the listener's port: {e}")))?
                        .port();
                    listener
                        .set_nonblocking(true)
                        .map_err(|e| CliError::Other(format!("configuring the listener: {e}")))?;
                    return Ok(Loopback { listener, port });
                }
                Err(e) => last_error = Some(e),
            }
        }
        let list = ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        Err(CliError::Other(format!(
            "no redirect port is free on 127.0.0.1 (tried {list}: {})",
            last_error.map(|e| e.to_string()).unwrap_or_default()
        ))
        .with_remedy(
            "close what holds them, or register another port with athenahealth and add it with \
             `athena config set redirect-ports <PORTS>`",
        ))
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn redirect_uri(&self) -> String {
        format!("http://127.0.0.1:{}/callback", self.port)
    }

    pub fn start_url(&self) -> String {
        format!("http://127.0.0.1:{}/", self.port)
    }

    /// Serve `start_page` at `/` until a callback arrives, then answer it and
    /// return its code. Gives up after `timeout`.
    pub fn wait_for_code(
        &self,
        start_page: &str,
        expected_state: &str,
        expected_issuer: Option<&str>,
        timeout: Duration,
    ) -> Result<String, CliError> {
        let deadline = Instant::now() + timeout;
        loop {
            match self.listener.accept() {
                Ok((stream, _)) => {
                    if let Some(result) =
                        handle(stream, start_page, expected_state, expected_issuer)
                    {
                        return result;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(CliError::Auth(format!(
                            "no sign-in arrived within {} minutes",
                            timeout.as_secs().div_ceil(60)
                        ))
                        .with_remedy("run `athena auth login` again"));
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => return Err(CliError::Other(format!("the sign-in listener failed: {e}"))),
            }
        }
    }
}

/// One request on the listener. `None` keeps waiting (the start page, a
/// favicon); `Some` ends the wait with the callback's outcome.
fn handle(
    mut stream: TcpStream,
    start_page: &str,
    expected_state: &str,
    expected_issuer: Option<&str>,
) -> Option<Result<String, CliError>> {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let target = match read_request_target(&mut stream) {
        Some(t) => t,
        None => {
            respond(&mut stream, 400, "text/plain", "bad request");
            return None;
        }
    };
    let path = target.split('?').next().unwrap_or("");
    match path {
        "/" => {
            respond(&mut stream, 200, "text/html; charset=utf-8", start_page);
            None
        }
        "/callback" => {
            let result = code_from_callback(&target, expected_state, expected_issuer);
            let page = match &result {
                Ok(_) => page(
                    "Signed in",
                    "athena has the sign-in. You can close this tab and return to the terminal.",
                ),
                Err(e) => page(
                    "Sign-in failed",
                    &format!("{} Return to the terminal.", html_escape(e.message())),
                ),
            };
            let status = if result.is_ok() { 200 } else { 400 };
            respond(&mut stream, status, "text/html; charset=utf-8", &page);
            Some(result)
        }
        _ => {
            respond(&mut stream, 404, "text/plain", "not found");
            None
        }
    }
}

/// The request target of a `GET`, or `None` for anything else.
fn read_request_target(stream: &mut TcpStream) -> Option<String> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") && buf.len() < 16 * 1024 {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => return None,
        }
    }
    let head = String::from_utf8_lossy(&buf);
    let line = head.lines().next()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?;
    let target = parts.next()?;
    (method == "GET" && target.starts_with('/')).then(|| target.to_string())
}

fn respond(stream: &mut TcpStream, status: u16, content_type: &str, body: &str) {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        _ => "Not Found",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body.as_bytes());
    let _ = stream.flush();
}

fn page(title: &str, message: &str) -> String {
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>athena: {title}</title>\
         <style>body{{font-family:system-ui,sans-serif;max-width:34rem;margin:4rem auto;\
         padding:0 1rem;line-height:1.5}}</style></head><body><h1>{title}</h1><p>{message}</p>\
         </body></html>"
    )
}

/// Escape text for HTML content and attribute values.
pub fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s256_matches_the_rfc_7636_vector() {
        assert_eq!(
            s256_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn a_verifier_is_long_and_url_safe() {
        let pkce = Pkce::generate().unwrap();
        assert_eq!(pkce.verifier.len(), 64);
        assert!(pkce
            .verifier
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        assert_ne!(pkce.verifier, Pkce::generate().unwrap().verifier);
    }

    #[test]
    fn the_authorize_url_carries_aud_pkce_and_the_scope() {
        let url = AuthorizeRequest {
            endpoint: "https://api.preview.platform.athenahealth.com/oauth2/v1/authorize",
            client_id: "client",
            redirect_uri: "http://127.0.0.1:47816/callback",
            scope: "openid launch/patient",
            state: "s",
            nonce: "n",
            aud: "https://api.preview.platform.athenahealth.com/fhir/r4",
            code_challenge: "c",
        }
        .url();
        assert!(url.starts_with(
            "https://api.preview.platform.athenahealth.com/oauth2/v1/authorize?response_type=code&"
        ));
        assert!(url.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A47816%2Fcallback"));
        assert!(url.contains("aud=https%3A%2F%2Fapi.preview.platform.athenahealth.com%2Ffhir%2Fr4"));
        assert!(url.contains("scope=openid%20launch%2Fpatient"));
        assert!(url.ends_with("code_challenge=c&code_challenge_method=S256"));
    }

    #[test]
    fn the_callback_yields_the_code_only_for_this_login() {
        assert_eq!(
            code_from_callback("/callback?code=abc%2Bd&state=s1", "s1", None).unwrap(),
            "abc+d"
        );
        assert_eq!(
            code_from_callback("/callback?code=abc&state=other", "s1", None)
                .unwrap_err()
                .exit_code(),
            3
        );
        assert!(code_from_callback("/callback?state=s1", "s1", None).is_err());
        assert!(code_from_callback(
            "/callback?code=x&state=s1&iss=https%3A%2F%2Fevil",
            "s1",
            Some("https://good")
        )
        .is_err());
        assert!(code_from_callback(
            "/callback?code=x&state=s1&iss=https%3A%2F%2Fgood",
            "s1",
            Some("https://good")
        )
        .is_ok());
        let denied = code_from_callback(
            "/callback?error=access_denied&error_description=User+said+no&state=s1",
            "s1",
            None,
        )
        .unwrap_err();
        assert!(denied.message().contains("cancelled"));
    }

    #[test]
    fn percent_decoding_tolerates_bad_escapes() {
        assert_eq!(percent_decode("a%20b+c"), "a b c");
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz"), "%zz");
    }

    #[test]
    fn expires_in_may_be_a_string() {
        let response = HttpResponse::new(
            200,
            r#"{"access_token":"a","expires_in":"300","refresh_token":"r","patient":"a-1.E-2"}"#,
        );
        let parsed = parse_token_response(&response).unwrap();
        assert_eq!(parsed.expires_in, Some(300));
        assert_eq!(parsed.patient.as_deref(), Some("a-1.E-2"));
    }

    #[test]
    fn token_errors_map_to_exit_codes() {
        let grant = HttpResponse::new(400, r#"{"error":"invalid_grant"}"#);
        assert_eq!(parse_token_response(&grant).unwrap_err().exit_code(), 3);
        let busy = HttpResponse::new(503, "unavailable");
        assert_eq!(parse_token_response(&busy).unwrap_err().exit_code(), 5);
        let html = HttpResponse::new(200, "<html>");
        assert_eq!(parse_token_response(&html).unwrap_err().exit_code(), 5);
    }

    #[test]
    fn jwt_claims_read_the_payload() {
        let payload = URL_SAFE_NO_PAD.encode(br#"{"nonce":"n1","fhirUser":"Patient/a-1.E-2"}"#);
        let claims = jwt_claims(&format!("e30.{payload}.sig")).unwrap();
        assert_eq!(claims["nonce"], "n1");
        assert!(jwt_claims("not-a-jwt").is_none());
    }

    #[test]
    fn html_is_escaped() {
        assert_eq!(
            html_escape("<a href=\"x\">&'"),
            "&lt;a href=&quot;x&quot;&gt;&amp;&#39;"
        );
    }
}
