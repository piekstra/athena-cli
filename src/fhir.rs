//! The FHIR read client: a bearer token kept fresh, reads, searches that
//! follow `Bundle.link[next]`, and HTTP statuses mapped onto exit codes.

use std::time::Duration;

use pk_cli_auth::refresh_lock::RefreshLock;
use pk_cli_core::transport::HttpResponse;
use pk_cli_core::{CliError, Reason};
use serde::Deserialize;
use serde_json::value::RawValue;
use serde_json::Value;

use crate::http::{request, same_origin, Http};
use crate::oauth;
use crate::session::{TokenSet, TokenStore};

/// Searches stop after this many pages; the stream records a `page_cap` skip.
pub const PAGE_CAP: usize = 500;

/// How often a 429, 502, 503 or 504 is retried before the request is given up.
const RETRIES: u32 = 3;
/// Requests in a row that may fail, each after its retries, before a pull
/// stops: athenahealth asks clients to break the circuit rather than keep
/// calling a server that is down.
pub const BREAKER: u32 = 3;

/// The longest a `Retry-After` is honoured.
const MAX_WAIT: Duration = Duration::from_secs(30);

pub const FHIR_JSON: &str = "application/fhir+json";

/// A signed-in patient's session against one FHIR server.
pub struct Client<'a> {
    http: &'a dyn Http,
    store: &'a dyn TokenStore,
    lock: Option<&'a RefreshLock>,
    key: String,
    tokens: TokenSet,
    now: fn() -> i64,
    sleep: fn(Duration),
    /// Requests in a row that ended in a 429, a 5xx or a network error.
    failures: u32,
}

impl<'a> Client<'a> {
    /// A client over a stored session. `lock` is the cross-process refresh
    /// lock; tests pass `None`.
    pub fn new(
        http: &'a dyn Http,
        store: &'a dyn TokenStore,
        lock: Option<&'a RefreshLock>,
        key: String,
        tokens: TokenSet,
    ) -> Client<'a> {
        Client {
            http,
            store,
            lock,
            key,
            tokens,
            now: crate::unix_now,
            sleep: std::thread::sleep,
            failures: 0,
        }
    }

    /// Replace the clock and the sleep, for tests.
    pub fn with_clock(mut self, now: fn() -> i64, sleep: fn(Duration)) -> Self {
        self.now = now;
        self.sleep = sleep;
        self
    }

    pub fn base(&self) -> &str {
        &self.tokens.fhir_base
    }

    pub fn patient(&self) -> &str {
        &self.tokens.patient
    }

    pub fn tokens(&self) -> &TokenSet {
        &self.tokens
    }

    /// The absolute URL of a path relative to the FHIR base, or an absolute
    /// URL on the base's origin. Anything else gets no token.
    pub fn resolve(&self, path_or_url: &str) -> Result<String, CliError> {
        if path_or_url.starts_with("https://") || path_or_url.starts_with("http://") {
            if same_origin(path_or_url, &self.tokens.fhir_base) {
                return Ok(path_or_url.to_string());
            }
            return Err(CliError::Usage(
                "that URL is not on the signed-in FHIR server; athena sends its token nowhere else"
                    .into(),
            ));
        }
        Ok(format!(
            "{}/{}",
            self.tokens.fhir_base.trim_end_matches('/'),
            path_or_url.trim_start_matches('/')
        ))
    }

    /// GET with the bearer token: renewed first when it has expired, renewed
    /// and retried once on a 401, and retried after a 502 to 504, or a 429
    /// that says when to come back.
    pub fn get(&mut self, url: &str, accept: &str) -> Result<HttpResponse, CliError> {
        if self.tokens.access_expired((self.now)()) {
            let presented = self.tokens.access_token.clone();
            self.renew(&presented)?;
        }
        let mut renewed = false;
        let mut attempt = 0;
        loop {
            let presented = self.tokens.access_token.clone();
            let response = match self.http.call(
                request("GET", url)
                    .header("Accept", accept)
                    .header("Authorization", format!("Bearer {presented}")),
            ) {
                Ok(response) => response,
                Err(e) => {
                    self.failures += 1;
                    return Err(e);
                }
            };
            match response.status {
                401 if !renewed => {
                    renewed = true;
                    self.renew(&presented)?;
                }
                // athenahealth: retry 502, 503 and 504 with exponential
                // backoff and jitter; retry a 429 only when it is about
                // concurrency, not a daily limit. A 429 with a short
                // `Retry-After` is the first; one without is left alone.
                502..=504 if attempt < RETRIES => {
                    attempt += 1;
                    let wait = response
                        .retry_after(crate::unix_now())
                        .unwrap_or_else(|| backoff(attempt))
                        .min(MAX_WAIT);
                    (self.sleep)(wait);
                }
                429 if attempt < RETRIES => match response.retry_after(crate::unix_now()) {
                    Some(wait) if wait <= MAX_WAIT => {
                        attempt += 1;
                        (self.sleep)(wait);
                    }
                    _ => return Ok(self.settled(response)),
                },
                _ => return Ok(self.settled(response)),
            }
        }
    }

    /// Count a final answer toward the circuit breaker: the server is up
    /// when it answers anything but a 429 or a 5xx.
    fn settled(&mut self, response: HttpResponse) -> HttpResponse {
        if response.status == 429 || response.status >= 500 {
            self.failures += 1;
        } else {
            self.failures = 0;
        }
        response
    }

    /// [`check`], with a refused token's remedy naming this sign-in's
    /// practice profile.
    pub fn check(&self, response: &HttpResponse, what: &str) -> Result<(), CliError> {
        check(response, what).map_err(|e| {
            if e.reason() == Some(Reason::CredentialRefused) {
                let org = self.key.split('/').next().unwrap_or_default();
                e.with_remedy(format!(
                    "sign in again with `athena auth login --org {org}`"
                ))
            } else {
                e
            }
        })
    }

    /// Whether the last [`BREAKER`] requests all failed, so a pull should
    /// stop rather than call a server that is down.
    pub fn tripped(&self) -> bool {
        self.failures >= BREAKER
    }

    /// Renew the access token under the refresh lock. `presented` is the
    /// token the server refused or that expired: when the stored one differs,
    /// another process renewed meanwhile and its token is used instead.
    fn renew(&mut self, presented: &str) -> Result<(), CliError> {
        let http = self.http;
        let store = self.store;
        let key = self.key.clone();
        let now = self.now;
        let org = key.split('/').next().unwrap_or_default().to_string();
        let sign_in_again = format!("sign in again with `athena auth login --org {org}`");
        let read = || {
            store.get(&key)?.ok_or_else(|| {
                CliError::Auth("this patient was signed out meanwhile".into())
                    .because(Reason::NoCredential)
                    .with_remedy(sign_in_again.clone())
            })
        };
        let due = |latest: &TokenSet| latest.access_token == presented;
        // The sign-in as marked unusable after a refused refresh, so the
        // caller's index follows the keychain.
        let dead_set = std::cell::RefCell::new(None);
        let grant = |latest: TokenSet| -> Result<TokenSet, CliError> {
            let refresh_token = latest.refresh_token.clone().ok_or_else(|| {
                CliError::Auth("the sign-in has expired and holds no refresh token".into())
                    .because(Reason::CredentialRefused)
                    .with_remedy(sign_in_again.clone())
            })?;
            let response = match oauth::refresh_grant(
                http,
                &latest.token_endpoint,
                &latest.client_id,
                &refresh_token,
                &latest.scope,
            ) {
                Ok(response) => response,
                Err(e) if e.reason() == Some(Reason::CredentialRefused) => {
                    // The refresh token is dead: keep the item, but without
                    // it, so `auth status` reports the sign-in as unusable.
                    let dead = TokenSet {
                        refresh_token: None,
                        expires_at: now(),
                        ..latest
                    };
                    let e = match store.set(&key, &dead) {
                        Ok(()) => e,
                        Err(write) => CliError::Auth(format!(
                            "{}; marking the stored sign-in unusable failed too ({}), so `athena \
                             auth status` may still call it usable",
                            e.message(),
                            write.message()
                        ))
                        .because(Reason::CredentialRefused),
                    };
                    *dead_set.borrow_mut() = Some(dead);
                    return Err(e.with_remedy(sign_in_again.clone()));
                }
                Err(e) => return Err(e),
            };
            let fresh = latest.renewed(response, now());
            store.set(&key, &fresh)?;
            Ok(fresh)
        };
        let renewed = match self.lock {
            Some(lock) => lock.renew(read, due, grant),
            None => read().and_then(|latest| {
                if due(&latest) {
                    grant(latest)
                } else {
                    Ok(latest)
                }
            }),
        };
        if let Some(dead) = dead_set.into_inner() {
            self.tokens = dead;
        }
        self.tokens = renewed?;
        Ok(())
    }

    /// Read one resource (`Patient/a-1.E-2`): its JSON text as served.
    pub fn read(&mut self, reference: &str) -> Result<String, CliError> {
        let url = self.resolve(reference)?;
        let response = self.get(&url, FHIR_JSON)?;
        self.check(&response, reference)?;
        Ok(response.body)
    }

    /// Search `resource_type` with `params`, following `link[next]` up to
    /// [`PAGE_CAP`] pages. `each` gets every matched or included resource's
    /// JSON text. Returns whether the cap cut the search short.
    pub fn search(
        &mut self,
        resource_type: &str,
        params: &[(&str, String)],
        mut each: impl FnMut(&mut Self, &RawValue) -> Result<(), CliError>,
    ) -> Result<SearchEnd, CliError> {
        let mut url = self.resolve(resource_type)?;
        let mut first = true;
        for (name, value) in params {
            url.push(if first { '?' } else { '&' });
            first = false;
            url.push_str(&pk_cli_core::transport::percent_encode(name));
            url.push('=');
            url.push_str(&pk_cli_core::transport::percent_encode(value));
        }
        for _ in 0..PAGE_CAP {
            let response = self.get(&url, FHIR_JSON)?;
            self.check(&response, resource_type)?;
            let page: Page<'_> = serde_json::from_str(&response.body).map_err(|e| {
                CliError::Upstream(format!(
                    "a {resource_type} search answered with something other than a Bundle: {e}"
                ))
            })?;
            if page.resource_type != "Bundle" {
                return Err(CliError::Upstream(format!(
                    "a {resource_type} search answered with a {} instead of a Bundle",
                    page.resource_type
                )));
            }
            for entry in &page.entry {
                let mode = entry
                    .search
                    .as_ref()
                    .and_then(|s| s.mode.as_deref())
                    .unwrap_or("match");
                if mode == "outcome" {
                    continue;
                }
                if let Some(resource) = entry.resource {
                    each(self, resource)?;
                }
            }
            let next = page
                .link
                .iter()
                .find(|l| l.relation == "next")
                .map(|l| l.url.clone());
            match next {
                None => return Ok(SearchEnd::Complete),
                Some(next) if same_origin(&next, &self.tokens.fhir_base) => url = next,
                Some(_) => {
                    return Err(CliError::Upstream(format!(
                        "a {resource_type} search's next page is on another host; athena sends \
                         its token nowhere else"
                    )))
                }
            }
        }
        Ok(SearchEnd::PageCap)
    }
}

/// 1 s, 2 s, 4 s, ... plus up to a quarter of that again, from the clock's
/// sub-second digits (jitter needs no more randomness than that).
fn backoff(attempt: u32) -> Duration {
    let base = Duration::from_secs(1u64 << (attempt - 1).min(5));
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    base + base.mul_f64(f64::from(nanos % 1000) / 4000.0)
}

/// How a search ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchEnd {
    Complete,
    PageCap,
}

#[derive(Deserialize)]
struct Page<'a> {
    #[serde(rename = "resourceType", default)]
    resource_type: String,
    #[serde(default)]
    link: Vec<Link>,
    #[serde(default, borrow)]
    entry: Vec<Entry<'a>>,
}

#[derive(Deserialize)]
struct Link {
    #[serde(default)]
    relation: String,
    #[serde(default)]
    url: String,
}

#[derive(Deserialize)]
struct Entry<'a> {
    #[serde(default, borrow)]
    resource: Option<&'a RawValue>,
    #[serde(default)]
    search: Option<EntrySearch>,
}

#[derive(Deserialize)]
struct EntrySearch {
    #[serde(default)]
    mode: Option<String>,
}

/// Map a FHIR answer onto the exit-code contract. The message names the
/// request and the `OperationOutcome`'s issue code, never its content beyond
/// a short diagnostic.
pub fn check(response: &HttpResponse, what: &str) -> Result<(), CliError> {
    if response.is_success() {
        return Ok(());
    }
    let status = response.status;
    let outcome = outcome_summary(&response.body);
    let detail = if outcome.is_empty() {
        String::new()
    } else {
        format!(": {outcome}")
    };
    Err(match status {
        401 => CliError::Auth(format!(
            "athenahealth refused the token for {what} (HTTP 401){detail}"
        ))
        .because(Reason::CredentialRefused)
        .with_remedy("sign in again with `athena auth login --org <ORG>`"),
        403 => CliError::Auth(format!(
            "{what} is not allowed for this sign-in (HTTP 403){detail}"
        ))
        .because(Reason::Forbidden),
        404 | 410 => CliError::NotFound(format!("{what} was not found (HTTP {status}){detail}")),
        400 | 422 => CliError::Upstream(format!(
            "athenahealth refused the request for {what} (HTTP {status}){detail}"
        ))
        .because(Reason::BadRequest),
        _ => CliError::Upstream(format!(
            "athenahealth answered HTTP {status} for {what}{detail}"
        )),
    })
}

/// `issue[0].code` and up to 160 characters of its diagnostics.
fn outcome_summary(body: &str) -> String {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return String::new();
    };
    if value.get("resourceType").and_then(Value::as_str) != Some("OperationOutcome") {
        return String::new();
    }
    let issue = &value["issue"][0];
    let code = issue["code"].as_str().unwrap_or("");
    let text = issue["diagnostics"]
        .as_str()
        .or_else(|| issue["details"]["text"].as_str())
        .unwrap_or("");
    let text: String = text.chars().filter(|c| !c.is_control()).take(160).collect();
    match (code.is_empty(), text.is_empty()) {
        (true, true) => String::new(),
        (false, true) => code.to_string(),
        (true, false) => text,
        (false, false) => format!("{code}: {text}"),
    }
}

/// `resourceType` and `id` of a resource's JSON text.
pub fn identity(raw: &RawValue) -> Option<(String, String)> {
    #[derive(Deserialize)]
    struct Head {
        #[serde(rename = "resourceType")]
        resource_type: String,
        #[serde(default)]
        id: Option<String>,
    }
    let head: Head = serde_json::from_str(raw.get()).ok()?;
    Some((head.resource_type, head.id.unwrap_or_default()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses_map_to_exit_codes() {
        let outcome = r#"{"resourceType":"OperationOutcome","issue":[{"code":"forbidden","diagnostics":"scope missing"}]}"#;
        let forbidden = check(&HttpResponse::new(403, outcome), "Observation").unwrap_err();
        assert_eq!(forbidden.exit_code(), 3);
        assert_eq!(forbidden.reason(), Some(Reason::Forbidden));
        assert!(forbidden.message().contains("forbidden: scope missing"));
        assert_eq!(
            check(&HttpResponse::new(404, ""), "x")
                .unwrap_err()
                .exit_code(),
            4
        );
        let bad = check(&HttpResponse::new(400, ""), "x").unwrap_err();
        assert_eq!(
            (bad.exit_code(), bad.reason()),
            (5, Some(Reason::BadRequest))
        );
        assert_eq!(
            check(&HttpResponse::new(500, "boom"), "x")
                .unwrap_err()
                .exit_code(),
            5
        );
        assert!(check(&HttpResponse::new(200, "{}"), "x").is_ok());
    }

    #[test]
    fn backoff_doubles_with_a_little_jitter() {
        for (attempt, low) in [(1u32, 1u64), (2, 2), (3, 4)] {
            let wait = backoff(attempt);
            assert!(wait >= Duration::from_secs(low), "{attempt}: {wait:?}");
            assert!(
                wait <= Duration::from_secs(low).mul_f64(1.25),
                "{attempt}: {wait:?}"
            );
        }
    }

    #[test]
    fn identity_reads_type_and_id() {
        let raw: Box<RawValue> =
            serde_json::from_str(r#"{"resourceType":"Observation","id":"o-1","value":1.50}"#)
                .unwrap();
        assert_eq!(identity(&raw), Some(("Observation".into(), "o-1".into())));
    }
}
