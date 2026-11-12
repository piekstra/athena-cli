//! The FHIR read client: medical-common's `pk_med_fhir::FhirClient` with
//! athenahealth's retry guidance, a bearer kept fresh by
//! `pk_med_smart::Renewer`, and the circuit breaker a pull counts.

use std::cell::Cell;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use pk_cli_auth::oauth::{ClientAuth, OAuthClient};
use pk_cli_auth::refresh_lock::RefreshLock;
use pk_cli_auth::token::DEFAULT_SKEW_SECS;
use pk_cli_core::{block_on, CliError, Reason};
use pk_cli_http::BlockingTransport;
use pk_cli_secrets::Secret;
use pk_med_fhir::outcome::TRY_AGAIN;
use pk_med_fhir::{
    FhirClient, RawResource, RetryPolicy, SearchEnd, SearchPage, SearchResult, UNREACHABLE,
};
use pk_med_smart::{Renewer, SmartSession};

use crate::session::{self, Store};
use crate::smart::Athenahealth;
use crate::{BIN, VERSION};

/// Searches stop after this many pages; the stream records a `page_cap` skip.
pub const PAGE_CAP: u32 = 500;

/// Requests in a row that may fail, each after its retries, before a pull
/// stops: athenahealth asks clients to break the circuit rather than keep
/// calling a server that is down.
pub const BREAKER: u32 = 3;

/// athenahealth's [Timeouts, Retries, and Backoff] guidance (`docs/api.md`):
/// four requests in all, 1 s, 2 s and 4 s apart, each wait lengthened by up
/// to a quarter; a 502, 503 or 504 asked again, and a 429 only when it says
/// when (`Retry-After`) within 30 s, since one that does not may be a daily
/// limit.
pub fn retry_policy() -> RetryPolicy {
    RetryPolicy::default()
        .attempts(4)
        .delay(Duration::from_secs(1))
        .max_wait(Duration::from_secs(30))
        .server_errors(&[502, 503, 504])
        .retry_after_required(true)
        .jitter(0.25)
}

fn now() -> u64 {
    crate::unix_now().max(0) as u64
}

/// The remedy of a refused or missing sign-in names this practice profile.
pub fn remedied(org: &str, error: CliError) -> CliError {
    match error.reason() {
        Some(Reason::CredentialRefused | Reason::NoCredential) => {
            error.with_remedy(session::sign_in_again(org))
        }
        _ => error,
    }
}

/// A sign-in in use: its session renewed when its token has lapsed or was
/// refused, and renewed again when athenahealth refuses its token mid-run.
/// It owns what renewal needs, so the FHIR client can call it from its
/// `bearer_with` source.
#[derive(Clone)]
pub struct Live {
    account: String,
    store: Store,
    lock: RefreshLock,
    oauth: OAuthClient<BlockingTransport>,
    /// The client the tokens were issued to, which renews them.
    client_id: String,
    current: Arc<Mutex<SmartSession>>,
}

impl Live {
    /// The session as read from `store`, renewed first when it is due. The
    /// renewal reads the store again under the refresh lock, so a token
    /// another process renewed meanwhile is used rather than spent again.
    pub fn start(
        store: Store,
        lock: RefreshLock,
        transport: BlockingTransport,
        session: SmartSession,
    ) -> Result<Live, CliError> {
        let live = Live {
            account: session.account(),
            client_id: session.client_id.clone(),
            oauth: OAuthClient::new(transport, BIN, VERSION),
            store,
            lock,
            current: Arc::new(Mutex::new(session)),
        };
        live.bearer(None)?;
        Ok(live)
    }

    /// The session as it stands, renewals included.
    pub fn session(&self) -> SmartSession {
        self.current().clone()
    }

    /// The lock is held only to read or replace the session whole, so a
    /// panic elsewhere leaves nothing half-written: a poisoned lock is
    /// taken as it stands.
    fn current(&self) -> MutexGuard<'_, SmartSession> {
        self.current.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The bearer for the next request: the current token, renewed first
    /// when it has lapsed or was refused before, or after athenahealth
    /// refused `refused`, a renewed one.
    pub fn bearer(&self, refused: Option<&Secret>) -> Result<Secret, CliError> {
        let at = now();
        let current = self.session();
        let presented = match refused {
            Some(refused) => refused.expose().to_string(),
            None if current.refused_at.is_some()
                || current.tokens.is_expired(at, DEFAULT_SKEW_SECS) =>
            {
                current.tokens.access_token.clone()
            }
            None => return Ok(current.bearer()),
        };
        let client = ClientAuth::public(self.client_id.clone());
        let renewer = Renewer::new(
            &*self.store,
            &self.lock,
            &self.oauth,
            &client,
            &Athenahealth,
        );
        match renewer.after_refusal(&self.account, &presented, at) {
            Ok(renewed) => {
                let bearer = renewed.bearer();
                *self.current() = renewed;
                Ok(bearer)
            }
            Err(e) => {
                // The renewer stamped the stored session the same way, so the
                // index the caller writes follows the keychain.
                if e.reason() == Some(Reason::CredentialRefused) {
                    self.current().refused_at = Some(at);
                }
                Err(remedied(&current.organization, e))
            }
        }
    }
}

/// A signed-in patient's reads against one FHIR server.
pub struct Client {
    fhir: FhirClient<BlockingTransport>,
    live: Live,
    org: String,
    patient: String,
    /// Requests in a row that ended, after their retries, in a 429, a 5xx,
    /// an edge's block or a connection that failed. A `Cell`, so a page of
    /// a search can fetch its `Binary` documents while the search goes on.
    failures: Cell<u32>,
}

impl Client {
    /// A client over the live session, which must name its patient (every
    /// athenahealth sign-in does, and `auth login` refuses one that does not).
    pub fn new(transport: BlockingTransport, live: Live) -> Result<Client, CliError> {
        let session = live.session();
        let Some(patient) = session.patient.clone() else {
            return Err(CliError::Auth(
                "the stored sign-in names no patient, so there is nothing to read".into(),
            )
            .because(Reason::NoCredential)
            .with_remedy(session::sign_in_again(&session.organization)));
        };
        let source = live.clone();
        let fhir = FhirClient::new(transport, &session.fhir_base, BIN, VERSION)?
            .bearer_with(move |refused| source.bearer(refused))
            .retry(retry_policy())
            .page_cap(PAGE_CAP);
        Ok(Client {
            fhir,
            live,
            org: session.organization,
            patient,
            failures: Cell::new(0),
        })
    }

    /// Told of each wait before a retry, with one line for a person.
    pub fn on_retry(mut self, report: impl Fn(&str) + Send + Sync + 'static) -> Self {
        self.fhir = self.fhir.on_retry(report);
        self
    }

    /// Replace the sleep between retries, for tests.
    pub fn sleeper(mut self, sleep: fn(Duration)) -> Self {
        self.fhir = self.fhir.sleeper(sleep);
        self
    }

    pub fn base(&self) -> &str {
        self.fhir.base()
    }

    /// The practice profile this sign-in belongs to.
    pub fn org(&self) -> &str {
        &self.org
    }

    pub fn patient(&self) -> &str {
        &self.patient
    }

    /// The session as it stands after this client's renewals, for the index.
    pub fn session(&self) -> SmartSession {
        self.live.session()
    }

    /// `GET <base>/<type>/<id>`.
    pub fn read(&self, resource_type: &str, id: &str) -> Result<RawResource, CliError> {
        let result = block_on(self.fhir.read(resource_type, id));
        self.settle(result)
    }

    /// A `Binary` by its reference (`Binary/<id>`, or an absolute URL on the
    /// FHIR server's origin), as FHIR JSON.
    pub fn binary(&self, reference: &str) -> Result<RawResource, CliError> {
        let result = block_on(self.fhir.binary(reference));
        self.settle(result)
    }

    /// Search `resource_type` with `params`, following `link[next]` on the
    /// server's origin up to [`PAGE_CAP`] pages.
    pub fn search(
        &self,
        resource_type: &str,
        params: &[(&str, String)],
    ) -> Result<SearchResult, CliError> {
        let result = block_on(self.fhir.search(resource_type, params));
        self.settle(result)
    }

    /// [`Self::search`], handing each page to `on_page` as it is read. A
    /// page that fails ends the search with its error, after the pages
    /// before it were handed over; an error from `on_page` ends it too.
    pub fn search_pages(
        &self,
        resource_type: &str,
        params: &[(&str, String)],
        on_page: impl FnMut(SearchPage) -> Result<(), CliError>,
    ) -> Result<SearchEnd, CliError> {
        let result = block_on(self.fhir.search_pages(resource_type, params, on_page));
        self.settle(result)
    }

    /// The body of a `GET` of a path under the base, or an absolute URL on
    /// its origin.
    pub fn get_raw(&self, path: &str) -> Result<String, CliError> {
        let result = block_on(self.fhir.get_raw(path));
        self.settle(result)
    }

    /// Whether the last [`BREAKER`] requests all failed, so a pull should
    /// stop rather than call a server that is down.
    pub fn tripped(&self) -> bool {
        self.failures.get() >= BREAKER
    }

    /// Count the answer toward the breaker, and name the practice profile in
    /// a sign-in's remedy.
    fn settle<T>(&self, result: Result<T, CliError>) -> Result<T, CliError> {
        match &result {
            Err(e) if server_trouble(e) => self.failures.set(self.failures.get() + 1),
            _ => self.failures.set(0),
        }
        result.map_err(|e| remedied(&self.org, e))
    }
}

/// Whether an error says the server is in trouble rather than answering: a
/// connection that failed, or an answer that says nothing (a 429, a 5xx, an
/// edge's HTML page), which `pk_med_fhir` gives the `try again later`
/// remedy.
fn server_trouble(error: &CliError) -> bool {
    error.reason() == Some(UNREACHABLE) || error.remedy() == Some(TRY_AGAIN)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pk_cli_core::transport::HttpResponse;
    use pk_med_fhir::outcome::status_error;

    const ORIGIN: &str = "https://api.preview.platform.athenahealth.com";

    #[test]
    fn the_retry_policy_is_athenahealths() {
        let policy = retry_policy();
        assert_eq!(policy.attempts, 4);
        assert_eq!(policy.delay, Duration::from_secs(1));
        assert_eq!(policy.max_wait, Duration::from_secs(30));
    }

    #[test]
    fn only_a_server_in_trouble_counts_toward_the_breaker() {
        let answer =
            |status, body: &str| status_error("x", ORIGIN, &HttpResponse::new(status, body), 0);
        assert!(server_trouble(&answer(503, "")));
        assert!(server_trouble(&answer(429, "")));
        let edge = HttpResponse::new(403, "<html>blocked</html>")
            .header("content-type", "text/html; charset=utf-8");
        assert!(server_trouble(&status_error("x", ORIGIN, &edge, 0)));
        assert!(server_trouble(
            &CliError::Upstream("connection refused".into()).because(UNREACHABLE)
        ));
        let forbidden = r#"{"resourceType":"OperationOutcome","issue":[{"code":"forbidden"}]}"#;
        assert!(!server_trouble(&answer(403, forbidden)));
        assert!(!server_trouble(&answer(400, "")));
        assert!(!server_trouble(&answer(404, "")));
        assert!(!server_trouble(&CliError::Upstream(
            "expected a FHIR Bundle, found Patient".into()
        )));
    }

    #[test]
    fn a_refused_sign_in_names_the_profile_to_sign_in_again() {
        let refused = remedied("clinic", answer_401());
        assert_eq!(refused.exit_code(), 3);
        assert!(refused
            .to_string()
            .contains("athena auth login --org clinic"));
        let other = remedied("clinic", CliError::NotFound("x".into()));
        assert!(!other.to_string().contains("auth login"));
    }

    fn answer_401() -> CliError {
        status_error("Patient", ORIGIN, &HttpResponse::new(401, ""), 0)
    }
}
