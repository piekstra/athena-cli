//! The sign-in, the stream and the documents against the loopback mock,
//! in-process, with tokens in memory: nothing here reads or writes the
//! keychain.

mod support;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use athena::config::Practice;
use athena::documents;
use athena::env::Environment;
use athena::export;
use athena::fhir::{Client, Live};
use athena::login;
use athena::logout::{self, LegacyItems};
use athena::session::{self, key};
use athena::stream;
use pk_cli_auth::refresh_lock::RefreshLock;
use pk_cli_core::{CliError, RangeArgs, Reason};
use pk_cli_http::BlockingTransport;
use pk_cli_secrets::Secret;
use pk_med_smart::{MemoryStore, SessionStore, SmartSession};
use serde_json::Value;
use support::mock::{self, Mock};

fn practice(m: &Mock) -> Practice {
    Practice {
        name: Some("Mock practice".into()),
        environment: Environment::Custom,
        fhir_base: Some(m.fhir_base()),
        ..Practice::default()
    }
}

fn prepare(m: &Mock, http: &BlockingTransport) -> login::Pending {
    login::prepare(
        http,
        &login::Request {
            org: "mock",
            practice: &practice(m),
            org_name: "Mock practice",
            client_id: mock::CLIENT_ID,
            ports: &[0],
            timeout: Duration::from_secs(30),
        },
    )
    .expect("prepare the sign-in")
}

fn now() -> u64 {
    athena::unix_now() as u64
}

fn sign_in(m: &Mock, http: &BlockingTransport) -> SmartSession {
    let pending = prepare(m, http);
    let start = pending.start_url();
    let browser = thread::spawn(move || mock::click_through(&start));
    let outcome = pending.finish(http, now()).expect("finish the sign-in");
    let page = browser.join().unwrap();
    assert_eq!(page.status, 200);
    assert!(page.body.contains("signed in"), "{}", page.body);
    assert_eq!(outcome.relationship, Some("proxy"));
    outcome.session
}

fn no_sleep(_: Duration) {}

/// A refresh lock of this test's own.
fn lock() -> RefreshLock {
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    RefreshLock::at(
        std::env::temp_dir().join(format!("athena-mock-flow-{}-{n}.lock", std::process::id())),
    )
}

/// The session stored in `store`, and a client over it.
fn client(http: &BlockingTransport, store: &Arc<MemoryStore>, signed_in: &SmartSession) -> Client {
    store.save(signed_in).unwrap();
    let live = Live::start(store.clone(), lock(), http.clone(), signed_in.clone())
        .expect("start the session");
    Client::new(http.clone(), live)
        .expect("a client")
        .sleeper(no_sleep)
}

fn stored(store: &MemoryStore) -> SmartSession {
    store
        .load(&key("mock", mock::PATIENT))
        .unwrap()
        .expect("a stored session")
}

fn header(signed_in: &SmartSession) -> stream::Header {
    stream::header(
        stream::Organization {
            id: "mock".into(),
            name: "Mock practice".into(),
            fhir_base: signed_in.fhir_base.clone(),
            vendor: Some(stream::VENDOR.into()),
            location: None,
            aliases: Vec::new(),
        },
        stream::PatientContext {
            id: signed_in.patient.clone().unwrap_or_default(),
            organization: "mock".into(),
            label: Some("kid".into()),
            relationship: Some("proxy".into()),
            kind: Some(stream::kind::PATIENT.into()),
            member_role: None,
            fhir_user: None,
            name: None,
            session: None,
        },
        None,
        "2026-01-01T00:00:00Z".into(),
    )
}

/// One export into memory, as `athena records export --ndjson` writes it:
/// the stream's text, and the error that cut it short (recorded in the
/// trailer as `complete: false`).
fn pull(c: &Client, signed_in: &SmartSession) -> (String, Result<(), CliError>) {
    pull_since(c, signed_in, None)
}

fn pull_since(
    c: &Client,
    signed_in: &SmartSession,
    since: Option<&str>,
) -> (String, Result<(), CliError>) {
    let mut buf = Vec::new();
    let mut header = header(signed_in);
    header.since = since.map(str::to_string);
    let (_, error) = export::write_stream(
        &mut buf,
        &header,
        || "2026-01-01T00:00:01Z".into(),
        |w| export::export(c, w, since),
    )
    .unwrap();
    (String::from_utf8(buf).unwrap(), error.map_or(Ok(()), Err))
}

/// A new, empty directory for one test.
fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("athena-mock-flow-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn lines(text: &str) -> Vec<Value> {
    text.lines()
        .map(|l| serde_json::from_str(l).expect("every line is JSON"))
        .collect()
}

#[test]
fn a_caregiver_sign_in_gets_tokens_for_the_chosen_patient() {
    let m = Mock::start(0);
    let http = BlockingTransport::new().unwrap();
    let tokens = sign_in(&m, &http);
    assert_eq!(tokens.organization, "mock");
    assert_eq!(tokens.patient.as_deref(), Some(mock::PATIENT));
    assert_eq!(tokens.account(), key("mock", mock::PATIENT));
    assert_eq!(tokens.fhir_user.as_deref(), Some(mock::FHIR_USER));
    assert_eq!(tokens.client_id, mock::CLIENT_ID);
    assert!(tokens.tokens.refresh_token.is_some());
    assert!(tokens
        .tokens
        .scope
        .as_deref()
        .unwrap()
        .contains("patient/DocumentReference.read"));
    // expires_in came as the string "3600".
    assert!(tokens.tokens.expires_at.unwrap() > now() + 3000);
    assert_eq!(
        session::revocation_endpoint(&tokens),
        Some(format!("{}/oauth2/v1/revoke", m.origin()).as_str())
    );
    assert!(session::usable(&tokens, now()));
}

#[test]
fn an_id_token_for_another_sign_in_is_refused() {
    let m = Mock::start(0);
    m.set_mode("nonce");
    let http = BlockingTransport::new().unwrap();
    let pending = prepare(&m, &http);
    let start = pending.start_url();
    let browser = thread::spawn(move || mock::click_through(&start));
    let err = pending.finish(&http, now()).err().expect("a refusal");
    browser.join().unwrap();
    assert_eq!(err.exit_code(), 3);
    assert_eq!(err.reason(), Some(Reason::CredentialRefused));
    assert!(err.message().contains("nonce"), "{err}");
}

#[test]
fn the_export_streams_every_resource_with_binaries_after_their_parents() {
    let m = Mock::start(0);
    let http = BlockingTransport::new().unwrap();
    let tokens = sign_in(&m, &http);
    let store = Arc::new(MemoryStore::default());
    let c = client(&http, &store, &tokens);
    let (text, result) = pull(&c, &tokens);
    result.expect("export");
    let out = lines(&text);

    assert_eq!(out[0]["schema"], "records-stream/v1");
    let trailer = out.last().unwrap();
    assert_eq!(trailer["schema"], "records-stream-end/v1");
    assert_eq!(trailer["complete"], true);
    let counts = &trailer["counts"];
    for (t, n) in [
        ("Patient", 1),
        ("Observation", 3),
        ("Encounter", 2),
        ("DocumentReference", 2),
        ("DiagnosticReport", 2),
        ("Immunization", 1),
        ("Binary", 4),
        ("Media", 1),
        ("Practitioner", 1),
        ("Organization", 1),
        ("Location", 1),
    ] {
        assert_eq!(counts[t], n, "{t}");
    }
    let resources = &out[1..out.len() - 1];
    let total: u64 = counts
        .as_object()
        .unwrap()
        .values()
        .map(|v| v.as_u64().unwrap())
        .sum();
    assert_eq!(resources.len() as u64, total, "counts match the lines");
    assert!(resources.iter().all(|r| r["resourceType"].is_string()));

    let at = |t: &str, id: &str| {
        resources
            .iter()
            .position(|r| r["resourceType"] == t && r["id"] == id)
            .unwrap_or_else(|| panic!("{t}/{id} is in the stream"))
    };
    assert_eq!(
        at("Binary", "bin-pdf-1"),
        at("DocumentReference", "doc-1") + 1
    );
    assert_eq!(
        at("Binary", "bin-png-1"),
        at("DiagnosticReport", "dr-1") + 1
    );
    assert_eq!(at("Binary", "bin-png-2"), at("Media", "media-1") + 1);

    let skips: Vec<(String, String)> = trailer["skipped"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            (
                s["resource_type"].as_str().unwrap_or("").into(),
                s["code"].as_str().unwrap().into(),
            )
        })
        .collect();
    assert!(
        skips.contains(&("Goal".into(), "forbidden".into())),
        "{skips:?}"
    );
    assert!(
        skips.contains(&("ServiceRequest".into(), "unsupported".into())),
        "{skips:?}"
    );
    assert!(
        skips.contains(&("Binary".into(), "unsupported".into())),
        "the off-host attachment: {skips:?}"
    );
}

#[test]
fn numbers_reach_the_stream_as_the_server_wrote_them() {
    let m = Mock::start(0);
    let http = BlockingTransport::new().unwrap();
    let tokens = sign_in(&m, &http);
    let store = Arc::new(MemoryStore::default());
    let c = client(&http, &store, &tokens);
    let (text, result) = pull(&c, &tokens);
    result.unwrap();
    let weight = text
        .lines()
        .find(|l| l.contains("\"id\":\"ob-1\""))
        .unwrap();
    assert!(weight.contains("\"value\":3.50"), "{weight}");
    assert!(
        !weight.contains(": "),
        "whitespace between tokens is removed"
    );
}

#[test]
fn an_expired_token_is_renewed_once_with_the_granted_scope() {
    let m = Mock::start(0);
    let http = BlockingTransport::new().unwrap();
    let tokens = sign_in(&m, &http);
    let store = Arc::new(MemoryStore::default());
    let c = client(&http, &store, &tokens);
    m.expire_access_tokens();
    c.read("Patient", mock::PATIENT)
        .expect("read after renewal");
    assert_eq!(m.refresh_grants(), 1);
    let scope = &m.refresh_scopes()[0];
    assert!(scope.contains("launch/patient") && scope.contains("patient/Patient.read"));
    let stored = stored(&store);
    assert_ne!(stored.tokens.access_token, tokens.tokens.access_token);
    assert_eq!(
        stored.tokens.refresh_token, tokens.tokens.refresh_token,
        "the refresh token is kept"
    );
    assert!(stored.tokens.obtained_at >= tokens.tokens.obtained_at);
    assert_eq!(
        c.session().tokens.access_token,
        stored.tokens.access_token,
        "the client holds what the keychain holds"
    );
}

#[test]
fn a_stored_sign_in_without_a_patient_is_refused_before_any_read() {
    let m = Mock::start(0);
    let http = BlockingTransport::new().unwrap();
    let mut tokens = sign_in(&m, &http);
    tokens.patient = None;
    let store = Arc::new(MemoryStore::default());
    store.save(&tokens).unwrap();
    let before = m.requests().len();
    let live = Live::start(store.clone(), lock(), http.clone(), tokens).unwrap();
    let err = Client::new(http.clone(), live).err().expect("refused");
    assert_eq!(err.exit_code(), 3);
    assert!(
        err.to_string().contains("athena auth login --org mock"),
        "{err}"
    );
    assert_eq!(m.requests().len(), before, "nothing was sent");
}

#[test]
fn a_lapsed_token_is_renewed_before_the_first_request() {
    let m = Mock::start(0);
    let http = BlockingTransport::new().unwrap();
    let mut tokens = sign_in(&m, &http);
    tokens.tokens.expires_at = Some(now() - 1);
    let store = Arc::new(MemoryStore::default());
    let before = m.requests().len();
    let c = client(&http, &store, &tokens);
    assert_eq!(m.refresh_grants(), 1, "renewed when the client started");
    c.read("Patient", mock::PATIENT).expect("read");
    let fhir: Vec<_> = m.requests()[before..]
        .iter()
        .filter(|(_, p)| p.starts_with("/fhir/"))
        .cloned()
        .collect();
    assert_eq!(fhir.len(), 1, "no refused request first: {fhir:?}");
    assert!(stored(&store).tokens.expires_at.unwrap() > now());
}

#[test]
fn a_revoked_sign_in_ends_the_stream_incomplete_with_exit_3() {
    let m = Mock::start(0);
    let http = BlockingTransport::new().unwrap();
    let tokens = sign_in(&m, &http);
    let store = Arc::new(MemoryStore::default());
    let c = client(&http, &store, &tokens);
    m.expire_access_tokens();
    m.set_mode("revoked");
    let (text, result) = pull(&c, &tokens);
    let err = result.unwrap_err();
    assert_eq!(err.exit_code(), 3);
    assert!(
        err.to_string().contains("athena auth login --org mock"),
        "{err}"
    );
    let out = lines(&text);
    let trailer = out.last().unwrap();
    assert_eq!(trailer["complete"], false);
    assert_eq!(trailer["error"]["code"], err.code());
    // The refusal is stamped on the stored sign-in, so status reports it
    // unusable; the refresh token is kept, in case the server takes it back.
    let stored = stored(&store);
    assert!(stored.refused_at.is_some());
    assert!(stored.tokens.refresh_token.is_some());
    assert!(!session::usable(&stored, now()));
    // The client holds the same stamp, which is what the caller writes into
    // the session index.
    assert!(c.session().refused_at.is_some());
    assert_eq!(
        session::signin_expires_at(&c.session()),
        c.session().refused_at.unwrap()
    );
}

#[test]
fn a_server_that_is_down_fails_the_export_after_retries() {
    let m = Mock::start(0);
    let http = BlockingTransport::new().unwrap();
    let tokens = sign_in(&m, &http);
    let store = Arc::new(MemoryStore::default());
    let c = client(&http, &store, &tokens);
    m.set_mode("down");
    let before = m.requests().len();
    let (text, result) = pull(&c, &tokens);
    let err = result.expect_err("no patient, no export");
    assert_eq!(err.exit_code(), 5);
    let out = lines(&text);
    assert_eq!(out.len(), 2, "header and trailer only");
    assert_eq!(out[1]["complete"], false);
    assert_eq!(out[1]["error"]["exit_code"], 5);
    // Patient: one request and three retries, and nothing after it.
    let after = &m.requests()[before..];
    assert_eq!(after.len(), 4);
    assert!(after
        .iter()
        .all(|(_, p)| p.ends_with(&format!("Patient/{}", mock::PATIENT))));
}

#[test]
fn a_refused_patient_read_ends_the_export_as_a_sign_in_problem() {
    let m = Mock::start(0);
    let http = BlockingTransport::new().unwrap();
    let tokens = sign_in(&m, &http);
    let store = Arc::new(MemoryStore::default());
    let c = client(&http, &store, &tokens);
    m.set_mode("forbidden");
    let (text, result) = pull(&c, &tokens);
    let err = result.expect_err("refused");
    assert_eq!(err.exit_code(), 3);
    assert!(err.to_string().contains("turned off access"), "{err}");
    assert!(err.to_string().contains("--org mock"), "{err}");
    let out = lines(&text);
    assert_eq!(out.len(), 2);
    assert_eq!(out[1]["complete"], false);
}

#[test]
fn failing_searches_trip_the_breaker() {
    let m = Mock::start(0);
    let http = BlockingTransport::new().unwrap();
    let tokens = sign_in(&m, &http);
    let store = Arc::new(MemoryStore::default());
    let c = client(&http, &store, &tokens);
    m.set_mode("degraded");
    let before = m.requests().len();
    let (text, result) = pull(&c, &tokens);
    let err = result.expect_err("the breaker trips");
    assert_eq!(err.exit_code(), 5);
    assert!(err.to_string().contains("in a row"), "{err}");
    assert!(err.to_string().ends_with("— try again later"), "{err}");
    let out = lines(&text);
    let trailer = out.last().unwrap();
    assert_eq!(trailer["complete"], false);
    assert_eq!(trailer["counts"]["Patient"], 1);
    let upstream = trailer["skipped"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|s| s["code"] == "upstream")
        .count();
    assert_eq!(upstream as u32, athena::fhir::BREAKER - 1);
    // The patient read, then three searches of four attempts each.
    assert_eq!(m.requests().len() - before, 1 + 3 * 4);
}

#[test]
fn a_cancelled_sign_in_is_exit_3() {
    let m = Mock::start(0);
    m.set_mode("deny");
    let http = BlockingTransport::new().unwrap();
    let pending = prepare(&m, &http);
    let start = pending.start_url();
    let browser = thread::spawn(move || mock::click_through(&start));
    let err = pending.finish(&http, now()).err().expect("a refusal");
    assert_eq!(err.exit_code(), 3);
    assert!(err.message().contains("access_denied"), "{err}");
    assert!(
        err.to_string().contains("athena auth login --org mock"),
        "{err}"
    );
    let page = browser.join().unwrap();
    assert!(page.body.contains("did not complete"), "{}", page.body);
}

#[test]
fn documents_are_listed_newest_first_and_checked_on_download() {
    let m = Mock::start(0);
    let http = BlockingTransport::new().unwrap();
    let tokens = sign_in(&m, &http);
    let store = Arc::new(MemoryStore::default());
    let c = client(&http, &store, &tokens);
    let items = documents::list(&c, &RangeArgs::default()).unwrap();
    let ids: Vec<&str> = items.iter().map(|i| i.document.id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "DiagnosticReport/dr-1",
            "DocumentReference/doc-1",
            "DocumentReference/doc-2#1",
            "DocumentReference/doc-2#2"
        ]
    );

    let pdf = documents::fetch(&c, &items[1]).ok().unwrap();
    assert!(pdf.bytes.starts_with(b"%PDF"));
    let png = documents::fetch(&c, &items[0]).ok().unwrap();
    assert!(png.bytes.starts_with(b"\x89PNG"));
    assert_eq!(documents::extension(png.content_type.as_deref()), "png");
    let html = documents::fetch(&c, &items[2]).err().unwrap();
    assert_eq!(html.code, "verify_failed");
    let elsewhere = documents::fetch(&c, &items[3]).err().unwrap();
    assert_eq!(elsewhere.code, "no_file");

    let found = documents::find(&c, "DocumentReference/doc-2#1").unwrap();
    assert_eq!(found.document.id, "DocumentReference/doc-2#1");
    assert_eq!(
        documents::find(&c, "DocumentReference/doc-2#3")
            .unwrap_err()
            .exit_code(),
        4
    );
    assert_eq!(
        documents::find(&c, "DocumentReference/none")
            .unwrap_err()
            .exit_code(),
        4
    );

    let since = RangeArgs {
        since: Some("2026-02-01".into()),
        ..RangeArgs::default()
    };
    assert_eq!(documents::list(&c, &since).unwrap().len(), 2);
}

#[test]
fn a_token_goes_nowhere_but_its_own_server() {
    let m = Mock::start(0);
    let http = BlockingTransport::new().unwrap();
    let tokens = sign_in(&m, &http);
    let store = Arc::new(MemoryStore::default());
    let c = client(&http, &store, &tokens);
    let before = m.requests().len();
    assert!(c
        .get_raw("https://elsewhere.example/fhir/r4/Patient/x")
        .is_err());
    assert!(c
        .binary("https://elsewhere.example/fhir/r4/Binary/x")
        .is_err());
    assert_eq!(m.requests().len(), before, "nothing was sent");
    assert!(c
        .get_raw(&format!("{}/Patient/{}", m.fhir_base(), mock::PATIENT))
        .is_ok());
}

#[test]
fn the_stream_reads_back_with_the_consumers_reader() {
    use pk_med_records::stream::{Item, RecordsReader};
    let m = Mock::start(0);
    let http = BlockingTransport::new().unwrap();
    let tokens = sign_in(&m, &http);
    let store = Arc::new(MemoryStore::default());
    let c = client(&http, &store, &tokens);
    let (text, result) = pull(&c, &tokens);
    result.expect("export");
    let mut reader = RecordsReader::new(std::io::BufReader::new(text.as_bytes()));
    assert_eq!(reader.header().unwrap().source.cli, "athena");
    let mut resources = 0u64;
    let mut trailer = None;
    for item in reader {
        match item.expect("every line reads") {
            Item::Resource(_) => resources += 1,
            Item::Trailer(t) => trailer = Some(t),
        }
    }
    let trailer = trailer.expect("a trailer");
    assert!(trailer.complete);
    assert_eq!(trailer.total(), resources);
    // records-stream/v1: a skipped search names no patient id.
    let searches: Vec<&str> = trailer
        .skipped
        .iter()
        .filter_map(|s| s.search.as_deref())
        .collect();
    assert!(searches.contains(&"ServiceRequest"), "{searches:?}");
    for search in searches {
        assert!(!search.contains(mock::PATIENT), "{search}");
    }
}

#[test]
fn a_since_pull_names_the_bound_in_skipped_searches() {
    let m = Mock::start(0);
    let http = BlockingTransport::new().unwrap();
    let tokens = sign_in(&m, &http);
    let store = Arc::new(MemoryStore::default());
    let c = client(&http, &store, &tokens);
    let (text, result) = pull_since(&c, &tokens, Some("2026-01-01"));
    result.expect("export");
    let out = lines(&text);
    assert_eq!(out[0]["since"], "2026-01-01");
    let searches: Vec<&str> = out.last().unwrap()["skipped"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|s| s["search"].as_str())
        .collect();
    assert!(
        searches.contains(&"ServiceRequest?_lastUpdated=ge2026-01-01"),
        "{searches:?}"
    );
    assert!(searches.iter().all(|s| !s.contains(mock::PATIENT)));
}

#[test]
fn a_search_entry_that_does_not_read_is_a_skip_and_the_rest_is_kept() {
    let m = Mock::start(0);
    let http = BlockingTransport::new().unwrap();
    let tokens = sign_in(&m, &http);
    let store = Arc::new(MemoryStore::default());
    let c = client(&http, &store, &tokens);
    m.set_mode("malformed");
    let (text, result) = pull(&c, &tokens);
    result.expect("export");
    let out = lines(&text);
    let trailer = out.last().unwrap();
    assert_eq!(trailer["complete"], true);
    let bad: Vec<&Value> = trailer["skipped"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|s| s["code"] == "verify_failed")
        .collect();
    assert_eq!(bad.len(), 1, "{trailer}");
    assert!(bad[0]["reason"]
        .as_str()
        .unwrap()
        .contains("no resourceType"));
    assert!(out
        .iter()
        .any(|l| l["resourceType"] == "Condition" && l["id"] == "co-9"));
    assert_eq!(trailer["counts"]["Condition"], 1);
}

#[test]
fn a_search_page_that_fails_keeps_the_pages_before_it() {
    let m = Mock::start(0);
    let http = BlockingTransport::new().unwrap();
    let tokens = sign_in(&m, &http);
    let store = Arc::new(MemoryStore::default());
    let c = client(&http, &store, &tokens);
    m.set_mode("page2-down");
    let (text, result) = pull(&c, &tokens);
    result.expect("a failed search is a skip, not the end");
    let out = lines(&text);
    let trailer = out.last().unwrap();
    assert_eq!(trailer["complete"], true);
    assert_eq!(trailer["counts"]["Observation"], 2, "page 1 is kept");
    let observation: Vec<&Value> = trailer["skipped"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|s| s["resource_type"] == "Observation")
        .collect();
    assert_eq!(observation.len(), 1, "{trailer}");
    assert_eq!(observation[0]["code"], "upstream");
    assert_eq!(observation[0]["search"], "Observation");
}

#[test]
fn an_export_to_a_directory_commits_complete_streams_and_keeps_the_last_one() {
    use pk_med_records::stream::{Item, RecordsReader, StreamError};
    let m = Mock::start(0);
    let http = BlockingTransport::new().unwrap();
    let tokens = sign_in(&m, &http);
    let store = Arc::new(MemoryStore::default());
    let c = client(&http, &store, &tokens);
    let dir = scratch("out");
    let now = || "2026-01-01T00:00:01Z".to_string();

    let mut sizes = Vec::new();
    for _ in 0..2 {
        let (export, error) =
            export::write_dir(&dir, &header(&tokens), now, |w| export::export(&c, w, None))
                .unwrap();
        assert!(error.is_none());
        let v = serde_json::to_value(&export).unwrap();
        assert_eq!(v["schema"], "records-export/v1");
        assert_eq!(v["complete"], true);
        assert!(export.path.ends_with("/records.ndjson"), "{}", export.path);
        let meta = std::fs::metadata(&export.path).unwrap();
        assert_eq!(meta.len(), export.bytes);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        }
        let file = std::fs::File::open(&export.path).unwrap();
        let mut reader = RecordsReader::new(std::io::BufReader::new(file));
        reader.header().unwrap();
        let mut read = 0u64;
        for item in reader {
            if let Item::Resource(_) = item.unwrap() {
                read += 1;
            }
        }
        assert_eq!(read, export.counts.values().sum::<u64>());
        sizes.push(export.bytes);
    }
    assert_eq!(sizes[0], sizes[1]);
    let names: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(names, vec!["records.ndjson".to_string()]);

    // A pull cut short goes to records.incomplete.ndjson, and the last
    // complete export stays.
    m.set_mode("degraded");
    let (export, error) =
        export::write_dir(&dir, &header(&tokens), now, |w| export::export(&c, w, None)).unwrap();
    assert_eq!(error.expect("cut short").exit_code(), 5);
    assert!(!export.complete);
    assert!(
        export.path.ends_with("/records.incomplete.ndjson"),
        "{}",
        export.path
    );
    assert!(export.bytes < sizes[0]);
    let file = std::fs::File::open(&export.path).unwrap();
    let mut reader = RecordsReader::new(std::io::BufReader::new(file));
    reader.header().unwrap();
    let last = reader.last().expect("an item");
    assert!(
        matches!(last, Err(StreamError::Incomplete { .. })),
        "{last:?}"
    );
    assert_eq!(
        std::fs::metadata(dir.join("records.ndjson")).unwrap().len(),
        sizes[0]
    );

    // The next complete export replaces records.ndjson and clears the
    // incomplete one.
    m.set_mode("normal");
    let (export, error) =
        export::write_dir(&dir, &header(&tokens), now, |w| export::export(&c, w, None)).unwrap();
    assert!(error.is_none() && export.complete);
    let mut names: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(names, vec!["records.ndjson".to_string()]);
    let _ = std::fs::remove_dir_all(&dir);
}

/// v0.2.x keychain items in memory. `denied` fails every read, as a denied
/// Keychain prompt does.
#[derive(Default)]
struct OldItems {
    items: Mutex<HashMap<String, String>>,
    denied: bool,
}

impl OldItems {
    fn holding(value: String) -> OldItems {
        let old = OldItems::default();
        old.items
            .lock()
            .unwrap()
            .insert(logout::legacy_account("mock", mock::PATIENT), value);
        old
    }

    fn is_empty(&self) -> bool {
        self.items.lock().unwrap().is_empty()
    }
}

impl LegacyItems for OldItems {
    fn get(&self, account: &str) -> Result<Option<Secret>, CliError> {
        if self.denied {
            return Err(CliError::Keychain("access was not allowed".into()));
        }
        Ok(self
            .items
            .lock()
            .unwrap()
            .get(account)
            .map(|v| Secret::new(v.clone())))
    }
    fn delete(&self, account: &str) -> Result<bool, CliError> {
        Ok(self.items.lock().unwrap().remove(account).is_some())
    }
}

/// A v0.2.x item as v0.2.x wrote it, revoked at `path` on the mock.
fn old_sign_in(m: &Mock, path: &str) -> String {
    serde_json::json!({
        "access_token": "synthetic-old-access",
        "refresh_token": "synthetic-old-refresh",
        "expires_at": 1,
        "scope": "openid",
        "patient": mock::PATIENT,
        "client_id": mock::CLIENT_ID,
        "fhir_base": m.fhir_base(),
        "token_endpoint": format!("{}/oauth2/v1/token", m.origin()),
        "revocation_endpoint": format!("{}{path}", m.origin()),
        "refreshed_at": 1
    })
    .to_string()
}

fn revocations(m: &Mock) -> usize {
    m.requests()
        .iter()
        .filter(|(method, path)| method == "POST" && path == "/oauth2/v1/revoke")
        .count()
}

/// Sign in, store the session, and sign out with `old` as the v0.2.x items.
fn sign_out_with(m: &Mock, old: &OldItems) -> (MemoryStore, logout::SignedOut) {
    let http = BlockingTransport::new().unwrap();
    let signed_in = sign_in(m, &http);
    let store = MemoryStore::default();
    store.save(&signed_in).unwrap();
    let result =
        logout::sign_out(&http, &lock(), &store, old, "mock", mock::PATIENT).expect("sign out");
    (store, result)
}

#[test]
fn logout_revokes_and_removes_the_sign_in() {
    let m = Mock::start(0);
    let old = OldItems::default();
    let (store, out) = sign_out_with(&m, &old);
    assert!(out.credential_removed && out.revoked, "{out:?}");
    assert!(out.left_behind.is_none());
    assert!(store.load(&key("mock", mock::PATIENT)).unwrap().is_none());
    assert_eq!(revocations(&m), 2, "the refresh and access tokens");
}

#[test]
fn logout_revokes_and_removes_a_v0_2_sign_in_too() {
    let m = Mock::start(0);
    let old = OldItems::holding(old_sign_in(&m, "/oauth2/v1/revoke"));
    let (_, out) = sign_out_with(&m, &old);
    assert!(out.credential_removed && out.revoked, "{out:?}");
    assert!(out.left_behind.is_none());
    assert!(old.is_empty());
    assert_eq!(revocations(&m), 4, "both items' refresh and access tokens");
}

#[test]
fn logout_removes_a_v0_2_item_that_does_not_read_without_revoking_it() {
    let m = Mock::start(0);
    let old = OldItems::holding("not a sign-in".into());
    let (_, out) = sign_out_with(&m, &old);
    assert!(out.credential_removed && out.revoked, "{out:?}");
    assert!(old.is_empty());
    assert_eq!(revocations(&m), 2, "only the new item's tokens");
}

#[test]
fn logout_is_not_revoked_when_a_v0_2_revocation_fails() {
    let m = Mock::start(0);
    let old = OldItems::holding(old_sign_in(&m, "/nowhere"));
    let (_, out) = sign_out_with(&m, &old);
    assert!(out.credential_removed, "{out:?}");
    assert!(!out.revoked, "the v0.2.x revocation answered 404");
    assert!(old.is_empty(), "the item is still deleted");
}

#[test]
fn logout_leaves_the_patient_when_the_v0_2_item_cannot_be_read() {
    let m = Mock::start(0);
    let old = OldItems {
        denied: true,
        ..OldItems::holding(old_sign_in(&m, "/oauth2/v1/revoke"))
    };
    let (store, out) = sign_out_with(&m, &old);
    let left = out.left_behind.as_ref().expect("the old item stays");
    assert_eq!(left.exit_code(), 1);
    assert!(
        left.to_string().contains("v0.2.x sign-in at mock"),
        "{left}"
    );
    assert!(!left.to_string().contains(mock::PATIENT), "{left}");
    assert!(!out.credential_removed);
    assert!(out.revoked, "the new item's tokens were revoked");
    assert!(store.load(&key("mock", mock::PATIENT)).unwrap().is_none());
    assert!(!old.is_empty());
}
