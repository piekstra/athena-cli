//! The sign-in, the stream and the documents against the loopback mock,
//! in-process, with tokens in memory: nothing here reads or writes the
//! keychain.

mod support;

use std::thread;
use std::time::Duration;

use athena::config::Practice;
use athena::documents;
use athena::env::Environment;
use athena::export;
use athena::fhir::Client;
use athena::login;
use athena::session::{key, MemoryStore, TokenSet, TokenStore};
use athena::stream::{self, Writer};
use pk_cli_core::RangeArgs;
use pk_cli_http::BlockingTransport;
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
            practice: &practice(m),
            org_name: "Mock practice",
            client_id: mock::CLIENT_ID,
            ports: &[0],
            timeout: Duration::from_secs(30),
        },
    )
    .expect("prepare the sign-in")
}

fn sign_in(m: &Mock, http: &BlockingTransport) -> TokenSet {
    let pending = prepare(m, http);
    let start = pending.start_url();
    let browser = thread::spawn(move || mock::click_through(&start));
    let outcome = pending
        .finish(http, athena::unix_now())
        .expect("finish the sign-in");
    let page = browser.join().unwrap();
    assert_eq!(page.status, 200);
    assert!(page.body.contains("Signed in"));
    assert_eq!(outcome.relationship, Some("proxy"));
    outcome.tokens
}

fn no_sleep(_: Duration) {}

fn client<'a>(
    http: &'a BlockingTransport,
    store: &'a MemoryStore,
    tokens: &TokenSet,
) -> Client<'a> {
    let k = key("mock", &tokens.patient);
    store.set(&k, tokens).unwrap();
    Client::new(http, store, None, k, tokens.clone()).with_clock(athena::unix_now, no_sleep)
}

fn header(tokens: &TokenSet) -> stream::Header {
    stream::Header::new(
        stream::Organization {
            id: "mock".into(),
            name: "Mock practice".into(),
            fhir_base: tokens.fhir_base.clone(),
            vendor: "athenahealth",
        },
        stream::Patient {
            id: tokens.patient.clone(),
            organization: "mock".into(),
            label: Some("kid".into()),
            relationship: Some("proxy".into()),
            kind: "patient",
        },
        None,
        "2026-01-01T00:00:00Z".into(),
    )
}

fn lines(bytes: Vec<u8>) -> Vec<Value> {
    String::from_utf8(bytes)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).expect("every line is JSON"))
        .collect()
}

#[test]
fn a_caregiver_sign_in_gets_tokens_for_the_chosen_patient() {
    let m = Mock::start(0);
    let http = BlockingTransport::new().unwrap();
    let tokens = sign_in(&m, &http);
    assert_eq!(tokens.patient, mock::PATIENT);
    assert_eq!(tokens.fhir_user.as_deref(), Some(mock::FHIR_USER));
    assert!(tokens.refresh_token.is_some());
    assert!(tokens.scope.contains("patient/DocumentReference.read"));
    // expires_in came as the string "3600".
    assert!(tokens.expires_at > athena::unix_now() + 3000);
}

#[test]
fn the_export_streams_every_resource_with_binaries_after_their_parents() {
    let m = Mock::start(0);
    let http = BlockingTransport::new().unwrap();
    let tokens = sign_in(&m, &http);
    let store = MemoryStore::default();
    let mut c = client(&http, &store, &tokens);
    let mut w = Writer::new(Vec::new());
    w.header(&header(&tokens)).unwrap();
    export::export(&mut c, &mut w, None).expect("export");
    let out = lines(w.finish("2026-01-01T00:00:01Z".into()).unwrap());

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
    let store = MemoryStore::default();
    let mut c = client(&http, &store, &tokens);
    let mut w = Writer::new(Vec::new());
    w.header(&header(&tokens)).unwrap();
    export::export(&mut c, &mut w, None).unwrap();
    let text = String::from_utf8(w.finish(String::new()).unwrap()).unwrap();
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
    let store = MemoryStore::default();
    let mut c = client(&http, &store, &tokens);
    m.expire_access_tokens();
    c.read(&format!("Patient/{}", mock::PATIENT))
        .expect("read after renewal");
    assert_eq!(m.refresh_grants(), 1);
    let scope = &m.refresh_scopes()[0];
    assert!(scope.contains("launch/patient") && scope.contains("patient/Patient.read"));
    let stored = store.get(&key("mock", mock::PATIENT)).unwrap().unwrap();
    assert_ne!(stored.access_token, tokens.access_token);
    assert_eq!(
        stored.refresh_token, tokens.refresh_token,
        "the refresh token is kept"
    );
    assert!(stored.refreshed_at >= tokens.refreshed_at);
}

#[test]
fn a_revoked_sign_in_ends_the_stream_incomplete_with_exit_3() {
    let m = Mock::start(0);
    let http = BlockingTransport::new().unwrap();
    let tokens = sign_in(&m, &http);
    let store = MemoryStore::default();
    let mut c = client(&http, &store, &tokens);
    m.expire_access_tokens();
    m.set_mode("revoked");
    let mut w = Writer::new(Vec::new());
    w.header(&header(&tokens)).unwrap();
    let err = export::export(&mut c, &mut w, None).unwrap_err();
    assert_eq!(err.exit_code(), 3);
    assert!(
        err.to_string().contains("athena auth login --org mock"),
        "{err}"
    );
    let out = lines(w.fail(&err, String::new()).unwrap());
    let trailer = out.last().unwrap();
    assert_eq!(trailer["complete"], false);
    assert_eq!(trailer["error"]["code"], err.code());
    // The dead refresh token is dropped, so status reports the sign-in unusable.
    let stored = store.get(&key("mock", mock::PATIENT)).unwrap().unwrap();
    assert!(stored.refresh_token.is_none());
    assert!(!stored.usable(athena::unix_now()));
    // The client holds the same marked set, which is what the caller writes
    // into the session index.
    assert_eq!(c.tokens(), &stored);
}

#[test]
fn a_server_that_is_down_fails_the_export_after_retries() {
    let m = Mock::start(0);
    let http = BlockingTransport::new().unwrap();
    let tokens = sign_in(&m, &http);
    let store = MemoryStore::default();
    let mut c = client(&http, &store, &tokens);
    m.set_mode("down");
    let before = m.requests().len();
    let mut w = Writer::new(Vec::new());
    w.header(&header(&tokens)).unwrap();
    let err = export::export(&mut c, &mut w, None).expect_err("no patient, no export");
    assert_eq!(err.exit_code(), 5);
    let out = lines(w.fail(&err, String::new()).unwrap());
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
    let store = MemoryStore::default();
    let mut c = client(&http, &store, &tokens);
    m.set_mode("forbidden");
    let mut w = Writer::new(Vec::new());
    w.header(&header(&tokens)).unwrap();
    let err = export::export(&mut c, &mut w, None).expect_err("refused");
    assert_eq!(err.exit_code(), 3);
    assert!(err.to_string().contains("turned off access"), "{err}");
    let out = lines(w.fail(&err, String::new()).unwrap());
    assert_eq!(out.len(), 2);
    assert_eq!(out[1]["complete"], false);
}

#[test]
fn failing_searches_trip_the_breaker() {
    let m = Mock::start(0);
    let http = BlockingTransport::new().unwrap();
    let tokens = sign_in(&m, &http);
    let store = MemoryStore::default();
    let mut c = client(&http, &store, &tokens);
    m.set_mode("degraded");
    let before = m.requests().len();
    let mut w = Writer::new(Vec::new());
    w.header(&header(&tokens)).unwrap();
    let err = export::export(&mut c, &mut w, None).expect_err("the breaker trips");
    assert_eq!(err.exit_code(), 5);
    assert!(err.to_string().contains("in a row"), "{err}");
    let out = lines(w.fail(&err, String::new()).unwrap());
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
    let err = pending
        .finish(&http, athena::unix_now())
        .err()
        .expect("a refusal");
    assert_eq!(err.exit_code(), 3);
    assert!(err.message().contains("cancelled"));
    assert_eq!(browser.join().unwrap().status, 400);
}

#[test]
fn documents_are_listed_newest_first_and_checked_on_download() {
    let m = Mock::start(0);
    let http = BlockingTransport::new().unwrap();
    let tokens = sign_in(&m, &http);
    let store = MemoryStore::default();
    let mut c = client(&http, &store, &tokens);
    let items = documents::list(&mut c, &RangeArgs::default()).unwrap();
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

    let pdf = documents::fetch(&mut c, &items[1]).ok().unwrap();
    assert!(pdf.bytes.starts_with(b"%PDF"));
    let png = documents::fetch(&mut c, &items[0]).ok().unwrap();
    assert!(png.bytes.starts_with(b"\x89PNG"));
    assert_eq!(documents::extension(png.content_type.as_deref()), "png");
    let html = documents::fetch(&mut c, &items[2]).err().unwrap();
    assert_eq!(html.code, "verify_failed");
    let elsewhere = documents::fetch(&mut c, &items[3]).err().unwrap();
    assert_eq!(elsewhere.code, "no_file");

    let found = documents::find(&mut c, "DocumentReference/doc-2#1").unwrap();
    assert_eq!(found.document.id, "DocumentReference/doc-2#1");
    assert_eq!(
        documents::find(&mut c, "DocumentReference/doc-2#3")
            .unwrap_err()
            .exit_code(),
        4
    );
    assert_eq!(
        documents::find(&mut c, "DocumentReference/none")
            .unwrap_err()
            .exit_code(),
        4
    );

    let since = RangeArgs {
        since: Some("2026-02-01".into()),
        ..RangeArgs::default()
    };
    assert_eq!(documents::list(&mut c, &since).unwrap().len(), 2);
}

#[test]
fn a_token_goes_nowhere_but_its_own_server() {
    let m = Mock::start(0);
    let http = BlockingTransport::new().unwrap();
    let tokens = sign_in(&m, &http);
    let store = MemoryStore::default();
    let c = client(&http, &store, &tokens);
    assert_eq!(
        c.resolve("https://elsewhere.example/fhir/r4/Patient/x")
            .unwrap_err()
            .exit_code(),
        2
    );
    assert!(c.resolve(&format!("{}/Patient/x", m.fhir_base())).is_ok());
}
