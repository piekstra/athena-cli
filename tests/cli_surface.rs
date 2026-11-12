//! Black-box tests of the binary's surface. None reaches the keychain or the
//! network: each renders help or info, or is refused by checks that run
//! before any credential read (SPEC §1.5). The config directory is a fresh
//! temp dir per test, and the keychain service is the empty test one.

use assert_cmd::Command;
use clap::CommandFactory;
use serde_json::Value;

fn tmp() -> std::path::PathBuf {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "athena-cli-test-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn athena(home: &std::path::Path) -> Command {
    let mut cmd = Command::cargo_bin("athena").unwrap();
    cmd.env("XDG_CONFIG_HOME", home)
        .env("HOME", home)
        .env("ATHENA_KEYCHAIN_SERVICE", "piekstra.athena.hermetic-tests")
        .env_remove("ATHENA_CONFIG")
        .env_remove("NO_COLOR");
    cmd
}

fn json_of(out: &std::process::Output) -> Value {
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout is one JSON document ({e}): {}",
            String::from_utf8_lossy(&out.stdout)
        )
    })
}

/// Run and return (exit code, stdout JSON or Null, stderr).
fn run(home: &std::path::Path, args: &[&str]) -> (i32, Value, String) {
    let out = athena(home).args(args).output().unwrap();
    let value = serde_json::from_slice(&out.stdout).unwrap_or(Value::Null);
    (
        out.status.code().unwrap_or(-1),
        value,
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn paths(cmd: &clap::Command, prefix: Vec<String>, out: &mut Vec<Vec<String>>) {
    out.push(prefix.clone());
    for sub in cmd.get_subcommands() {
        let mut next = prefix.clone();
        next.push(sub.get_name().to_string());
        paths(sub, next, out);
    }
}

#[test]
fn every_command_renders_help() {
    let home = tmp();
    let mut all = Vec::new();
    paths(&athena::cli::Cli::command(), Vec::new(), &mut all);
    assert!(all.len() > 25, "{} command paths", all.len());
    for path in all {
        if path.last().map(String::as_str) == Some("help") {
            continue;
        }
        let mut args = path.clone();
        args.push("--help".into());
        let out = athena(&home).args(&args).output().unwrap();
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(!out.stdout.is_empty(), "{args:?}");
    }
}

#[test]
fn info_describes_the_cli() {
    let home = tmp();
    let out = athena(&home).arg("info").output().unwrap();
    assert!(out.status.success());
    let v = json_of(&out);
    assert_eq!(v["schema"], "cli-info/v1");
    assert_eq!(v["name"], "athena");
    assert_eq!(v["spec"], "piekstra-cli/1");
    assert_eq!(v["auth"]["method"], "browser-session");
    assert_eq!(
        v["profiles"],
        serde_json::json!(["health-records/v1", "documents/v1"])
    );
    assert_eq!(
        v["capabilities"],
        serde_json::json!(["orgs", "auth", "patients", "records", "documents", "api"])
    );
}

#[test]
fn completions_and_no_color_work() {
    let home = tmp();
    for shell in ["bash", "zsh", "fish"] {
        let out = athena(&home).args(["completions", shell]).output().unwrap();
        assert!(out.status.success() && !out.stdout.is_empty(), "{shell}");
    }
    athena(&home)
        .env("NO_COLOR", "1")
        .arg("info")
        .assert()
        .success();
    athena(&home).arg("--version").assert().success();
}

#[test]
fn usage_errors_are_exit_2_with_a_json_error() {
    let home = tmp();
    for args in [
        vec!["--json", "config", "set", "practice", "Bad Slug"],
        vec![
            "--json",
            "config",
            "set",
            "practice",
            "clinic",
            "--practice-id",
            "12a",
        ],
        vec![
            "--json",
            "config",
            "set",
            "practice",
            "clinic",
            "--practice-id",
            "195900",
        ],
        vec![
            "--json", "config", "set", "practice", "clinic", "--env", "custom",
        ],
        vec![
            "--json",
            "config",
            "set",
            "practice",
            "clinic",
            "--env",
            "custom",
            "--fhir-base",
            "http://example.com/fhir",
        ],
        vec![
            "--json",
            "config",
            "set",
            "client-id",
            "has space",
            "--env",
            "preview",
        ],
        vec!["--json", "config", "set", "redirect-ports", "80"],
        vec!["--json", "auth", "login", "--org", "Bad Slug"],
        vec![
            "--json",
            "auth",
            "login",
            "--org",
            "sandbox",
            "--label",
            "two words",
        ],
        vec!["--json", "auth", "login", "--org", "sandbox"],
        vec!["--json", "records", "export", "--patient", "x"],
        vec![
            "--json",
            "records",
            "export",
            "--ndjson",
            "--since",
            "01/02/2026",
        ],
        vec![
            "--json",
            "documents",
            "download",
            "Patient/x",
            "-o",
            "out.pdf",
        ],
        vec![
            "--json",
            "documents",
            "list",
            "--since",
            "2026-02-01",
            "--until",
            "2026-01-01",
        ],
        vec!["--json", "api", "POST", "Patient"],
    ] {
        let (code, v, _) = run(&home, &args);
        assert_eq!(code, 2, "{args:?}: {v}");
        assert_eq!(v["error"]["code"], "usage", "{args:?}");
    }
    // clap's own refusals are exit 2 too.
    for args in [
        vec!["auth", "login", "--org", "sandbox", "--timeout", "0"],
        vec!["records", "export", "--ndjson", "-o", "dir"],
        vec!["documents", "download", "-o", "dir"],
        vec!["no-such-command"],
    ] {
        let (code, _, _) = run(&home, &args);
        assert_eq!(code, 2, "{args:?}");
    }
}

#[test]
fn a_missing_client_id_names_the_registration_doc() {
    let home = tmp();
    let (code, v, _) = run(&home, &["--json", "auth", "login", "--org", "sandbox"]);
    assert_eq!(code, 2);
    let message = v["error"]["message"].as_str().unwrap();
    assert!(message.contains("docs/registration.md"), "{message}");
    assert!(message.contains("--env preview"), "{message}");
}

#[test]
fn an_unknown_profile_is_exit_4() {
    let home = tmp();
    let (code, v, _) = run(&home, &["--json", "auth", "login", "--org", "nowhere"]);
    assert_eq!(code, 4);
    assert_eq!(v["error"]["code"], "not_found");
}

#[test]
fn signed_out_reads_are_exit_3_and_touch_nothing() {
    let home = tmp();
    for args in [
        vec!["--json", "documents", "list"],
        vec![
            "--json",
            "documents",
            "download",
            "DocumentReference/d-1",
            "-o",
            "x.pdf",
        ],
        vec!["--json", "api", "GET", "Patient/x"],
        vec!["--json", "records", "export", "-o", "out"],
    ] {
        let (code, v, _) = run(&home, &args);
        assert_eq!(code, 3, "{args:?}: {v}");
        assert_eq!(v["error"]["code"], "auth", "{args:?}");
    }
    assert!(
        !home.join("out").exists(),
        "a failed export creates no directory"
    );
}

#[test]
fn a_stream_that_fails_before_its_header_writes_nothing_to_stdout() {
    let home = tmp();
    let out = athena(&home)
        .args(["--json", "records", "export", "--ndjson"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    assert!(
        out.stdout.is_empty(),
        "stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("no patient is signed in"));
}

#[test]
fn auth_status_signed_out_reads_no_keychain() {
    let home = tmp();
    let (code, v, _) = run(&home, &["--json", "auth", "status"]);
    assert_eq!(code, 0);
    assert_eq!(v["schema"], "auth-status/v1");
    assert_eq!(v["authenticated"], false);
    assert_eq!(v["method"], "browser-session");
    assert_eq!(v["sessions"], serde_json::json!([]));
    let (code, v, _) = run(&home, &["--json", "auth", "logout"]);
    assert_eq!(code, 4, "{v}");
    let (code, v, _) = run(&home, &["--json", "patients", "list"]);
    assert_eq!(code, 0);
    assert_eq!(v["schema"], "patient-list/v1");
    assert_eq!(v["items"], serde_json::json!([]));
}

#[test]
fn config_round_trips_and_stays_owner_only() {
    let home = tmp();
    let ok = |args: &[&str]| {
        let (code, v, err) = run(&home, args);
        assert_eq!(code, 0, "{args:?}: {v} {err}");
        v
    };
    ok(&[
        "--json",
        "config",
        "set",
        "client-id",
        "0oaPREVIEWEXAMPLE",
        "--env",
        "preview",
    ]);
    ok(&["--json", "config", "set", "redirect-ports", "47816,47817"]);
    ok(&[
        "--json",
        "config",
        "set",
        "practice",
        "clinic",
        "--name",
        "Example clinic",
        "--env",
        "preview",
        "--practice-id",
        "195900",
        "--brand-id",
        "1",
        "--csg-id",
        "1",
        "--portal-host",
        "example.portal.athenahealth.com",
    ]);
    let shown = ok(&["--json", "config", "show"]);
    assert_eq!(shown["schema"], "config/v1");
    assert_eq!(shown["client_ids"]["preview"], "0oaPREVIEWEXAMPLE");
    assert_eq!(shown["practices"]["clinic"]["practice_id"], "195900");

    let orgs = ok(&["--json", "orgs", "list"]);
    assert_eq!(orgs["schema"], "org-list/v1");
    let items = orgs["items"].as_array().unwrap();
    let clinic = items.iter().find(|o| o["id"] == "clinic").unwrap();
    assert_eq!(
        clinic["fhir_base"],
        "https://api.preview.platform.athenahealth.com/195900/brand/1/csg/1/fhir/r4"
    );
    assert_eq!(clinic["client_id_configured"], true);
    let sandbox = items.iter().find(|o| o["id"] == "sandbox").unwrap();
    assert_eq!(sandbox["builtin"], true);
    assert_eq!(
        sandbox["fhir_base"],
        "https://api.preview.platform.athenahealth.com/fhir/r4"
    );

    let path = ok(&["--json", "config", "path"])["path"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(path.ends_with("athena/config.json"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    ok(&["--json", "config", "unset", "practice", "clinic"]);
    let (code, _, _) = run(&home, &["--json", "config", "unset", "practice", "clinic"]);
    assert_eq!(code, 4);
    ok(&["--json", "config", "unset", "client-id", "--env", "preview"]);
    let shown = ok(&["--json", "config", "show"]);
    assert!(shown.get("client_ids").is_none());
}

#[test]
fn a_config_flag_moves_every_file() {
    let home = tmp();
    let alt = home.join("elsewhere/athena.json");
    let alt_s = alt.to_str().unwrap();
    let (code, _, _) = run(
        &home,
        &[
            "--config",
            alt_s,
            "config",
            "set",
            "client-id",
            "x1",
            "--env",
            "production",
        ],
    );
    assert_eq!(code, 0);
    assert!(alt.exists());
    let (code, v, _) = run(&home, &["--json", "--config", alt_s, "config", "show"]);
    assert_eq!(code, 0);
    assert_eq!(v["client_ids"]["production"], "x1");
    assert!(!home.join("athena/config.json").exists());
}

#[test]
fn orgs_search_needs_the_directory() {
    let home = tmp();
    let (code, v, _) = run(&home, &["--json", "orgs", "search", "pediatrics"]);
    assert_eq!(code, 4);
    assert!(v["error"]["message"]
        .as_str()
        .unwrap()
        .contains("athena orgs refresh"));
    let (code, _, _) = run(
        &home,
        &["orgs", "refresh", "--url", "http://example.com/x.json"],
    );
    assert_eq!(code, 2, "a plain-http directory URL is refused");
}

#[test]
fn self_update_check_is_documented_but_not_run() {
    let home = tmp();
    athena(&home)
        .args(["self-update", "--help"])
        .assert()
        .success();
}

#[test]
fn plain_file_export_refuses_a_real_practice_before_the_keychain() {
    let home = tmp();
    let state = home.join("athena");
    std::fs::create_dir_all(&state).unwrap();
    std::fs::write(
        state.join("sessions.json"),
        serde_json::json!({"sessions": [{
            "org": "clinic",
            "patient": "a-900001.E-1001",
            "label": "kid",
            "environment": "production",
            "fhir_base": "https://api.platform.athenahealth.com/900001/brand/1/csg/1/fhir/r4",
            "stored_at": "2026-01-01T00:00:00Z"
        }]})
        .to_string(),
    )
    .unwrap();
    let out_dir = home.join("out");
    let (code, json, _) = run(
        &home,
        &[
            "--json",
            "records",
            "export",
            "--patient",
            "kid",
            "-o",
            out_dir.to_str().unwrap(),
        ],
    );
    assert_eq!(code, 2);
    assert_eq!(json["error"]["code"], "usage");
    let message = json["error"]["message"].as_str().unwrap();
    assert!(message.contains("plain file"), "{message}");
    assert!(
        message.contains("medrec import --from athena --patient kid"),
        "{message}"
    );
    assert!(!out_dir.exists());
}

#[test]
fn a_download_path_whose_directory_is_missing_or_a_file_is_refused_first() {
    let home = tmp();
    let missing = home.join("missing").join("x.pdf");
    let (code, json, _) = run(
        &home,
        &[
            "--json",
            "documents",
            "download",
            "DocumentReference/d-1",
            "-o",
            missing.to_str().unwrap(),
        ],
    );
    assert_eq!(code, 2);
    let message = json["error"]["message"].as_str().unwrap();
    assert!(message.contains("does not exist"), "{message}");
    assert!(!home.join("missing").exists());

    let file = home.join("a-file");
    std::fs::write(&file, b"").unwrap();
    let under_file = file.join("x.pdf");
    let (code, json, _) = run(
        &home,
        &[
            "--json",
            "documents",
            "download",
            "DocumentReference/d-1",
            "-o",
            under_file.to_str().unwrap(),
        ],
    );
    assert_eq!(code, 2);
    let message = json["error"]["message"].as_str().unwrap();
    assert!(message.contains("is a file, not a directory"), "{message}");
}

#[test]
fn org_and_patient_items_read_as_the_profiles_dtos() {
    use pk_med_records::dto::{Organization, PatientContext};
    let home = tmp();
    let state = home.join("athena");
    std::fs::create_dir_all(&state).unwrap();
    let bundle = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/directory/bundle.json"
    ))
    .unwrap();
    athena::directory::parse(bundle.as_slice(), "test", "2026-01-01T00:00:00Z".into())
        .unwrap()
        .save(&state.join("directory.json"))
        .unwrap();
    std::fs::write(
        state.join("sessions.json"),
        serde_json::json!({"sessions": [{
            "org": "clinic",
            "patient": "a-900001.E-1001",
            "label": "kid",
            "relationship": "proxy",
            "environment": "production",
            "fhir_base": "https://api.platform.athenahealth.com/900001/brand/1/csg/1/fhir/r4",
            "stored_at": "2026-01-01T00:00:00Z"
        }]})
        .to_string(),
    )
    .unwrap();

    for args in [
        &["--json", "orgs", "search", "pediatrics"][..],
        &["--json", "orgs", "list"][..],
    ] {
        let (code, v, err) = run(&home, args);
        assert_eq!(code, 0, "{args:?}: {err}");
        assert_eq!(v["schema"], "org-list/v1");
        for item in v["items"].as_array().unwrap() {
            let org: Organization = serde_json::from_value(item.clone())
                .unwrap_or_else(|e| panic!("{args:?}: {e}: {item}"));
            assert_eq!(org.vendor.as_deref(), Some("athenahealth"));
        }
    }

    let (code, v, err) = run(&home, &["--json", "patients", "list"]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(v["schema"], "patient-list/v1");
    let patient: PatientContext = serde_json::from_value(v["items"][0].clone()).unwrap();
    assert_eq!(patient.organization, "clinic");
    assert_eq!(patient.kind.as_deref(), Some("patient"));
    assert_eq!(
        patient.session.as_deref(),
        Some("smart/clinic/a-900001.E-1001")
    );
}
