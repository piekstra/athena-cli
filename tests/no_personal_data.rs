//! The repository carries no personal data; runtime output may.
//!
//! Walks every tracked file (`git ls-files`) and looks for the shapes
//! personal data takes (phone numbers, street addresses, email addresses,
//! long account-like numbers) and for athenaOne practice ids outside the
//! synthetic and public-sandbox set. It never lists real values: a denylist
//! would publish what it exists to keep out.

use std::process::Command;

/// Practice ids a tracked file may name: the global `a-1`, athenahealth's
/// published Preview sandbox practices, and the synthetic fixtures' ids.
const ALLOWED_PRACTICES: &[&str] = &["1", "80000", "195900", "900001", "900002", "900003"];

fn tracked_files() -> Vec<String> {
    let out = Command::new("git")
        .args(["ls-files"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("git ls-files");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_string)
        .collect()
}

fn digits_run(s: &str, min: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for c in s.chars().chain(std::iter::once(' ')) {
        if c.is_ascii_digit() {
            cur.push(c);
        } else {
            if cur.len() >= min {
                out.push(cur.clone());
            }
            cur.clear();
        }
    }
    out
}

/// All one digit, at least four zeros then at most three digits (a counter
/// in an invented id), or a 555 phone number.
fn is_dummy_number(n: &str) -> bool {
    let first = n.chars().next().unwrap();
    let zeros = n.len() - n.trim_start_matches('0').len();
    n.chars().all(|c| c == first)
        || (zeros >= 4 && n.len() - zeros <= 3)
        || n.starts_with("555")
        || n.starts_with("1555")
}

/// The digits right after each `marker` in `line`.
fn ids_after<'a>(line: &'a str, marker: &str) -> Vec<&'a str> {
    line.match_indices(marker)
        .map(|(i, _)| {
            let rest = &line[i + marker.len()..];
            let end = rest
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(rest.len());
            &rest[..end]
        })
        .filter(|d| !d.is_empty())
        .collect()
}

/// The digits right before each `marker` in `line`.
fn ids_before<'a>(line: &'a str, marker: &str) -> Vec<&'a str> {
    line.match_indices(marker)
        .map(|(i, _)| {
            let head = &line[..i];
            let start = head
                .rfind(|c: char| !c.is_ascii_digit())
                .map_or(0, |j| j + 1);
            &head[start..]
        })
        .filter(|d| !d.is_empty())
        .collect()
}

fn scan_line(line: &str) -> Vec<String> {
    let mut findings = Vec::new();
    let phoneish: String = line.replace(['(', ')', '-', '.', ' '], "");
    for n in digits_run(line, 7).into_iter().chain(
        digits_run(&phoneish, 10)
            .into_iter()
            .filter(|n| n.len() <= 11),
    ) {
        if !is_dummy_number(&n) {
            findings.push(format!("number {n}"));
        }
    }
    for word in line.split(|c: char| c.is_whitespace() || "\"'<>(),;`".contains(c)) {
        if let Some((local, domain)) = word.split_once('@') {
            let domain =
                domain.trim_end_matches(|c: char| !(c.is_ascii_alphanumeric() || c == '-'));
            let ok = local.is_empty()
                || !domain.contains('.')
                || domain == "example.com"
                || domain.ends_with(".example")
                || domain == "mailinator.com"
                || domain.ends_with("users.noreply.github.com");
            if !ok {
                findings.push(format!("email {word}"));
            }
        }
    }
    let lower = line.to_ascii_lowercase();
    for suffix in [" way", " st", " ave", " blvd", " dr", " ln", " ct", " rd"] {
        if let Some(pos) = lower.find(suffix) {
            let has_number = lower[..pos]
                .split_whitespace()
                .rev()
                .take(4)
                .any(|w| w.len() >= 3 && w.chars().all(|c| c.is_ascii_digit()));
            if has_number && !lower.contains("example") {
                findings.push(format!("address-like `{}`", line.trim()));
            }
        }
    }
    // athenaOne practice ids: in base URLs, patient and practice ids, portal hosts and flags.
    let mut practices = Vec::new();
    practices.extend(ids_before(line, "/brand/"));
    practices.extend(ids_after(line, ".Practice-"));
    practices.extend(ids_after(line, "Organization/a-"));
    practices.extend(ids_after(line, "Patient/a-"));
    practices.extend(ids_after(line, "\"a-"));
    practices.extend(ids_after(line, "ah-practice=Organization/a-1.Practice-"));
    practices.extend(ids_after(line, "--practice-id "));
    practices.extend(ids_after(line, "practice_id\": \""));
    for (i, _) in line.match_indices(".portal.athenahealth.com") {
        // `<practice>-<brand>.portal.athenahealth.com`
        let host_start = line[..i]
            .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
            .map_or(0, |j| j + 1);
        if let Some(p) = line[host_start..i].split('-').next() {
            if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() {
                practices.push(p);
            }
        }
    }
    for p in practices {
        if !ALLOWED_PRACTICES.contains(&p) {
            findings.push(format!("practice id {p}"));
        }
    }
    findings
}

#[test]
fn tracked_files_carry_no_personal_data() {
    let files = tracked_files();
    if files.is_empty() {
        return;
    }
    let mut findings = Vec::new();
    for file in files {
        if file.ends_with(".lock")
            || file.starts_with("LICENSE")
            || file == "tests/no_personal_data.rs"
        {
            continue;
        }
        let path = format!("{}/{file}", env!("CARGO_MANIFEST_DIR"));
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for (i, line) in text.lines().enumerate() {
            for f in scan_line(line) {
                findings.push(format!("{file}:{}: {f}", i + 1));
            }
        }
    }
    assert!(
        findings.is_empty(),
        "personal-data shapes in tracked files:\n{}",
        findings.join("\n")
    );
}

/// The fixtures' people and patients are the synthetic ones.
#[test]
fn fixture_identities_are_synthetic() {
    let dir = format!("{}/tests/fixtures/mock", env!("CARGO_MANIFEST_DIR"));
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let mut stack = vec![&value];
        while let Some(v) = stack.pop() {
            match v {
                serde_json::Value::Object(map) => {
                    if let Some(serde_json::Value::String(family)) = map.get("family") {
                        assert!(
                            family.starts_with("Test"),
                            "{}: family name `{family}`",
                            path.display()
                        );
                    }
                    if let Some(serde_json::Value::String(r)) = map.get("reference") {
                        if let Some(id) = r.strip_prefix("Patient/") {
                            assert_eq!(id, "a-900001.E-1001", "{}", path.display());
                        }
                    }
                    for key in ["telecom", "address", "photo"] {
                        assert!(
                            !map.contains_key(key),
                            "{}: `{key}` in a fixture",
                            path.display()
                        );
                    }
                    stack.extend(map.values());
                }
                serde_json::Value::Array(items) => stack.extend(items),
                _ => {}
            }
        }
    }
}

#[test]
fn the_scanner_flags_real_shapes_and_passes_dummies() {
    for real in [
        "call (772) 404-1234",
        "account 8123456789",
        "member 0000123456",
        "mail someone@gmail.com",
        "lives at 1234 NW Oak St, Somewhere",
        "https://api.platform.athenahealth.com/4321/brand/1/csg/1/fhir/r4",
        "Patient/a-4321.E-77",
        "athena config set practice x --practice-id 4321",
        "4321-1.portal.athenahealth.com",
    ] {
        assert!(!scan_line(real).is_empty(), "missed: {real}");
    }
    for dummy in [
        "call (555) 010-0001",
        "npi 0000000001",
        "Organization/00000000-0000-5000-8000-000000000101",
        "phrtest_preview@mailinator.com, someone@example.com",
        "1 Example Way, Springfield",
        "https://api.preview.platform.athenahealth.com/195900/brand/1/csg/1/fhir/r4",
        "Patient/a-195900.E-60178 and a-80000.E-14545",
        "Organization/a-1.Practice-195900",
        "--practice-id <ID>",
        "<practice>-<brand>.portal.athenahealth.com",
    ] {
        assert!(
            scan_line(dummy).is_empty(),
            "false positive: {dummy}: {:?}",
            scan_line(dummy)
        );
    }
}
