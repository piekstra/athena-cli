//! A loopback stand-in for athenahealth: SMART discovery, an authorize
//! endpoint that answers at once, a token endpoint that checks PKCE, token
//! revocation, and a FHIR R4 server over the synthetic fixtures in
//! `tests/fixtures/mock`. Shared by the integration tests and
//! `examples/mock_server.rs`, which the dogfood runs against.
//!
//! It copies the athenahealth behaviours `docs/api.md` records: `expires_in`
//! as a string, a refresh grant that must carry `scope` and returns no new
//! refresh token, the chosen patient in the token answer, an id token whose
//! `fhirUser` is a `RelatedPerson` (a caregiver's sign-in), `cursor` paging,
//! and `Binary` as JSON with base64 `data`.
//!
//! Its mode (`POST /__mock/mode?set=<mode>`) switches the error paths on:
//! `normal`, `expired` (every access token is refused until refreshed),
//! `revoked` (every refresh is `invalid_grant`), `deny` (the sign-in is
//! cancelled), `down` (FHIR answers 503), `forbidden` (FHIR answers 403).

#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use sha2::{Digest, Sha256};

pub const CLIENT_ID: &str = "mock-client";
pub const PATIENT: &str = "a-900001.E-1001";
pub const FHIR_USER: &str = "RelatedPerson/rp-1";

macro_rules! fixture {
    ($name:literal) => {
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/mock/",
            $name
        ))
    };
}

fn fixture(path: &str) -> Option<&'static str> {
    Some(match path {
        "Patient" => fixture!("patient.json"),
        "AllergyIntolerance" => fixture!("search-AllergyIntolerance.json"),
        "Condition" => fixture!("search-Condition.json"),
        "Encounter" => fixture!("search-Encounter.json"),
        "Observation" => fixture!("search-Observation.json"),
        "Observation-page2" => fixture!("search-Observation-page2.json"),
        "Immunization" => fixture!("search-Immunization.json"),
        "DiagnosticReport" => fixture!("search-DiagnosticReport.json"),
        "DocumentReference" => fixture!("search-DocumentReference.json"),
        "Practitioner/pr-1" => fixture!("practitioner.json"),
        "Organization/org-1" => fixture!("organization.json"),
        "Location/loc-1" => fixture!("location.json"),
        "Media/media-1" => fixture!("media.json"),
        "Binary/bin-pdf-1" => fixture!("binary-bin-pdf-1.json"),
        "Binary/bin-pdf-2" => fixture!("binary-bin-pdf-2.json"),
        "Binary/bin-png-1" => fixture!("binary-bin-png-1.json"),
        "Binary/bin-png-2" => fixture!("binary-bin-png-2.json"),
        "outcome-forbidden" => fixture!("outcome-forbidden.json"),
        "outcome-unsupported" => fixture!("outcome-unsupported.json"),
        "outcome-expired" => fixture!("outcome-expired.json"),
        _ => return None,
    })
}

#[derive(Default)]
struct State {
    mode: String,
    next: u64,
    /// code -> (challenge, redirect_uri, nonce, scope)
    codes: HashMap<String, (String, String, String, String)>,
    /// access tokens that work
    access: Vec<String>,
    /// refresh tokens that work
    refresh: Vec<String>,
    /// how many 429s are still owed, by resource type
    throttle: HashMap<String, u32>,
    /// requests seen: (method, path)
    pub log: Vec<(String, String)>,
    refresh_grants: u32,
    refresh_scopes: Vec<String>,
}

#[derive(Clone)]
pub struct Mock {
    pub port: u16,
    state: Arc<Mutex<State>>,
}

pub struct Http {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Http {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

impl Mock {
    /// Listen on `port` (0: any free one) of 127.0.0.1.
    pub fn start(port: u16) -> Mock {
        let listener = TcpListener::bind(("127.0.0.1", port)).expect("bind the mock");
        let port = listener.local_addr().unwrap().port();
        let state = Arc::new(Mutex::new(State {
            mode: "normal".into(),
            ..State::default()
        }));
        state
            .lock()
            .unwrap()
            .throttle
            .insert("Immunization".into(), 1);
        let mock = Mock { port, state };
        let server = mock.clone();
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let server = server.clone();
                thread::spawn(move || server.serve(stream));
            }
        });
        mock
    }

    pub fn origin(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    pub fn fhir_base(&self) -> String {
        format!("{}/fhir/r4", self.origin())
    }

    pub fn set_mode(&self, mode: &str) {
        self.state.lock().unwrap().mode = mode.into();
    }

    pub fn requests(&self) -> Vec<(String, String)> {
        self.state.lock().unwrap().log.clone()
    }

    pub fn refresh_grants(&self) -> u32 {
        self.state.lock().unwrap().refresh_grants
    }

    pub fn refresh_scopes(&self) -> Vec<String> {
        self.state.lock().unwrap().refresh_scopes.clone()
    }

    /// Refuse every access token issued so far, as an expiry would.
    pub fn expire_access_tokens(&self) {
        self.state.lock().unwrap().access.clear();
    }

    fn serve(&self, mut stream: TcpStream) {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
        let Some((method, target, headers, body)) = read_request(&mut stream) else {
            return;
        };
        self.state.lock().unwrap().log.push((
            method.clone(),
            target.split('?').next().unwrap_or("").to_string(),
        ));
        let response = self.route(&method, &target, &headers, &body);
        write_response(&mut stream, response);
    }

    fn route(&self, method: &str, target: &str, headers: &[(String, String)], body: &str) -> Http {
        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        let q = parse_form(query);
        match (method, path) {
            ("POST", "/__mock/mode") => {
                self.set_mode(q.get("set").map(String::as_str).unwrap_or("normal"));
                json(200, "{\"ok\":true}")
            }
            ("POST", "/__mock/expire") => {
                self.expire_access_tokens();
                json(200, "{\"ok\":true}")
            }
            ("GET", "/fhir/r4/.well-known/smart-configuration") => {
                json(200, &self.smart_configuration())
            }
            ("GET", "/oauth2/v1/authorize") => self.authorize(&q),
            ("POST", "/oauth2/v1/token") => self.token(&parse_form(body)),
            ("POST", "/oauth2/v1/revoke") => {
                let form = parse_form(body);
                let mut s = self.state.lock().unwrap();
                if let Some(t) = form.get("token") {
                    s.access.retain(|a| a != t);
                    s.refresh.retain(|r| r != t);
                }
                json(200, "")
            }
            ("GET", p) if p.starts_with("/fhir/r4/") => {
                self.fhir(&p["/fhir/r4/".len()..], &q, headers)
            }
            _ => json(404, "{\"error\":\"not found\"}"),
        }
    }

    fn smart_configuration(&self) -> String {
        let o = self.origin();
        serde_json::json!({
            "issuer": format!("{o}/oauth2/mock"),
            "authorization_endpoint": format!("{o}/oauth2/v1/authorize"),
            "token_endpoint": format!("{o}/oauth2/v1/token"),
            "revocation_endpoint": format!("{o}/oauth2/v1/revoke"),
            "token_endpoint_auth_methods_supported": ["none", "client_secret_basic", "private_key_jwt"],
            "grant_types_supported": ["authorization_code", "client_credentials"],
            "code_challenge_methods_supported": ["S256"],
            "capabilities": ["launch-standalone", "client-public", "context-standalone-patient",
                             "permission-offline", "permission-patient", "sso-openid-connect"]
        })
        .to_string()
    }

    fn authorize(&self, q: &HashMap<String, String>) -> Http {
        let get = |k: &str| q.get(k).cloned().unwrap_or_default();
        let redirect = get("redirect_uri");
        if !redirect.starts_with("http://127.0.0.1:") || !redirect.ends_with("/callback") {
            return json(400, "{\"error\":\"invalid_request\",\"error_description\":\"redirect_uri is not registered\"}");
        }
        let state = get("state");
        if self.state.lock().unwrap().mode == "deny" {
            return redirect_to(&format!(
                "{redirect}?error=access_denied&error_description=Synthetic+denial&state={}",
                enc(&state)
            ));
        }
        let problems = [
            (get("response_type") != "code", "response_type"),
            (get("client_id") != CLIENT_ID, "client_id"),
            (
                get("code_challenge_method") != "S256",
                "code_challenge_method",
            ),
            (get("code_challenge").is_empty(), "code_challenge"),
            (get("aud") != self.fhir_base(), "aud"),
            (state.is_empty(), "state"),
            (get("nonce").is_empty(), "nonce"),
            (
                !get("scope").split(' ').any(|s| s == "launch/patient"),
                "scope",
            ),
        ];
        if let Some((_, what)) = problems.iter().find(|(bad, _)| *bad) {
            return redirect_to(&format!(
                "{redirect}?error=invalid_request&error_description={what}&state={}",
                enc(&state)
            ));
        }
        let mut s = self.state.lock().unwrap();
        s.next += 1;
        let code = format!("code-{}", s.next);
        s.codes.insert(
            code.clone(),
            (
                get("code_challenge"),
                redirect.clone(),
                get("nonce"),
                get("scope"),
            ),
        );
        redirect_to(&format!(
            "{redirect}?code={code}&state={}&iss={}",
            enc(&state),
            enc(&format!("{}/oauth2/mock", self.origin()))
        ))
    }

    fn token(&self, form: &HashMap<String, String>) -> Http {
        let get = |k: &str| form.get(k).cloned().unwrap_or_default();
        if get("client_id") != CLIENT_ID {
            return json(401, "{\"error\":\"invalid_client\"}");
        }
        let mut s = self.state.lock().unwrap();
        match get("grant_type").as_str() {
            "authorization_code" => {
                let Some((challenge, redirect, nonce, scope)) = s.codes.remove(&get("code")) else {
                    return json(400, "{\"error\":\"invalid_grant\"}");
                };
                let computed =
                    URL_SAFE_NO_PAD.encode(Sha256::digest(get("code_verifier").as_bytes()));
                if computed != challenge || redirect != get("redirect_uri") {
                    return json(400, "{\"error\":\"invalid_grant\",\"error_description\":\"PKCE or redirect_uri mismatch\"}");
                }
                s.next += 1;
                let n = s.next;
                let access = format!("mock-access-{n}");
                let refresh = format!("mock-refresh-{n}");
                s.access.push(access.clone());
                s.refresh.push(refresh.clone());
                let granted: Vec<&str> = scope.split(' ').collect();
                let id_token = jwt(&serde_json::json!({
                    "iss": format!("{}/oauth2/mock", self.origin()),
                    "aud": CLIENT_ID,
                    "nonce": nonce,
                    "fhirUser": FHIR_USER,
                    "sub": "synthetic-user"
                }));
                json(
                    200,
                    &serde_json::json!({
                        "token_type": "Bearer",
                        "expires_in": "3600",
                        "access_token": access,
                        "scope": granted.join(" "),
                        "refresh_token": refresh,
                        "id_token": id_token,
                        "patient": PATIENT
                    })
                    .to_string(),
                )
            }
            "refresh_token" => {
                s.refresh_grants += 1;
                s.refresh_scopes.push(get("scope"));
                if s.mode == "revoked" || !s.refresh.contains(&get("refresh_token")) {
                    return json(400, "{\"error\":\"invalid_grant\",\"error_description\":\"The refresh token is invalid or expired.\"}");
                }
                if get("scope").is_empty() {
                    return json(
                        400,
                        "{\"error\":\"invalid_scope\",\"error_description\":\"scope is required\"}",
                    );
                }
                s.next += 1;
                let access = format!("mock-access-{}", s.next);
                s.access.push(access.clone());
                // athenahealth's refresh answer: a new access token, the old refresh token kept.
                json(
                    200,
                    &serde_json::json!({
                        "token_type": "Bearer",
                        "expires_in": 3600,
                        "access_token": access,
                        "scope": get("scope")
                    })
                    .to_string(),
                )
            }
            _ => json(400, "{\"error\":\"unsupported_grant_type\"}"),
        }
    }

    fn fhir(&self, path: &str, q: &HashMap<String, String>, headers: &[(String, String)]) -> Http {
        let token = headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("authorization"))
            .and_then(|(_, v)| v.strip_prefix("Bearer "))
            .unwrap_or("")
            .to_string();
        let base = self.fhir_base();
        let mut s = self.state.lock().unwrap();
        if s.mode == "expired" || !s.access.contains(&token) {
            return fhir_json(401, fixture("outcome-expired").unwrap());
        }
        match s.mode.as_str() {
            "down" => return fhir_json(503, "Service Unavailable"),
            "forbidden" => return fhir_json(403, fixture("outcome-forbidden").unwrap()),
            _ => {}
        }
        let (resource_type, id) = path.split_once('/').unwrap_or((path, ""));
        if let Some(left) = s.throttle.get_mut(resource_type) {
            if *left > 0 {
                *left -= 1;
                let mut r = fhir_json(429, "{\"resourceType\":\"OperationOutcome\",\"issue\":[{\"severity\":\"error\",\"code\":\"throttled\"}]}");
                r.headers.push(("Retry-After".into(), "0".into()));
                return r;
            }
        }
        drop(s);
        let serve = |text: &str| fhir_json(200, &text.replace("{{BASE}}", &base));
        if !id.is_empty() {
            if resource_type == "Patient" {
                return if id == PATIENT {
                    serve(fixture("Patient").unwrap())
                } else {
                    fhir_json(403, fixture("outcome-forbidden").unwrap())
                };
            }
            if let Some(text) = fixture(path) {
                return serve(text);
            }
            // A read of a resource the searches return.
            if let Some(found) = fixture(resource_type).and_then(|b| find_in_bundle(b, id)) {
                return serve(&found);
            }
            return fhir_json(404, "{\"resourceType\":\"OperationOutcome\",\"issue\":[{\"severity\":\"error\",\"code\":\"not-found\"}]}");
        }
        // A search.
        if q.get("patient").map(String::as_str) != Some(PATIENT) {
            return fhir_json(400, fixture("outcome-unsupported").unwrap());
        }
        match resource_type {
            "Goal" => fhir_json(403, fixture("outcome-forbidden").unwrap()),
            "ServiceRequest" => fhir_json(400, fixture("outcome-unsupported").unwrap()),
            "Observation" if q.get("cursor").map(String::as_str) == Some("2") => serve(fixture("Observation-page2").unwrap()),
            t => match fixture(t) {
                Some(text) if t != "Patient" => serve(text),
                _ => fhir_json(200, &format!(
                    "{{\"resourceType\":\"Bundle\",\"type\":\"searchset\",\"total\":0,\"link\":[{{\"relation\":\"self\",\"url\":\"{base}/{t}\"}}]}}"
                )),
            },
        }
    }
}

fn find_in_bundle(bundle: &str, id: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(bundle).ok()?;
    value["entry"]
        .as_array()?
        .iter()
        .map(|e| &e["resource"])
        .find(|r| r["id"] == id)
        .map(|r| serde_json::to_string_pretty(r).unwrap())
}

fn jwt(claims: &serde_json::Value) -> String {
    let head = URL_SAFE_NO_PAD.encode(b"{\"alg\":\"none\",\"typ\":\"JWT\"}");
    let body = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
    format!("{head}.{body}.")
}

fn json(status: u16, body: &str) -> Http {
    Http {
        status,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: body.into(),
    }
}

fn fhir_json(status: u16, body: &str) -> Http {
    Http {
        status,
        headers: vec![("Content-Type".into(), "application/fhir+json".into())],
        body: body.into(),
    }
}

fn redirect_to(location: &str) -> Http {
    Http {
        status: 302,
        headers: vec![("Location".into(), location.into())],
        body: String::new(),
    }
}

fn enc(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

pub fn decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    out.push(b);
                    i += 2;
                } else {
                    out.push(b'%');
                }
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn parse_form(s: &str) -> HashMap<String, String> {
    s.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (decode(k), decode(v))
        })
        .collect()
}

/// A request as the mock reads it: method, target, headers, body.
type Request = (String, String, Vec<(String, String)>, String);

fn read_request(stream: &mut TcpStream) -> Option<Request> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let method = first.next()?.to_string();
    let target = first.next()?.to_string();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    let length: usize = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    let mut body = buf[head_end..].to_vec();
    while body.len() < length {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    Some((
        method,
        target,
        headers,
        String::from_utf8_lossy(&body).into_owned(),
    ))
}

fn write_response(stream: &mut TcpStream, r: Http) {
    let reason = match r.status {
        200 => "OK",
        302 => "Found",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        429 => "Too Many Requests",
        _ => "Status",
    };
    let mut head = format!(
        "HTTP/1.1 {} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n",
        r.status,
        r.body.len()
    );
    for (k, v) in &r.headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(r.body.as_bytes());
    let _ = stream.flush();
}

/// A plain GET over a fresh connection, as a browser would make it: the
/// tests use it to click through the sign-in.
pub fn get(url: &str) -> Http {
    let rest = url.strip_prefix("http://").expect("an http URL");
    let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    let path = if path.is_empty() { "/" } else { path };
    let mut stream = TcpStream::connect(authority).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    Http {
        status,
        headers,
        body: body.to_string(),
    }
}

/// What a person does in the browser: open athena's start page, press the
/// button, let athenahealth redirect back. Returns the callback page.
pub fn click_through(start_url: &str) -> Http {
    let page = get(start_url);
    assert_eq!(page.status, 200, "the start page");
    let href = page
        .body
        .split("id=\"signin\" href=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("the sign-in link")
        .replace("&amp;", "&");
    let answer = get(&href);
    assert_eq!(answer.status, 302, "the authorize endpoint redirects");
    get(answer.header("Location").expect("a Location"))
}
