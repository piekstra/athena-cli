//! `records-stream/v1`: the NDJSON a provider CLI writes and `medrec` reads.
//!
//! Line one is the header, then one FHIR resource per line exactly as the
//! server sent it (whitespace removed, nothing re-serialized), then the
//! `records-stream-end/v1` trailer with counts and skips. The shape is
//! `pk-med-records`'s; this writer is athena's until that crate is tagged.

use std::collections::{BTreeMap, HashSet};
use std::io::Write;

use pk_cli_core::CliError;
use serde::Serialize;

/// The longest line written. A resource beyond it is skipped as `too_large`.
pub const LINE_CAP: usize = 64 * 1024 * 1024;

/// Skip codes, `pk-med-records`' set.
pub mod code {
    pub const NO_FILE: &str = "no_file";
    pub const VERIFY_FAILED: &str = "verify_failed";
    pub const UPSTREAM: &str = "upstream";
    pub const FORBIDDEN: &str = "forbidden";
    pub const NOT_FOUND: &str = "not_found";
    pub const TOO_LARGE: &str = "too_large";
    pub const UNSUPPORTED: &str = "unsupported";
    pub const PAGE_CAP: &str = "page_cap";
}

#[derive(Debug, Clone, Serialize)]
pub struct Header {
    pub schema: &'static str,
    pub source: Source,
    pub organization: Organization,
    pub patient: Patient,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
    pub pulled_at: String,
    pub fhir_version: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct Source {
    pub cli: &'static str,
    pub version: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct Organization {
    pub id: String,
    pub name: String,
    pub fhir_base: String,
    pub vendor: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct Patient {
    pub id: String,
    pub organization: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relationship: Option<String>,
    pub kind: &'static str,
}

impl Header {
    pub fn new(
        organization: Organization,
        patient: Patient,
        since: Option<String>,
        pulled_at: String,
    ) -> Header {
        Header {
            schema: "records-stream/v1",
            source: Source {
                cli: crate::BIN,
                version: crate::VERSION,
            },
            organization,
            patient,
            since,
            pulled_at,
            fhir_version: "4.0.1",
        }
    }
}

/// One thing the stream does not carry, and why.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Skip {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search: Option<String>,
    pub reason: String,
    pub code: &'static str,
}

#[derive(Serialize)]
struct Trailer<'a> {
    schema: &'static str,
    complete: bool,
    counts: &'a BTreeMap<String, u64>,
    skipped: &'a [Skip],
    finished_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<TrailerError<'a>>,
}

#[derive(Serialize)]
struct TrailerError<'a> {
    code: &'a str,
    message: &'a str,
}

/// Writes one stream: the header once, resources deduplicated by
/// (resourceType, id), the trailer last, with counts that always match the
/// lines written.
pub struct Writer<W: Write> {
    out: W,
    header_written: bool,
    counts: BTreeMap<String, u64>,
    seen: HashSet<(String, String)>,
    skipped: Vec<Skip>,
}

impl<W: Write> Writer<W> {
    pub fn new(out: W) -> Writer<W> {
        Writer {
            out,
            header_written: false,
            counts: BTreeMap::new(),
            seen: HashSet::new(),
            skipped: Vec::new(),
        }
    }

    pub fn header_written(&self) -> bool {
        self.header_written
    }

    pub fn header(&mut self, header: &Header) -> Result<(), CliError> {
        let line = serde_json::to_string(header)
            .map_err(|e| CliError::Other(format!("encoding the stream header: {e}")))?;
        self.line(&line)?;
        self.header_written = true;
        Ok(())
    }

    /// Whether (type, id) has been written already.
    pub fn has(&self, resource_type: &str, id: &str) -> bool {
        self.seen
            .contains(&(resource_type.to_string(), id.to_string()))
    }

    /// Write one resource's JSON text. `false` when it was a duplicate or
    /// too large (the latter recorded as a skip).
    pub fn resource(
        &mut self,
        resource_type: &str,
        id: &str,
        json: &str,
    ) -> Result<bool, CliError> {
        if !id.is_empty() && self.has(resource_type, id) {
            return Ok(false);
        }
        let line = minify(json);
        if line.len() > LINE_CAP {
            self.skip(Skip {
                resource_type: Some(resource_type.into()),
                id: Some(id.into()).filter(|i: &String| !i.is_empty()),
                search: None,
                reason: format!("{} bytes is over the stream's line cap", line.len()),
                code: code::TOO_LARGE,
            });
            return Ok(false);
        }
        self.line(&line)?;
        if !id.is_empty() {
            self.seen.insert((resource_type.into(), id.into()));
        }
        *self.counts.entry(resource_type.into()).or_insert(0) += 1;
        Ok(true)
    }

    pub fn skip(&mut self, skip: Skip) {
        self.skipped.push(skip);
    }

    pub fn counts(&self) -> &BTreeMap<String, u64> {
        &self.counts
    }

    pub fn skipped(&self) -> &[Skip] {
        &self.skipped
    }

    /// The trailer of a stream that ran to its end.
    pub fn finish(mut self, finished_at: String) -> Result<W, CliError> {
        self.trailer(true, None, finished_at)?;
        Ok(self.out)
    }

    /// The trailer of a stream cut short by `error`.
    pub fn fail(mut self, error: &CliError, finished_at: String) -> Result<W, CliError> {
        self.trailer(false, Some(error), finished_at)?;
        Ok(self.out)
    }

    fn trailer(
        &mut self,
        complete: bool,
        error: Option<&CliError>,
        finished_at: String,
    ) -> Result<(), CliError> {
        let message = error.map(|e| e.to_string());
        let trailer = Trailer {
            schema: "records-stream-end/v1",
            complete,
            counts: &self.counts,
            skipped: &self.skipped,
            finished_at,
            error: error.zip(message.as_deref()).map(|(e, m)| TrailerError {
                code: e.code(),
                message: m,
            }),
        };
        let line = serde_json::to_string(&trailer)
            .map_err(|e| CliError::Other(format!("encoding the stream trailer: {e}")))?;
        self.line(&line)?;
        self.out
            .flush()
            .map_err(|e| CliError::Other(format!("writing the stream: {e}")))
    }

    fn line(&mut self, line: &str) -> Result<(), CliError> {
        self.out
            .write_all(line.as_bytes())
            .and_then(|_| self.out.write_all(b"\n"))
            .map_err(|e| CliError::Other(format!("writing the stream: {e}")))
    }
}

/// JSON text with the whitespace between tokens removed and every string,
/// number and key left byte for byte as it was.
pub fn minify(json: &str) -> String {
    let mut out = String::with_capacity(json.len());
    let mut in_string = false;
    let mut escaped = false;
    for c in json.chars() {
        if in_string {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
        } else if c == '"' {
            in_string = true;
            out.push(c);
        } else if !matches!(c, ' ' | '\n' | '\r' | '\t') {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> Header {
        Header::new(
            Organization {
                id: "sandbox".into(),
                name: "Sandbox".into(),
                fhir_base: "https://example.invalid/fhir/r4".into(),
                vendor: "athenahealth",
            },
            Patient {
                id: "a-1.E-2".into(),
                organization: "sandbox".into(),
                label: Some("test".into()),
                relationship: Some("proxy".into()),
                kind: "patient",
            },
            Some("2026-01-01".into()),
            "2026-01-02T00:00:00Z".into(),
        )
    }

    #[test]
    fn minify_keeps_strings_and_numbers_exact() {
        assert_eq!(
            minify("{ \"a\" : \"x  y\\\" z\",\n \"n\": 1.50 , \"e\": 1E+2 }"),
            "{\"a\":\"x  y\\\" z\",\"n\":1.50,\"e\":1E+2}"
        );
    }

    #[test]
    fn a_stream_is_header_resources_trailer_with_matching_counts() {
        let mut w = Writer::new(Vec::new());
        w.header(&header()).unwrap();
        assert!(w
            .resource(
                "Patient",
                "a-1.E-2",
                "{\"resourceType\":\"Patient\",\"id\":\"a-1.E-2\"}"
            )
            .unwrap());
        assert!(!w.resource("Patient", "a-1.E-2", "{}").unwrap());
        w.resource(
            "Observation",
            "o-1",
            "{ \"resourceType\": \"Observation\", \"id\": \"o-1\" }",
        )
        .unwrap();
        w.skip(Skip {
            resource_type: Some("Goal".into()),
            id: None,
            search: Some("Goal?patient=a-1.E-2".into()),
            reason: "not granted".into(),
            code: code::FORBIDDEN,
        });
        let out = String::from_utf8(w.finish("2026-01-02T00:00:01Z".into()).unwrap()).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 4);
        let head: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(head["schema"], "records-stream/v1");
        assert_eq!(head["source"]["cli"], "athena");
        assert_eq!(head["organization"]["vendor"], "athenahealth");
        assert_eq!(head["patient"]["relationship"], "proxy");
        assert_eq!(head["fhir_version"], "4.0.1");
        assert_eq!(
            lines[2],
            "{\"resourceType\":\"Observation\",\"id\":\"o-1\"}"
        );
        let tail: serde_json::Value = serde_json::from_str(lines[3]).unwrap();
        assert_eq!(tail["schema"], "records-stream-end/v1");
        assert_eq!(tail["complete"], true);
        assert_eq!(tail["counts"]["Patient"], 1);
        assert_eq!(tail["counts"]["Observation"], 1);
        assert_eq!(tail["skipped"][0]["code"], "forbidden");
        assert!(tail.get("error").is_none());
    }

    #[test]
    fn a_failed_stream_says_so() {
        let mut w = Writer::new(Vec::new());
        w.header(&header()).unwrap();
        let err = CliError::Auth("signed out".into());
        let out = String::from_utf8(w.fail(&err, "2026-01-02T00:00:01Z".into()).unwrap()).unwrap();
        let tail: serde_json::Value = serde_json::from_str(out.lines().last().unwrap()).unwrap();
        assert_eq!(tail["complete"], false);
        assert_eq!(tail["error"]["code"], err.code());
    }
}
