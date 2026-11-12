//! `records export`: every resource a patient sign-in can read, as a
//! `records-stream/v1` stream.

use std::collections::BTreeSet;
use std::io::{BufWriter, Write};
use std::path::Path;

use pk_cli_core::{CliError, Reason};
use serde_json::Value;

use crate::fhir::{self, Client};
use crate::http::same_origin;
use crate::smart::{granted_types, PATIENT_TYPES};
use pk_med_fhir::RawResource;
use pk_med_records::dto::RecordsExport;
use pk_med_records::export::ExportFile;

use crate::stream::{code, Finished, Header, Skip, Writer};

/// Searched by `patient`, in this order. `Patient` is read first; `Binary`
/// follows the resource that points at it.
pub const SEARCH_TYPES: &[&str] = &[
    "AllergyIntolerance",
    "Condition",
    "MedicationRequest",
    "MedicationDispense",
    "Immunization",
    "Encounter",
    "Procedure",
    "Observation",
    "DiagnosticReport",
    "DocumentReference",
    "ServiceRequest",
    "Specimen",
    "CarePlan",
    "CareTeam",
    "Goal",
    "Device",
    "Coverage",
    "RelatedPerson",
];

/// Read one by one when an exported resource refers to them. athenahealth
/// serves `Media` by read only (no search), so a `DiagnosticReport.media`
/// link is the way to it; its image follows it as a `Binary`.
pub const REFERENCED_TYPES: &[&str] = &[
    "Practitioner",
    "Organization",
    "Location",
    "Medication",
    "Media",
];

/// One stream into `out`, header to trailer: `pull` writes the resources and
/// skips. The second value is the error that cut the pull short, which the
/// trailer records as `complete: false`. `Err` means not even the header,
/// or the trailer, could be written.
pub fn write_stream<W: Write>(
    out: W,
    header: &Header,
    finished_at: impl FnOnce() -> String,
    pull: impl FnOnce(&mut Writer<W>) -> Result<(), CliError>,
) -> Result<(Finished, Option<CliError>), CliError> {
    let mut w = Writer::start(out, header)?;
    let error = pull(&mut w).err();
    let finished = w.finish(finished_at(), error.as_ref())?;
    Ok((finished, error))
}

/// The stream writer of `records export -o <DIR>`.
pub type DirWriter<'f> = Writer<BufWriter<&'f mut ExportFile>>;

/// `records export -o <DIR>` (medical-common DESIGN 1.5): the stream is
/// written beside `<DIR>/records.ndjson`, owner-only, and committed when the
/// trailer is out. A complete stream replaces `records.ndjson`; one cut short
/// goes to `records.incomplete.ndjson` and the last complete export stays.
/// Returns the `records-export/v1` summary of the file committed and the
/// error that cut the pull short. A stream whose header or trailer could not
/// be written is never committed, and its file is removed.
pub fn write_dir(
    dir: &Path,
    header: &Header,
    finished_at: impl FnOnce() -> String,
    pull: impl FnOnce(&mut DirWriter<'_>) -> Result<(), CliError>,
) -> Result<(RecordsExport, Option<CliError>), CliError> {
    let mut file = pk_med_records::export::create_export_file(dir)?;
    let (finished, error) = write_stream(BufWriter::new(&mut file), header, finished_at, pull)?;
    let path = file.commit(&finished)?;
    Ok((
        RecordsExport::new(path.display().to_string(), &finished),
        error,
    ))
}

/// Export the client's patient to `w`, whose header is already written.
/// Returns an error only for what ends the stream (a refused sign-in, a
/// failed write); everything else becomes a skip.
pub fn export<W: Write>(
    client: &Client,
    w: &mut Writer<W>,
    since: Option<&str>,
) -> Result<(), CliError> {
    let patient = client.patient().to_string();
    let granted = {
        let g = granted_types(client.session().tokens.scope.as_deref().unwrap_or_default());
        if g.is_empty() {
            // A token answer without `scope` grants what was asked for.
            PATIENT_TYPES.iter().map(|t| t.to_string()).collect()
        } else {
            g
        }
    };
    let mut references = BTreeSet::new();
    let binary_granted = granted.contains("Binary");

    match client.read("Patient", &patient) {
        Ok(resource) => {
            w.resource(&resource)?;
        }
        // Without the patient there is no export. A refusal here, when the
        // sign-in asked for Patient, means access was withdrawn.
        Err(e) if e.reason() == Some(Reason::Forbidden) => {
            return Err(e.with_remedy(format!(
                "sign in again with `athena auth login --org {}`; if it is refused again, the \
                 practice may have turned off access for this app",
                client.org()
            )))
        }
        Err(e) => return Err(e),
    }

    for resource_type in SEARCH_TYPES {
        // As records-stream/v1 asks: the search without the patient's id.
        let search = match since {
            Some(since) => format!("{resource_type}?_lastUpdated=ge{since}"),
            None => resource_type.to_string(),
        };
        if !granted.contains(*resource_type) {
            w.skip(Skip {
                resource_type: Some(resource_type.to_string()),
                id: None,
                search: Some(search),
                reason: "the sign-in did not grant this resource type".into(),
                code: code::FORBIDDEN.into(),
            });
            continue;
        }
        let mut params = vec![("patient", patient.clone())];
        if let Some(since) = since {
            params.push(("_lastUpdated", format!("ge{since}")));
        }
        // Each page is written as it is read, its Binary documents after
        // their parents, so a page that fails keeps the ones before it. What
        // ends the stream from inside a page is kept apart from the search's
        // own failure, which is a skip.
        let mut stopped = None;
        let outcome = client.search_pages(resource_type, &params, |page| {
            for why in &page.unreadable {
                w.skip(Skip {
                    resource_type: None,
                    id: None,
                    search: Some(search.clone()),
                    reason: format!("a search answered with an entry that did not read: {why}"),
                    code: code::VERIFY_FAILED.into(),
                });
            }
            for resource in page.resources.iter().chain(&page.included) {
                if let Err(e) = write_resource(client, w, resource, &mut references, binary_granted)
                {
                    stopped = Some(e);
                    return Err(CliError::Other("the export stopped".into()));
                }
            }
            Ok(())
        });
        if let Some(e) = stopped {
            return Err(e);
        }
        match outcome {
            Ok(found) => {
                if found.truncated {
                    w.skip(Skip {
                        resource_type: Some(resource_type.to_string()),
                        id: None,
                        search: Some(search),
                        reason: if found.pages >= fhir::PAGE_CAP {
                            format!("stopped after {} pages", fhir::PAGE_CAP)
                        } else {
                            format!(
                                "stopped after {} pages: the server named the last one as its \
                                 own next page",
                                found.pages
                            )
                        },
                        code: code::PAGE_CAP.into(),
                    });
                }
            }
            Err(e) => skip_or_fail(
                w,
                e,
                Some(resource_type),
                None,
                Some(search),
                client.tripped(),
            )?,
        }
    }

    for reference in references {
        let Some((resource_type, id)) = reference.split_once('/') else {
            continue;
        };
        if w.written(resource_type, id) {
            continue;
        }
        if !granted.contains(resource_type) {
            w.skip(Skip {
                resource_type: Some(resource_type.into()),
                id: Some(id.into()),
                search: None,
                reason: "the sign-in did not grant this resource type".into(),
                code: code::FORBIDDEN.into(),
            });
            continue;
        }
        match client.read(resource_type, id) {
            Ok(resource) => {
                let mut more = BTreeSet::new();
                write_resource(client, w, &resource, &mut more, binary_granted)?;
            }
            Err(e) => skip_or_fail(w, e, Some(resource_type), Some(id), None, client.tripped())?,
        }
    }
    Ok(())
}

/// Write one resource, note what it refers to, and fetch the `Binary`
/// documents it points at right after it.
fn write_resource<W: Write>(
    client: &Client,
    w: &mut Writer<W>,
    resource: &RawResource,
    references: &mut BTreeSet<String>,
    binary_granted: bool,
) -> Result<(), CliError> {
    if !w.resource(resource)? {
        return Ok(());
    }
    let Ok(value) = resource.value() else {
        return Ok(());
    };
    collect_references(&value, client.base(), references);
    for url in attachment_urls(&value) {
        fetch_binary(client, w, &url, binary_granted)?;
    }
    Ok(())
}

fn fetch_binary<W: Write>(
    client: &Client,
    w: &mut Writer<W>,
    url: &str,
    granted: bool,
) -> Result<(), CliError> {
    let Some(id) = binary_id(url, client.base()) else {
        w.skip(Skip {
            resource_type: Some("Binary".into()),
            id: None,
            search: None,
            reason: "an attachment points somewhere other than this FHIR server's Binary; athena \
                     sends its token nowhere else"
                .into(),
            code: code::UNSUPPORTED.into(),
        });
        return Ok(());
    };
    if w.written("Binary", &id) {
        return Ok(());
    }
    if !granted {
        w.skip(Skip {
            resource_type: Some("Binary".into()),
            id: Some(id),
            search: None,
            reason: "the sign-in did not grant Binary".into(),
            code: code::FORBIDDEN.into(),
        });
        return Ok(());
    }
    match client.binary(url) {
        Ok(binary) => {
            w.resource(&binary)?;
        }
        Err(e) => skip_or_fail(w, e, Some("Binary"), Some(&id), None, client.tripped())?,
    }
    Ok(())
}

/// Record a per-item failure as a skip; return the ones that end the stream.
fn skip_or_fail<W: Write>(
    w: &mut Writer<W>,
    error: CliError,
    resource_type: Option<&str>,
    id: Option<&str>,
    search: Option<String>,
    tripped: bool,
) -> Result<(), CliError> {
    let code = match (error.base(), error.reason()) {
        (_, Some(Reason::Forbidden)) => code::FORBIDDEN,
        (CliError::NotFound(_), _) => code::NOT_FOUND,
        (_, Some(Reason::BadRequest)) => code::UNSUPPORTED,
        (CliError::Upstream(_), _) if tripped => {
            return Err(CliError::Upstream(format!(
                "{} requests in a row failed, so the export stopped: {}",
                fhir::BREAKER,
                error.message()
            ))
            .with_remedy(pk_med_fhir::outcome::TRY_AGAIN))
        }
        (CliError::Upstream(_), _) => code::UPSTREAM,
        _ => return Err(error),
    };
    w.skip(Skip {
        resource_type: resource_type.map(Into::into),
        id: id.map(Into::into),
        search,
        reason: error.message().to_string(),
        code: code.into(),
    });
    Ok(())
}

/// `Binary/<id>` from an attachment URL, relative or on the FHIR server's
/// origin. `None` for anything else.
pub fn binary_id(url: &str, base: &str) -> Option<String> {
    let path = if url.starts_with("https://") || url.starts_with("http://") {
        if !same_origin(url, base) {
            return None;
        }
        url.split_once("/Binary/").map(|(_, rest)| rest)?
    } else {
        url.strip_prefix("Binary/")
            .or_else(|| url.strip_prefix("/Binary/"))?
    };
    let id = path.split(['?', '#', '/']).next().unwrap_or("");
    (!id.is_empty()).then(|| id.to_string())
}

/// The URLs of a DocumentReference's attachments, a DiagnosticReport's
/// presented forms and a Media's content. An attachment with inline `data` needs no fetch.
pub fn attachment_urls(resource: &Value) -> Vec<String> {
    let mut out = Vec::new();
    let mut push = |attachment: &Value| {
        if attachment.get("data").is_none() {
            if let Some(url) = attachment.get("url").and_then(Value::as_str) {
                out.push(url.to_string());
            }
        }
    };
    match resource.get("resourceType").and_then(Value::as_str) {
        Some("DocumentReference") => {
            for content in resource["content"].as_array().into_iter().flatten() {
                push(&content["attachment"]);
            }
        }
        Some("DiagnosticReport") => {
            for form in resource["presentedForm"].as_array().into_iter().flatten() {
                push(form);
            }
        }
        Some("Media") => push(&resource["content"]),
        _ => {}
    }
    out
}

/// Every `reference` in `value` to one of [`REFERENCED_TYPES`], as `Type/id`.
pub fn collect_references(value: &Value, base: &str, out: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            if let Some(Value::String(reference)) = map.get("reference") {
                if let Some(r) = local_reference(reference, base) {
                    out.insert(r);
                }
            }
            for v in map.values() {
                collect_references(v, base, out);
            }
        }
        Value::Array(items) => {
            for v in items {
                collect_references(v, base, out);
            }
        }
        _ => {}
    }
}

fn local_reference(reference: &str, base: &str) -> Option<String> {
    let relative = if reference.starts_with("https://") || reference.starts_with("http://") {
        if !same_origin(reference, base) {
            return None;
        }
        let base_path = base.trim_end_matches('/');
        reference.strip_prefix(base_path)?.trim_start_matches('/')
    } else {
        reference
    };
    let (resource_type, id) = relative.split_once('/')?;
    let id = id.split(['/', '?', '#']).next()?;
    (REFERENCED_TYPES.contains(&resource_type) && !id.is_empty())
        .then(|| format!("{resource_type}/{id}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const BASE: &str = "https://api.preview.platform.athenahealth.com/fhir/r4";

    #[test]
    fn binary_ids_come_only_from_this_server() {
        assert_eq!(binary_id("Binary/b-1", BASE).as_deref(), Some("b-1"));
        assert_eq!(
            binary_id(&format!("{BASE}/Binary/b-2?x=1"), BASE).as_deref(),
            Some("b-2")
        );
        assert_eq!(
            binary_id("https://elsewhere.example/Binary/b-3", BASE),
            None
        );
        assert_eq!(binary_id("DocumentReference/d-1", BASE), None);
    }

    #[test]
    fn attachments_with_inline_data_need_no_fetch() {
        let doc = json!({"resourceType":"DocumentReference","content":[
            {"attachment":{"url":"Binary/b-1","contentType":"application/pdf"}},
            {"attachment":{"data":"JVBERg==","contentType":"application/pdf"}}]});
        assert_eq!(attachment_urls(&doc), vec!["Binary/b-1"]);
        let report =
            json!({"resourceType":"DiagnosticReport","presentedForm":[{"url":"Binary/b-2"}]});
        assert_eq!(attachment_urls(&report), vec!["Binary/b-2"]);
    }

    #[test]
    fn references_to_practitioners_and_places_are_collected() {
        let encounter = json!({"resourceType":"Encounter",
            "participant":[{"individual":{"reference":"Practitioner/p-1"}}],
            "serviceProvider":{"reference": format!("{BASE}/Organization/o-1")},
            "subject":{"reference":"Patient/a-1.E-2"},
            "location":[{"location":{"reference":"https://elsewhere.example/Location/l-1"}}]});
        let mut out = BTreeSet::new();
        collect_references(&encounter, BASE, &mut out);
        assert_eq!(
            out.into_iter().collect::<Vec<_>>(),
            vec!["Organization/o-1", "Practitioner/p-1"]
        );
    }
}
