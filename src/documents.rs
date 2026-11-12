//! `documents list|download` (`documents/v1`): the files a patient sign-in
//! can read, from `DocumentReference` attachments and `DiagnosticReport`
//! presented forms, fetched as `Binary`.
//!
//! A document's id is the resource it hangs on, `DocumentReference/<id>` or
//! `DiagnosticReport/<id>`, with `#<n>` (from 1) when that resource carries
//! more than one file.

use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use pk_cli_core::{CliError, RangeArgs, Reason};
use pk_cli_documents::{fs_safe, Document, SKIP_NO_FILE, SKIP_UPSTREAM, SKIP_VERIFY_FAILED};
use serde_json::Value;

use crate::export::binary_id;
use crate::fhir::Client;

/// One file a resource carries, and where its bytes are.
#[derive(Debug, Clone)]
pub struct Item {
    pub document: Document,
    pub content_type: Option<String>,
    source: Source,
}

#[derive(Debug, Clone)]
enum Source {
    /// `attachment.data`, base64.
    Inline(String),
    /// `attachment.url`.
    Url(String),
    /// An attachment with neither.
    None,
}

/// The files of one `DocumentReference` or `DiagnosticReport`.
pub fn items_of(resource: &Value) -> Vec<Item> {
    let Some(resource_type) = resource["resourceType"].as_str() else {
        return Vec::new();
    };
    let id = resource["id"].as_str().unwrap_or_default();
    let attachments: Vec<&Value> = match resource_type {
        "DocumentReference" => resource["content"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|c| &c["attachment"])
            .collect(),
        "DiagnosticReport" => resource["presentedForm"]
            .as_array()
            .into_iter()
            .flatten()
            .collect(),
        _ => return Vec::new(),
    };
    let several = attachments.len() > 1;
    let name = title(resource, resource_type);
    let date = date(resource, resource_type);
    let category = category(resource);
    attachments
        .into_iter()
        .enumerate()
        .map(|(n, attachment)| {
            let source = match (attachment["data"].as_str(), attachment["url"].as_str()) {
                (Some(data), _) => Source::Inline(data.to_string()),
                (None, Some(url)) => Source::Url(url.to_string()),
                _ => Source::None,
            };
            let doc_id = if several {
                format!("{resource_type}/{id}#{}", n + 1)
            } else {
                format!("{resource_type}/{id}")
            };
            let mut document = Document::new(doc_id, name.clone());
            document.date = date.clone();
            document.category = category.clone();
            document.file = attachment["title"]
                .as_str()
                .filter(|t| !t.trim().is_empty())
                .map(str::to_string);
            Item {
                document,
                content_type: attachment["contentType"].as_str().map(str::to_string),
                source,
            }
        })
        .collect()
}

fn title(resource: &Value, resource_type: &str) -> String {
    let coded = |field: &str| {
        resource[field]["text"]
            .as_str()
            .or_else(|| resource[field]["coding"][0]["display"].as_str())
            .map(str::to_string)
    };
    let found = match resource_type {
        "DocumentReference" => resource["description"]
            .as_str()
            .map(str::to_string)
            .or_else(|| coded("type")),
        _ => coded("code"),
    };
    found.filter(|t| !t.trim().is_empty()).unwrap_or_else(|| {
        if resource_type == "DiagnosticReport" {
            "Report".into()
        } else {
            "Document".into()
        }
    })
}

fn date(resource: &Value, resource_type: &str) -> Option<String> {
    let candidates: &[&str] = match resource_type {
        "DocumentReference" => &["date"],
        _ => &["effectiveDateTime", "issued"],
    };
    let raw = candidates
        .iter()
        .find_map(|f| resource[*f].as_str())
        .or_else(|| resource["context"]["period"]["start"].as_str())
        .or_else(|| resource["effectivePeriod"]["start"].as_str())?;
    let day = raw.get(..10)?;
    pk_cli_core::dates::parse_iso(day)
        .ok()
        .map(|_| day.to_string())
}

fn category(resource: &Value) -> Option<String> {
    let c = &resource["category"][0];
    c["coding"][0]["code"]
        .as_str()
        .or_else(|| c["text"].as_str())
        .map(str::to_string)
}

/// Every document of the signed-in patient, newest first, within `range`.
pub fn list(client: &mut Client<'_>, range: &RangeArgs) -> Result<Vec<Item>, CliError> {
    range.validate()?;
    let patient = client.patient().to_string();
    let mut items = Vec::new();
    for resource_type in ["DocumentReference", "DiagnosticReport"] {
        client.search(resource_type, &[("patient", patient.clone())], |_, raw| {
            if let Ok(value) = serde_json::from_str::<Value>(raw.get()) {
                items.extend(items_of(&value));
            }
            Ok(())
        })?;
    }
    items.retain(|item| {
        let date = item.document.date.as_deref();
        range
            .since
            .as_deref()
            .is_none_or(|s| date.is_some_and(|d| d >= s))
            && range
                .until
                .as_deref()
                .is_none_or(|u| date.is_some_and(|d| d <= u))
    });
    items.sort_by(|a, b| b.document.date.cmp(&a.document.date));
    if let Some(limit) = range.limit {
        items.truncate(limit as usize);
    }
    Ok(items)
}

/// `DocumentReference/<id>[#n]` split into the resource reference and the
/// attachment's index (0 when there is no `#n`).
pub fn parse_id(id: &str) -> Result<(String, usize), CliError> {
    let (reference, n) = match id.split_once('#') {
        Some((r, n)) => {
            let n: usize = n
                .parse()
                .ok()
                .filter(|n| *n >= 1)
                .ok_or_else(|| bad_id(id))?;
            (r, n - 1)
        }
        None => (id, 0),
    };
    let (resource_type, rid) = reference.split_once('/').ok_or_else(|| bad_id(id))?;
    let ok_type = matches!(resource_type, "DocumentReference" | "DiagnosticReport");
    let ok_id = !rid.is_empty()
        && rid.len() <= 64
        && rid
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.');
    if !(ok_type && ok_id) {
        return Err(bad_id(id));
    }
    Ok((reference.to_string(), n))
}

fn bad_id(id: &str) -> CliError {
    CliError::Usage(format!(
        "`{id}` is not a document id: expected DocumentReference/<id> or DiagnosticReport/<id>, \
         with #<n> for one of several files"
    ))
    .with_remedy("list them with `athena documents list`")
}

/// One document by id: its resource read, its file picked out.
pub fn find(client: &mut Client<'_>, id: &str) -> Result<Item, CliError> {
    let (reference, n) = parse_id(id)?;
    let body = client.read(&reference)?;
    let value: Value = serde_json::from_str(&body).map_err(|_| {
        CliError::Upstream(format!(
            "{reference} came back as something other than JSON"
        ))
    })?;
    let mut items = items_of(&value);
    if n >= items.len() {
        return Err(CliError::NotFound(format!(
            "{reference} carries {} file(s); there is no #{}",
            items.len(),
            n + 1
        )));
    }
    let mut item = items.swap_remove(n);
    // The id the caller used, so a single-file document read by its plain id
    // keeps it.
    item.document.id = id.to_string();
    Ok(item)
}

/// A file's bytes and their content type, decoded and checked.
pub struct Fetched {
    pub bytes: Vec<u8>,
    pub content_type: Option<String>,
}

/// Why a file could not be produced, as a `documents/v1` skip code.
pub struct FetchError {
    pub code: &'static str,
    pub error: CliError,
}

impl From<CliError> for FetchError {
    fn from(error: CliError) -> Self {
        FetchError {
            code: SKIP_UPSTREAM,
            error,
        }
    }
}

/// Fetch an item's bytes: inline, or the `Binary` its URL names on this
/// FHIR server.
pub fn fetch(client: &mut Client<'_>, item: &Item) -> Result<Fetched, FetchError> {
    let (data, content_type) = match &item.source {
        Source::Inline(data) => (data.clone(), item.content_type.clone()),
        Source::Url(url) => {
            if binary_id(url, client.base()).is_none() {
                return Err(FetchError {
                    code: SKIP_NO_FILE,
                    error: CliError::NotFound(
                        "the file is not a Binary on this FHIR server; athena sends its token \
                         nowhere else"
                            .into(),
                    ),
                });
            }
            let body = client.read(url).map_err(|error| FetchError {
                code: match (error.base(), error.reason()) {
                    (CliError::NotFound(_), _) | (_, Some(Reason::Forbidden)) => SKIP_NO_FILE,
                    _ => SKIP_UPSTREAM,
                },
                error,
            })?;
            let value: Value = serde_json::from_str(&body).map_err(|_| FetchError {
                code: SKIP_VERIFY_FAILED,
                error: CliError::Upstream(
                    "the Binary came back as something other than JSON".into(),
                ),
            })?;
            if value["resourceType"] != "Binary" {
                return Err(FetchError {
                    code: SKIP_VERIFY_FAILED,
                    error: CliError::Upstream(
                        "the server answered with something other than a Binary".into(),
                    ),
                });
            }
            let data = value["data"].as_str().unwrap_or_default().to_string();
            let content_type = value["contentType"]
                .as_str()
                .map(str::to_string)
                .or_else(|| item.content_type.clone());
            (data, content_type)
        }
        Source::None => {
            return Err(FetchError {
                code: SKIP_NO_FILE,
                error: CliError::NotFound("the document carries no file".into()),
            })
        }
    };
    if data.is_empty() {
        return Err(FetchError {
            code: SKIP_NO_FILE,
            error: CliError::NotFound("the document's file is empty".into()),
        });
    }
    let bytes = STANDARD
        .decode(
            data.as_bytes()
                .iter()
                .filter(|b| !b.is_ascii_whitespace())
                .copied()
                .collect::<Vec<u8>>(),
        )
        .map_err(|_| FetchError {
            code: SKIP_VERIFY_FAILED,
            error: CliError::Upstream("the document's data is not base64".into()),
        })?;
    verify(&bytes, content_type.as_deref()).map_err(|error| FetchError {
        code: SKIP_VERIFY_FAILED,
        error,
    })?;
    Ok(Fetched {
        bytes,
        content_type,
    })
}

/// Check bytes against their declared type by magic number, or as text. The
/// message names the type and the size only: a document's bytes are never
/// quoted.
pub fn verify(bytes: &[u8], content_type: Option<&str>) -> Result<(), CliError> {
    let mime = mime(content_type);
    let ok = match mime.as_str() {
        _ if bytes.is_empty() => false,
        "application/pdf" => bytes.starts_with(b"%PDF"),
        "image/png" => bytes.starts_with(b"\x89PNG\r\n\x1a\n"),
        "image/jpeg" | "image/jpg" => bytes.starts_with(&[0xFF, 0xD8, 0xFF]),
        "image/gif" => bytes.starts_with(b"GIF8"),
        "image/tiff" => bytes.starts_with(b"II*\0") || bytes.starts_with(b"MM\0*"),
        "application/dicom" => bytes.len() > 132 && &bytes[128..132] == b"DICM",
        m if m.starts_with("text/")
            || m.ends_with("+xml")
            || m == "application/xml"
            || m == "application/rtf" =>
        {
            std::str::from_utf8(&bytes[..bytes.len().min(4096)])
                .map(|_| true)
                .unwrap_or_else(|e| e.error_len().is_none())
        }
        _ => true,
    };
    if ok {
        Ok(())
    } else {
        Err(CliError::Upstream(format!(
            "the file ({} bytes) is not the {} it was declared as",
            bytes.len(),
            if mime.is_empty() {
                "document"
            } else {
                mime.as_str()
            }
        )))
    }
}

fn mime(content_type: Option<&str>) -> String {
    content_type
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}

/// The extension a saved file gets for its content type.
pub fn extension(content_type: Option<&str>) -> &'static str {
    match mime(content_type).as_str() {
        "application/pdf" => "pdf",
        "image/png" => "png",
        "image/jpeg" | "image/jpg" => "jpg",
        "image/gif" => "gif",
        "image/tiff" => "tif",
        "text/plain" => "txt",
        "text/html" => "html",
        "text/xml" | "application/xml" => "xml",
        "application/rtf" | "text/rtf" => "rtf",
        "application/dicom" => "dcm",
        "application/msword" => "doc",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document" => "docx",
        _ => "bin",
    }
}

/// `<date>_<name>_<id>.<ext>`, every part through `fs_safe`.
pub fn file_name(item: &Item, content_type: Option<&str>) -> String {
    let date = item.document.date.as_deref().unwrap_or("undated");
    let name: String = fs_safe(&item.document.name).chars().take(60).collect();
    let id = fs_safe(
        item.document
            .id
            .rsplit('/')
            .next()
            .unwrap_or(&item.document.id),
    );
    format!(
        "{}_{}_{}.{}",
        fs_safe(date),
        name.trim_matches('_'),
        id,
        extension(content_type)
    )
}

/// Where `-o` puts a file: inside it when it is a directory, else at it.
pub fn target(out: &Path, item: &Item, content_type: Option<&str>) -> PathBuf {
    if out.is_dir() {
        out.join(file_name(item, content_type))
    } else {
        out.to_path_buf()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_reference_with_two_files_gives_two_documents() {
        let doc = json!({"resourceType":"DocumentReference","id":"d-1","date":"2026-03-04T10:00:00Z",
            "type":{"text":"Visit summary"},"category":[{"coding":[{"code":"clinical-note"}]}],
            "content":[{"attachment":{"url":"Binary/b-1","contentType":"application/pdf"}},
                       {"attachment":{"data":"JVBERi0x","contentType":"application/pdf","title":"page.pdf"}}]});
        let items = items_of(&doc);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].document.id, "DocumentReference/d-1#1");
        assert_eq!(items[1].document.id, "DocumentReference/d-1#2");
        assert_eq!(items[0].document.name, "Visit summary");
        assert_eq!(items[0].document.date.as_deref(), Some("2026-03-04"));
        assert_eq!(items[0].document.category.as_deref(), Some("clinical-note"));
        assert_eq!(items[1].document.file.as_deref(), Some("page.pdf"));
    }

    #[test]
    fn a_report_names_itself_by_its_code() {
        let report = json!({"resourceType":"DiagnosticReport","id":"r-1","effectiveDateTime":"2026-02-01",
            "code":{"coding":[{"display":"Imaging report"}]},"presentedForm":[{"url":"Binary/b-2","contentType":"image/png"}]});
        let items = items_of(&report);
        assert_eq!(items[0].document.id, "DiagnosticReport/r-1");
        assert_eq!(items[0].document.name, "Imaging report");
        assert_eq!(items[0].document.date.as_deref(), Some("2026-02-01"));
    }

    #[test]
    fn ids_are_checked() {
        assert_eq!(
            parse_id("DocumentReference/d-1").unwrap(),
            ("DocumentReference/d-1".into(), 0)
        );
        assert_eq!(
            parse_id("DiagnosticReport/r.1#2").unwrap(),
            ("DiagnosticReport/r.1".into(), 1)
        );
        for bad in [
            "Patient/x",
            "DocumentReference/",
            "DocumentReference/d#0",
            "DocumentReference/../x",
            "d-1",
        ] {
            assert_eq!(parse_id(bad).unwrap_err().exit_code(), 2, "{bad}");
        }
    }

    #[test]
    fn files_are_checked_by_magic_without_quoting_them() {
        assert!(verify(b"%PDF-1.7", Some("application/pdf")).is_ok());
        let err = verify(b"<html>secret", Some("application/pdf")).unwrap_err();
        assert!(!err.message().contains("secret"));
        assert!(!err.message().contains("html"));
        assert!(verify(b"\x89PNG\r\n\x1a\n....", Some("image/png")).is_ok());
        assert!(verify(b"plain words", Some("text/plain; charset=utf-8")).is_ok());
        assert!(verify(&[0xff, 0xfe, 0x00, 0x80], Some("text/plain")).is_err());
        assert!(verify(b"", None).is_err());
    }

    #[test]
    fn file_names_cannot_leave_the_directory() {
        let mut item = items_of(&json!({"resourceType":"DocumentReference","id":"d-1",
            "description":"../../etc/passwd","content":[{"attachment":{"url":"Binary/b"}}]}))
        .remove(0);
        item.document.date = Some("2026-01-02".into());
        let name = file_name(&item, Some("application/pdf"));
        assert_eq!(name, "2026-01-02_etc_passwd_d-1.pdf");
        assert!(!name.contains('/'));
    }
}
