//! athenahealth's published directory of practices and their FHIR base URLs.
//!
//! athenahealth publishes one FHIR `Bundle` of every athenaOne practice
//! (`Organization`, with its practice and brand as extensions) and its
//! endpoints (`Endpoint`: the global base and the practice's brand base),
//! updated daily. It is large (about 135 MB), so `orgs refresh` downloads it
//! once and keeps a compact copy beside the config; `orgs search` reads the
//! copy and never the network.

use std::collections::HashMap;
use std::io::{BufReader, Read, Write};
use std::path::Path;
use std::time::Duration;

use pk_cli_core::transport::require_secure_url;
use pk_cli_core::CliError;
use serde::{Deserialize, Serialize};

use crate::session::write_private;

/// The directory athenahealth publishes for production.
pub const DIRECTORY_URL: &str =
    "https://service-base-urls.api.fhir.athena.io/athena-fhir-service-base-urls.json";

/// Refuse a download past this size: the published file is about 135 MB.
const MAX_BYTES: u64 = 1024 * 1024 * 1024;

const PRACTICE_EXT: &str = "https://fhir.athena.io/StructureDefinition/ah-practice";
const BRAND_EXT: &str = "https://fhir.athena.io/StructureDefinition/ah-brand";

/// One practice location as the directory lists it. Public information
/// athenahealth publishes; the cache holds nothing about any patient.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub practice_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub brand_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub csg_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fhir_base: Option<String>,
}

/// The cached copy.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Directory {
    pub source: String,
    pub fetched_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published_at: Option<String>,
    pub entries: Vec<Entry>,
}

#[derive(Deserialize)]
struct Bundle {
    #[serde(default)]
    timestamp: Option<String>,
    #[serde(default)]
    entry: Vec<BundleEntry>,
}

#[derive(Deserialize)]
struct BundleEntry {
    resource: Resource,
}

#[derive(Deserialize)]
struct Resource {
    #[serde(rename = "resourceType")]
    resource_type: String,
    #[serde(default)]
    id: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    address: Option<serde_json::Value>,
    #[serde(default)]
    endpoint: Vec<Reference>,
    #[serde(default)]
    extension: Vec<Extension>,
}

#[derive(Deserialize)]
struct Reference {
    #[serde(default)]
    reference: String,
}

#[derive(Deserialize)]
struct Extension {
    #[serde(default)]
    url: String,
    #[serde(rename = "valueReference", default)]
    value_reference: Option<Reference>,
}

/// Read the published bundle into directory entries.
pub fn parse(reader: impl Read, source: &str, fetched_at: String) -> Result<Directory, CliError> {
    let bundle: Bundle = serde_json::from_reader(BufReader::new(reader)).map_err(|e| {
        CliError::Upstream(format!(
            "athenahealth's practice directory is not readable: {e}"
        ))
    })?;
    let mut endpoints: HashMap<String, String> = HashMap::new();
    let mut organizations = Vec::new();
    for entry in bundle.entry {
        let r = entry.resource;
        match r.resource_type.as_str() {
            "Endpoint" => {
                if let Some(serde_json::Value::String(address)) = r.address {
                    endpoints.insert(r.id, address);
                }
            }
            "Organization" => organizations.push(r),
            _ => {}
        }
    }
    let mut entries: Vec<Entry> = organizations
        .into_iter()
        .filter_map(|org| {
            let name = org.name.filter(|n| !n.trim().is_empty())?;
            let address = org
                .address
                .as_ref()
                .and_then(|a| a.as_array())
                .and_then(|a| a.first());
            let field = |k: &str| {
                address
                    .and_then(|a| a.get(k))
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
            };
            let ext = |url: &str| {
                org.extension
                    .iter()
                    .find(|e| e.url == url)
                    .and_then(|e| e.value_reference.as_ref())
                    .map(|r| r.reference.clone())
            };
            // `Organization/a-1.Practice-900001` and `Organization/a-900001.Brand-1`.
            let practice_id = ext(PRACTICE_EXT).and_then(|r| tail_after(&r, ".Practice-"));
            let brand_id = ext(BRAND_EXT).and_then(|r| tail_after(&r, ".Brand-"));
            let fhir_base = org
                .endpoint
                .iter()
                .filter_map(|e| e.reference.strip_prefix("Endpoint/"))
                .filter_map(|id| endpoints.get(id))
                .find(|address| address.contains("/brand/"))
                .cloned();
            let csg_id = fhir_base.as_deref().and_then(csg_of);
            Some(Entry {
                name,
                city: field("city"),
                state: field("state"),
                zip: field("postalCode").map(|z| z.chars().take(5).collect()),
                practice_id,
                brand_id,
                csg_id,
                fhir_base,
            })
        })
        .collect();
    entries.sort_by_key(|e| e.name.to_lowercase());
    entries.dedup();
    Ok(Directory {
        source: source.into(),
        fetched_at,
        published_at: bundle.timestamp,
        entries,
    })
}

fn tail_after(reference: &str, marker: &str) -> Option<String> {
    let (_, tail) = reference.split_once(marker)?;
    (!tail.is_empty() && tail.chars().all(|c| c.is_ascii_digit())).then(|| tail.to_string())
}

/// The chart sharing group of a brand base URL
/// (`.../{practice}/brand/{brand}/csg/{csg}/fhir/r4`).
fn csg_of(url: &str) -> Option<String> {
    let (_, rest) = url.split_once("/csg/")?;
    let id = rest.split('/').next()?;
    (!id.is_empty() && id.chars().all(|c| c.is_ascii_digit())).then(|| id.to_string())
}

/// Download the directory to a temporary file, then parse it.
pub fn download(url: &str) -> Result<Directory, CliError> {
    require_secure_url(url)?;
    let client = pk_cli_http::builder(crate::BIN, crate::VERSION)
        .timeout(Duration::from_secs(600))
        .redirect(pk_cli_core::transport::secure_redirects())
        .build()
        .map_err(|e| CliError::Other(format!("building the HTTP client: {e}")))?;
    let mut response = client
        .get(url)
        .header("Accept", "application/fhir+json, application/json")
        .send()
        .map_err(|e| {
            CliError::Upstream(format!(
                "downloading athenahealth's practice directory: {e}"
            ))
        })?;
    if !response.status().is_success() {
        return Err(CliError::Upstream(format!(
            "athenahealth's practice directory answered HTTP {}",
            response.status().as_u16()
        )));
    }
    let mut file = tempfile_in_temp()?;
    let copied =
        std::io::copy(&mut (&mut response).take(MAX_BYTES + 1), &mut file.1).map_err(|e| {
            CliError::Upstream(format!(
                "downloading athenahealth's practice directory: {e}"
            ))
        })?;
    if copied > MAX_BYTES {
        return Err(CliError::Upstream(
            "athenahealth's practice directory is larger than athena accepts".into(),
        ));
    }
    file.1
        .flush()
        .map_err(|e| CliError::Other(format!("writing the download: {e}")))?;
    let reader = std::fs::File::open(&file.0)
        .map_err(|e| CliError::Other(format!("reading the download: {e}")))?;
    let parsed = parse(
        reader,
        url,
        pk_cli_core::dates::fmt_rfc3339(crate::unix_now()),
    );
    let _ = std::fs::remove_file(&file.0);
    parsed
}

fn tempfile_in_temp() -> Result<(std::path::PathBuf, std::fs::File), CliError> {
    let path = std::env::temp_dir().join(format!(
        "athena-directory-{}-{}.json",
        std::process::id(),
        crate::unix_now()
    ));
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|e| CliError::Other(format!("creating {}: {e}", path.display())))?;
    Ok((path, file))
}

impl Directory {
    pub fn load(path: &Path) -> Result<Option<Directory>, CliError> {
        match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(|e| {
                CliError::Other(format!("{} is not a directory cache: {e}", path.display()))
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(CliError::Other(format!("reading {}: {e}", path.display()))),
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), CliError> {
        let bytes = serde_json::to_vec(self)
            .map_err(|e| CliError::Other(format!("encoding the directory cache: {e}")))?;
        write_private(path, &bytes)
    }

    /// Entries matching every whitespace-separated term of `query`, each
    /// against the name, city, state, ZIP code or practice id.
    pub fn search(&self, query: &str) -> Vec<&Entry> {
        let terms: Vec<String> = query.split_whitespace().map(str::to_lowercase).collect();
        self.entries
            .iter()
            .filter(|e| {
                let hay = format!(
                    "{} {} {} {} {}",
                    e.name,
                    e.city.as_deref().unwrap_or(""),
                    e.state.as_deref().unwrap_or(""),
                    e.zip.as_deref().unwrap_or(""),
                    e.practice_id.as_deref().unwrap_or("")
                )
                .to_lowercase();
                terms.iter().all(|t| hay.contains(t.as_str()))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUNDLE: &str = include_str!("../tests/fixtures/directory/bundle.json");

    #[test]
    fn the_bundle_becomes_entries_with_brand_bases() {
        let dir = parse(BUNDLE.as_bytes(), "test", "2026-01-01T00:00:00Z".into()).unwrap();
        assert_eq!(dir.published_at.as_deref(), Some("2026-01-01T06:00:00Z"));
        assert_eq!(dir.entries.len(), 3);
        let first = &dir.entries[0];
        assert_eq!(first.name, "Example Family Medicine");
        assert_eq!(first.practice_id.as_deref(), Some("900001"));
        assert_eq!(first.brand_id.as_deref(), Some("1"));
        assert_eq!(first.csg_id.as_deref(), Some("1"));
        assert_eq!(
            first.fhir_base.as_deref(),
            Some("https://api.platform.athenahealth.com/900001/brand/1/csg/1/fhir/r4")
        );
        assert_eq!(first.zip.as_deref(), Some("00001"));
    }

    #[test]
    fn search_needs_every_term() {
        let dir = parse(BUNDLE.as_bytes(), "test", String::new()).unwrap();
        assert_eq!(dir.search("pediatrics").len(), 2);
        assert_eq!(dir.search("pediatrics springfield").len(), 1);
        assert_eq!(dir.search("900002").len(), 1);
        assert!(dir.search("nowhere").is_empty());
    }

    #[test]
    fn the_cache_round_trips() {
        let dir = parse(BUNDLE.as_bytes(), "test", String::new()).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("directory.json");
        dir.save(&path).unwrap();
        assert_eq!(
            Directory::load(&path).unwrap().unwrap().entries,
            dir.entries
        );
        assert!(Directory::load(&tmp.path().join("none.json"))
            .unwrap()
            .is_none());
    }
}
