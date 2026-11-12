//! SMART App Launch for a standalone patient app: discovery and scopes.

use std::collections::BTreeSet;

use pk_cli_core::transport::require_secure_url;
use pk_cli_core::CliError;
use serde::Deserialize;

use crate::http::{request, Http};

/// `.well-known/smart-configuration`, the fields athena uses.
///
/// athenahealth's `issuer` is its Okta authorization server
/// (`https://athena.okta.com/oauth2/...`), not the FHIR host, and its
/// `grant_types_supported` leaves out `refresh_token` although refresh works;
/// neither is relied on beyond what is noted here.
#[derive(Debug, Clone, Deserialize)]
pub struct SmartConfiguration {
    #[serde(default)]
    pub issuer: Option<String>,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(default)]
    pub revocation_endpoint: Option<String>,
    #[serde(default)]
    pub code_challenge_methods_supported: Vec<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
}

/// Read a FHIR server's SMART configuration.
pub fn discover(http: &dyn Http, fhir_base: &str) -> Result<SmartConfiguration, CliError> {
    let url = format!(
        "{}/.well-known/smart-configuration",
        fhir_base.trim_end_matches('/')
    );
    let response = http.call(request("GET", &url).header("Accept", "application/json"))?;
    if !response.is_success() {
        return Err(CliError::Upstream(format!(
            "the FHIR server's SMART configuration answered HTTP {}",
            response.status
        )));
    }
    let config: SmartConfiguration = serde_json::from_str(&response.body).map_err(|e| {
        CliError::Upstream(format!(
            "the FHIR server's SMART configuration is not readable: {e}"
        ))
    })?;
    for endpoint in std::iter::once(&config.authorization_endpoint)
        .chain(std::iter::once(&config.token_endpoint))
        .chain(config.revocation_endpoint.iter())
    {
        require_secure_url(endpoint).map_err(|_| {
            CliError::Upstream(
                "the FHIR server's SMART configuration names an endpoint that is not https".into(),
            )
        })?;
    }
    if !config.code_challenge_methods_supported.is_empty()
        && !config
            .code_challenge_methods_supported
            .iter()
            .any(|m| m == "S256")
    {
        return Err(CliError::Upstream(
            "the FHIR server does not support PKCE S256, which a client without a secret needs"
                .into(),
        ));
    }
    Ok(config)
}

/// The resource types athena asks to read: athenahealth's list of
/// auto-approved patient scopes for a standalone launch, less the DSTU2-only
/// and proprietary names. athenahealth refuses wildcard scopes, so each is
/// named.
pub const PATIENT_TYPES: &[&str] = &[
    "AllergyIntolerance",
    "Binary",
    "CarePlan",
    "CareTeam",
    "Condition",
    "Coverage",
    "Device",
    "DiagnosticReport",
    "DocumentReference",
    "Encounter",
    "Goal",
    "Immunization",
    "Location",
    "Media",
    "Medication",
    "MedicationDispense",
    "MedicationRequest",
    "Observation",
    "Organization",
    "Patient",
    "Practitioner",
    "Procedure",
    "Provenance",
    "RelatedPerson",
    "ServiceRequest",
    "Specimen",
];

/// The scope string of a standalone patient sign-in: OpenID Connect, a
/// refresh token, the patient picker, and read access per type.
pub fn scope_string() -> String {
    let mut scopes = vec![
        "openid".to_string(),
        "fhirUser".into(),
        "offline_access".into(),
        "launch/patient".into(),
    ];
    scopes.extend(PATIENT_TYPES.iter().map(|t| format!("patient/{t}.read")));
    scopes.join(" ")
}

/// The resource types a granted scope string allows reading, in SMART v1
/// (`patient/Observation.read`, `patient/*.read`) and v2
/// (`patient/Observation.rs`, with or without a `?category=` narrowing)
/// spellings.
pub fn granted_types(scope: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for item in scope.split_whitespace() {
        let Some(rest) = item
            .strip_prefix("patient/")
            .or_else(|| item.strip_prefix("user/"))
        else {
            continue;
        };
        let Some((resource, perms)) = rest.split_once('.') else {
            continue;
        };
        let perms = perms.split('?').next().unwrap_or("");
        let reads = perms == "read"
            || perms == "*"
            || (!perms.is_empty()
                && perms.chars().all(|c| "cruds".contains(c))
                && (perms.contains('r') || perms.contains('s')));
        if !reads {
            continue;
        }
        if resource == "*" {
            out.extend(PATIENT_TYPES.iter().map(|t| t.to_string()));
        } else {
            out.insert(resource.to_string());
        }
    }
    out
}

/// `self` when the signed-in person is the patient the token is for,
/// `proxy` when someone else (a caregiver) signed in, from the id token's
/// `fhirUser`.
pub fn relationship(fhir_user: Option<&str>, patient: &str) -> Option<&'static str> {
    let user = fhir_user?;
    if user == format!("Patient/{patient}") || user.ends_with(&format!("/Patient/{patient}")) {
        Some("self")
    } else {
        Some("proxy")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_scope_names_every_type_and_no_wildcard() {
        let scope = scope_string();
        assert!(scope.starts_with("openid fhirUser offline_access launch/patient "));
        assert!(scope.contains("patient/DocumentReference.read"));
        assert!(scope.contains("patient/Binary.read"));
        assert!(!scope.contains('*'));
        assert_eq!(scope.split(' ').count(), 4 + PATIENT_TYPES.len());
    }

    #[test]
    fn granted_types_reads_v1_and_v2_spellings() {
        let granted = granted_types(
            "openid patient/Patient.read patient/Observation.rs?category=http://x|laboratory \
             patient/Condition.s patient/Goal.c launch/patient",
        );
        assert!(granted.contains("Patient"));
        assert!(granted.contains("Observation"));
        assert!(granted.contains("Condition"));
        assert!(!granted.contains("Goal"));
        assert!(!granted.contains("launch"));
        assert_eq!(granted_types("patient/*.read").len(), PATIENT_TYPES.len());
    }

    #[test]
    fn relationship_comes_from_fhir_user() {
        assert_eq!(
            relationship(Some("https://x/fhir/r4/Patient/a-1.E-2"), "a-1.E-2"),
            Some("self")
        );
        assert_eq!(
            relationship(Some("RelatedPerson/r-1"), "a-1.E-2"),
            Some("proxy")
        );
        assert_eq!(
            relationship(Some("Patient/a-1.E-9"), "a-1.E-2"),
            Some("proxy")
        );
        assert_eq!(relationship(None, "a-1.E-2"), None);
    }
}
