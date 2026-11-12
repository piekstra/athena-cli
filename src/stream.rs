//! `records-stream/v1`: the NDJSON a provider CLI writes and `medrec` reads,
//! from medical-common's `pk-med-records`.
//!
//! Line one is the header, then one FHIR resource per line exactly as the
//! server sent it (whitespace removed, nothing re-serialized), then the
//! `records-stream-end/v1` trailer with counts and skips.

pub use pk_med_records::dto::{kind, Organization, PatientContext};
pub use pk_med_records::stream::{
    skip as code, Finished, Header, RecordsWriter as Writer, Skip, Source,
};

/// The vendor athena names in every header.
pub const VENDOR: &str = "athenahealth";

/// The header of one patient's pull from one practice profile.
pub fn header(
    organization: Organization,
    patient: PatientContext,
    since: Option<String>,
    pulled_at: String,
) -> Header {
    let mut header = Header::new(
        Source::new(crate::BIN, crate::VERSION),
        organization,
        patient,
        pulled_at,
    );
    header.since = since;
    header
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_header_names_athena_and_the_profile() {
        let h = header(
            Organization {
                id: "clinic".into(),
                name: "Clinic".into(),
                fhir_base: "https://api.platform.athenahealth.com/fhir/r4".into(),
                vendor: Some(VENDOR.into()),
                location: None,
                aliases: Vec::new(),
            },
            PatientContext {
                id: "a-900001.E-1001".into(),
                organization: "clinic".into(),
                label: Some("kid1".into()),
                relationship: Some("proxy".into()),
                kind: Some(kind::PATIENT.into()),
                member_role: None,
                fhir_user: None,
                name: None,
                session: None,
            },
            Some("2026-01-01".into()),
            "2026-01-02T00:00:00Z".into(),
        );
        let v = serde_json::to_value(&h).unwrap();
        assert_eq!(v["schema"], "records-stream/v1");
        assert_eq!(v["source"]["cli"], "athena");
        assert_eq!(v["organization"]["vendor"], "athenahealth");
        assert_eq!(v["patient"]["kind"], "patient");
        assert_eq!(v["since"], "2026-01-01");
        assert_eq!(v["fhir_version"], "4.0.1");
        assert!(v.get("method").is_none());
    }
}
