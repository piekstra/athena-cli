# Fixtures

Every person, practice, record and identifier here is invented. None is a
capture of a real patient's data, and none may become one: real records never
enter this repository, its issues or its pull requests.

| Path | What it is | Read by |
|---|---|---|
| `directory/bundle.json` | The structure of athenahealth's FHIR base URL Bundle (`https://service-base-urls.api.fhir.athena.io/athena-fhir-service-base-urls.json`, 2026-11-12): a `collection` Bundle of `Organization`s carrying `ah-practice` and `ah-brand` extensions, `address` and an NPI `identifier`, each pointing at a global and a brand `Endpoint`. Three invented practices (900001 to 900003) in `Springfield, ZZ 00000`, NPIs `000000000<n>`. | `src/directory.rs` tests |
| `mock/patient.json` | The mock practice's one patient, `a-900001.E-1001`, `Testpatient, Sample`, born 2025-01-01. | `tests/support/mock.rs` |
| `mock/search-*.json` | One searchset per exported type, in athenahealth's shapes: `Observation` pages through a `cursor` next link and carries a weight written `3.50` (the stream must keep the server's text); `DiagnosticReport` has a PNG `presentedForm` and a `media` link; `DocumentReference` has a PDF, an HTML body labelled as PDF, and an attachment on another host. `search-Condition-malformed.json` (mode `malformed`) has an entry with no `resourceType` before a good one. | `tests/support/mock.rs` |
| `mock/binary-*.json` | `Binary` resources with base64 `data`: two PDFs (one is HTML claiming to be a PDF) and two PNGs, each under 100 bytes of invented content. | `tests/support/mock.rs` |
| `mock/practitioner.json`, `organization.json`, `location.json`, `media.json` | The resources the exported ones refer to. | `tests/support/mock.rs` |
| `mock/outcome-*.json` | `OperationOutcome`s for a refused scope, an unsupported search and an expired token. | `tests/support/mock.rs` |

`{{BASE}}` in a fixture is replaced with the mock's FHIR base when served.

## Rules

- Patients' family names start with `Test`; the only patient id is
  `a-900001.E-1001`; birth dates are `2025-01-01`; no telephone, email,
  address or photo on a person.
- Practice ids are 900001 to 900003, or athenahealth's own published sandbox
  ids (80000, 195900) where athenahealth publishes them. Hosts are
  athenahealth's public API hosts (in the directory's `Endpoint`s), the
  mock's `{{BASE}}` on 127.0.0.1, or the reserved `.example` domain.
- `tests/no_personal_data.rs` checks these rules positively over the mock
  fixtures and scans every tracked file for personal-data shapes and
  practice ids outside that list.
