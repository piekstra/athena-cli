# AGENTS.md — athena-cli

`athena` reads a household member's own records from medical practices on
athenahealth's athenaOne, through athenahealth's patient-access SMART on FHIR
API (its Certified APIs). It conforms to piekstra-cli/1 and the
`health-records/v1` and `documents/v1` profiles, on the `pk-cli-*` crates
from [cli-common](https://github.com/piekstra/cli-common).

## Layout

| File | Owns |
|---|---|
| `src/cli.rs` | the clap tree, the `Ctx`, every command's handler, exit codes, `info` |
| `src/config.rs` | `config.json`: client ids per environment, redirect ports, practice profiles and their FHIR base |
| `src/env.rs` | athenahealth's Preview and Production hosts, and custom servers |
| `src/directory.rs` | athenahealth's FHIR base URL Bundle: download, the cut-down local copy, search |
| `src/smart.rs` | athenahealth's `VendorQuirks` (none beyond the defaults), the scopes, granted types, `self` or `proxy` |
| `src/oauth.rs` | token revocation for `auth logout` |
| `src/login.rs` | one sign-in through `pk_med_smart` (discover, begin, exchange), and the "Log in with athenahealth" start page on a loopback port of its own |
| `src/session.rs` | the Keychain store of `SmartSession`s (account `smart/<profile>/<patient>`), the 90-day horizon, and the session index (`sessions.json`) |
| `src/fhir.rs` | the read client: `pk_med_fhir::FhirClient` with athenahealth's `RetryPolicy`, the `Live` bearer source renewing through `pk_med_smart::Renewer`, and the circuit breaker |
| `src/export.rs` | the export plan: searches, referenced reads, `Binary` after its parent, skips |
| `src/stream.rs` | `pk-med-records`' `records-stream/v1` writer and DTOs, re-exported, and athena's header |
| `src/documents.rs` | `documents/v1` over DocumentReference and DiagnosticReport, `Binary` fetch and file-type check |
| `src/http.rs` | the request trait (revocation, the directory), origins |
| `tests/support/mock.rs` | a mock athenahealth practice on 127.0.0.1 (also `make mock`) |
| `docs/api.md` | athenahealth's behaviour and traps, quoted; read before changing sign-in or export |

medical-common is pinned at v0.4.1, on the same cli-common tag (v0.31.1).
From `pk-med-smart`: discovery, the scope set, the launch (`begin`, with the
OpenID nonce) and the code exchange, `SmartSession` and its Keychain store,
and `Renewer`, which renews under the refresh lock and stamps a refused
grant as `refused_at`. From `pk-med-fhir`: `FhirClient` (retries, the bearer
source, same-origin paging and `Binary`, statuses to errors), `RawResource`
and `outcome::status_error`. From `pk-med-records`: the stream writer, its
header, skip and trailer, the `Organization` and `PatientContext` DTOs,
`records-export/v1` and the export file (`ExportFile`, committed after the
trailer). Tests read athena's stream back with `pk-med-records`'
`RecordsReader`, as medrec does.

athena's own code is what is athenahealth's: the retry policy's values, the
circuit breaker (counted from `FhirClient`'s results in `fhir::Client`), the
start page with athenahealth's button (cli-common's redirect listener answers
only `/callback`), revocation (`pk_cli_auth::oauth` has none), and the
90-day refresh horizon.

## Medical data

Medical records are the most sensitive data a household has.

- The repository carries no personal data: invented fixtures only
  (`tests/fixtures/README.md`), checked by `tests/no_personal_data.rs`. A
  practice's name, place and ids are household information too: they live in
  the owner's local config, never here, in an issue or in a pull request.
- Develop and dogfood against the mock or athenahealth's Preview sandbox
  (synthetic patients). A check against real data reports counts, statuses
  and exit codes only, or is left to the owner in their own terminal. An
  agent never reads, prints or summarizes a real record, document or patient
  name.
- `records export -o <DIR>` writes `<DIR>/records.ndjson` and refuses any server but
  athenahealth's sandbox and 127.0.0.1 (`cli::synthetic`); real records go to
  medrec through `--ndjson`.
- No MCP surface: athena is not registered in cli-mcp and ships no `mcp`
  command, because a tool call would hand records to the model making it
  (the effort's plan, §8, until the owner decides otherwise).
- athena reads the API only. athenahealth's developer terms forbid screen
  scraping athenaOne, so there is no portal automation.

## Credentials

- One Keychain item per (practice profile, patient): service
  `piekstra.athena`, account `smart/<profile>/<patient>`, a
  `pk_med_smart::SmartSession` (the tokens, the granted scope, the endpoints
  they belong to, `refused_at`, and athenahealth's revocation endpoint in
  `extra`). Never printed, logged, or put in argv.
- The client id is configuration (`config set client-id`), never code: each
  household registers its own app (`docs/registration.md`).
- Renewals run under `pk_cli_auth::refresh_lock::RefreshLock`, so two
  processes never present one refresh token at once.
- Tests and `make verify` never read the real Keychain: the in-process tests
  use `session::MemoryStore` (shareable with the bearer source, unlike
  `pk_med_smart::MemoryStore`), and the surface tests and `smoke` set
  `ATHENA_KEYCHAIN_SERVICE` to an empty service and reach no command that
  reads it.
- If an `athena` call hangs, it waits on a Keychain approval. Stop calling it
  and tell the owner; a retry only raises another dialog.

## Conventions

- `--json` on every command, one schema-tagged document on stdout. `records
  export --ndjson` writes the stream instead: a failure before the header
  writes nothing to stdout, and one after it ends the stream with an
  incomplete trailer and the exit code.
- Arguments are checked before the Keychain or the network.
- Read-only: `api` takes GET and nothing else.
- A token goes only to the FHIR server's own origin: absolute paths, next
  links and attachment URLs on another origin are refused or skipped.
- Every binary-producing `make` target signs with the stable
  `pk-cli-codesign` identity.

## Tests

`make verify` (fmt, clippy, tests, smoke), offline:

- `tests/mock_flow.rs`: sign-in as a caregiver, export, renewal, revoked and
  cancelled sign-ins, outages, documents, against the mock in-process.
- `tests/cli_surface.rs`: the binary's help, exit codes, JSON errors, `info`,
  completions, config, and the checks before the Keychain.
- `tests/no_personal_data.rs`: every tracked file, and the fixtures' identities.

`make mock` runs the mock as a server for dogfooding; `examples/mock_server.rs`
prints how to point a practice profile at it and switch its error modes.

## Definition of done

`make verify` and CI green, the installed binary dogfooded against the mock
and athenahealth's sandbox (orgs, login, patients, export into a synthetic
medrec folder, documents, `api`, the error paths), `docs/api.md` matching what
athenahealth does, and no personal data anywhere in the diff.
