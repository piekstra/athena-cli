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
| `src/smart.rs` | `.well-known/smart-configuration` discovery, scopes, granted types, `self` or `proxy` |
| `src/oauth.rs` | PKCE, the authorize URL, the loopback listener, code exchange, refresh, revoke |
| `src/login.rs` | one sign-in from start page to token set, and the "Log in with athenahealth" start page |
| `src/session.rs` | the token set, one Keychain item per (practice profile, patient) behind `TokenStore`, and the session index (`sessions.json`) |
| `src/fhir.rs` | the read client: renewal under the refresh lock, retries, same-origin paging, status to error |
| `src/export.rs` | the export plan: searches, referenced reads, `Binary` after its parent, skips |
| `src/stream.rs` | the `records-stream/v1` writer |
| `src/documents.rs` | `documents/v1` over DocumentReference and DiagnosticReport, `Binary` fetch and file-type check |
| `src/http.rs` | the transport trait, origins |
| `tests/support/mock.rs` | a mock athenahealth practice on 127.0.0.1 (also `make mock`) |
| `docs/api.md` | athenahealth's behaviour and traps, quoted; read before changing sign-in or export |

`src/smart.rs`, `src/fhir.rs` and `src/stream.rs` stand in for
medical-common's `pk-med-smart`, `pk-med-fhir` and `pk-med-records`; each
goes when its crate is tagged and pinned, with no change to the stream.

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
- `records export -o <DIR>` writes a plain file and refuses any server but
  athenahealth's sandbox and 127.0.0.1 (`cli::synthetic`); real records go to
  medrec through `--ndjson`.
- No MCP surface: athena is not registered in cli-mcp and ships no `mcp`
  command, because a tool call would hand records to the model making it
  (the effort's plan, §8, until the owner decides otherwise).
- athena reads the API only. athenahealth's developer terms forbid screen
  scraping athenaOne, so there is no portal automation.

## Credentials

- One Keychain item per (practice profile, patient): service
  `piekstra.athena`, account `<profile>/<patient>`, JSON holding the tokens,
  the granted scope and the endpoints they belong to. Never printed, logged,
  or put in argv.
- The client id is configuration (`config set client-id`), never code: each
  household registers its own app (`docs/registration.md`).
- Renewals run under `pk_cli_auth::refresh_lock::RefreshLock`, so two
  processes never present one refresh token at once.
- Tests and `make verify` never read the real Keychain: the in-process tests
  use `MemoryStore`, and the surface tests and `smoke` set
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
