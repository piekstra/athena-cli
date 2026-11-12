# athena

Pull your own health records, and your children's through caregiver access,
from medical practices that run athenahealth's athenaOne, through
athenahealth's patient-access SMART on FHIR API.

Unofficial; not affiliated with or endorsed by athenahealth, Inc.
athenahealth and athenaOne are athenahealth's trademarks.

```sh
athena orgs refresh                                    # athenahealth's directory of practices, once
athena orgs search "<practice name>" "<city>"
athena config set practice clinic --env production --practice-id <P> --brand-id <B> --csg-id <C>
athena auth login --org clinic --label kid1            # sign in in the browser, one child at a time
athena patients list
athena records export --patient kid1 --ndjson | medrec import --from athena
athena documents list --patient kid1
athena documents download DocumentReference/<id> -o note.pdf --patient kid1
athena api GET Patient/<id> --patient kid1
```

`athena` only reads. Records go where you send them; nothing is sent
anywhere else.

## Before the first sign-in

Each household registers its own free patient app with athenahealth and gives
`athena` the two client ids: [docs/registration.md](docs/registration.md).

```sh
athena config set client-id <PREVIEW_CLIENT_ID> --env preview
athena config set client-id <PRODUCTION_CLIENT_ID> --env production
```

## Install

```sh
curl -sSL https://github.com/piekstra/athena-cli/releases/latest/download/athena-aarch64-apple-darwin.tar.gz | tar xz
mv athena ~/.local/bin/        # or anywhere on PATH
athena self-update             # later releases
```

Release assets: `athena-<target>.tar.gz` and `.sha256` for
`aarch64-apple-darwin`, `x86_64-apple-darwin` and
`x86_64-unknown-linux-gnu`. From source: `make install`.

## Commands

| Command | What it does |
|---|---|
| `orgs refresh\|list\|search` | Practice profiles (`org-list/v1`), and athenahealth's directory of practices, downloaded on `refresh` (about 135 MB) and kept as names, places and ids. A search match's `id` is the directory's `<practice>-<brand>-<csg>` key; `--org` takes a profile's slug |
| `config set\|unset practice <slug>` | A practice profile: environment, practice, brand and chart sharing group ids, or a FHIR base in full |
| `auth login --org <ORG> [--label <WHO>]` | Standalone patient launch in the browser (PKCE, loopback); one sign-in per patient record |
| `auth status` / `auth logout` | Each sign-in's state (`auth-status/v1`); remove one or all |
| `patients list [--org <ORG>]` | The patients signed in, each with `self` or `proxy` (`patient-list/v1`) |
| `records export --patient <ID> [--since D] --ndjson` | Every resource the practice serves to the patient, files included, as `records-stream/v1` |
| `documents list\|download` | Visit notes, reports and results' forms (`documents/v1`) |
| `api GET <path>` | One FHIR read as the signed-in patient |
| `config path\|show\|set\|unset` | Client ids, redirect ports, practice profiles |
| `info`, `completions`, `self-update` | Family standard |

Every command takes `--json`. Exit codes: 0 ok, 2 usage, 3 sign-in needed
or refused, 4 not found, 5 the practice or network failed.

`records export -o <DIR>` writes `<DIR>/records.ndjson` instead and prints
`records-export/v1`, for athenahealth's sandbox and local test servers only.
The file is owner-only and replaced on each run, a failed run included: a
pull cut short leaves its partial stream there, marked `complete: false`,
and exits with its error's code. Up to v0.1.0, `-o` wrote a new
`<profile>_<patient>_<time>.ndjson` on each run.

## How sign-in works

1. `athena` reads athenahealth's sign-in endpoints and opens a page on
   `127.0.0.1` with a "Log in with athenahealth" button.
2. You sign in with your patient portal account. A caregiver picks one child's
   record there; each child is one sign-in (`--label` names it).
3. athenahealth redirects to `http://127.0.0.1:47816/callback` (or `:47817`),
   where `athena` listens, and `athena` exchanges the code with PKCE.
4. Access tokens last an hour and renew themselves; a sign-in lasts 90 days
   from its last use. `auth status` shows when each one ends.

Tokens are one macOS Keychain item per patient (`piekstra.athena`, account
`<practice profile>/<patient>`). Nothing secret is written anywhere else.

## What a patient token sees

What the practice has published to its patient portal: athenahealth filters
out unpublished notes and results for patient sign-ins. There is no imaging
study download; imaging reports come as documents. Details, with
athenahealth's wording: [docs/api.md](docs/api.md).

## Docs

- [docs/registration.md](docs/registration.md): registering a household's app
- [docs/api.md](docs/api.md): athenahealth's behaviour and traps, with its wording
- [AGENTS.md](AGENTS.md): working on the code

Licensed under MIT or Apache-2.0.
