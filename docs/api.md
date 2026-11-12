# athenahealth's patient-access API, as athena uses it

What athena relies on, in athenahealth's own words where it has them, and the
traps found on the way. Quotations are from athenahealth's developer
documentation at <https://docs.athenahealth.com/api/>, read on 2026-11-12;
the page each comes from is named beside it. Everything marked **unverified**
waits on a sign-in against athenahealth's Preview sandbox.

## Route: Certified APIs, as a PHR app

athenahealth publishes two families of API: its proprietary athenaOne APIs
(contract required) and its **Certified APIs**, the ONC (g)(10) patient-access
API that the 21st Century Cures Act requires. athena uses only the second.

- "athenahealth offers access to our Certified APIs free of charge to the
  healthcare developer community." ([23.3 release note][r233])
- A patient-facing app that reads its user's own records is a **PHR app**:
  "If you are developing a PHR app that exclusively uses Certified APIs ...
  please follow the self-service onboarding process ... You must use
  3-legged OAuth. Upon app creation, your application will automatically be
  enabled to access all athenahealth tablespaces. Your app will not be able to
  retrieve a patient's data, however, until a patient consents to the app's
  access request." ([Certified APIs][certified])
- A practice can switch it off: "Individual athenaOne customers will also be
  able to disable your app from accessing their patients' data via the Manage
  PHR Access admin page." ([Certified APIs][certified])
- The app is listed under a name that follows athenahealth's
  [App Naming Guidelines][naming]: it must "Include your company name/brand"
  and cannot contain "athenahealth branded words such as "athena",
  "athenahealth"", environment words ("prod", "preview", "dev"), "Usernames,
  email addresses, website URLs, names of people/teams", "app",
  "application", "The words "CAPI" or "PHR"", or, for Certified-API-only
  apps, "Test", "Temp" and the like.

**Portal automation is not a route.** The [Developer Portal Terms and
Conditions][terms] forbid it outright: you may not "apply systems to extract
or modify information from the API or athenaOne using technology or methods
such as those commonly referred to as "web scraping," "data scraping," or
"screen scraping"". athena reads the API only.

### The terms a registration agrees to

[Developer Portal Terms and Conditions][terms], the points that bind a
household tool:

| Section | athenahealth's wording, shortened |
|---|---|
| License | "a limited, non-exclusive, revocable, non-transferable, and non-sublicensable right to access and use the Developer Portal, API and ... Materials" |
| Restrictions | no "reverse engineer, reverse compile, disassemble the API or Materials"; no scraping (above); no redistributing "access to the API"; no use "for purposes of monitoring the availability, performance, or functionality of our services or for any other benchmarking purposes" |
| Keys | "You will be issued one or more unique passwords, security codes, or tokens (each a "Key")"; Keys are not shared, and "You may not transfer, assign, or delegate these terms or your Keys to any third party" |
| Fees | only "In the event that you have an agreement with Athena"; Certified APIs are free (above) |
| Termination | "Athena may change, suspend, or discontinue the API and suspend or terminate your use ... at any time for any reason, with or without notice" |
| Indemnity | the developer indemnifies athenahealth for use "in violation of these Terms" |
| Liability | "Under no circumstances shall Athena be liable to you for any direct damages in excess of $100" |
| Law | "the laws of the Commonwealth of Massachusetts" |

So athena keeps the client id in local configuration, never in the
repository: each household registers its own app (`docs/registration.md`).

## Environments

| | Preview (sandbox) | Production |
|---|---|---|
| API host | `https://api.preview.platform.athenahealth.com` | `https://api.platform.athenahealth.com` |
| OAuth | `<host>/oauth2/v1/{authorize,token,revoke,introspect,keys,logout}` | same |
| FHIR R4, athenahealth-wide | `<host>/fhir/r4` | same |
| FHIR R4, one practice | `<host>/{practiceid}/brand/{brandid}/csg/{chartsharinggroupid}/fhir/r4` | same |
| Okta issuer (SMART configuration) | `https://athena.okta.com/oauth2/aus2hfei6ookPyyCA297` | `https://athena.okta.com/oauth2/aus2hff5eqFb7Wqfh297` |

A client id is issued per environment: the Developer Console makes Preview and
Production credentials separately ([Onboarding Overview][onboarding]).

"These site-specific URLs require the appropriate practice ID(s), brand ID(s),
and chart sharing group ID(s) for that organization." ([FHIR Base URLs][base])

## Sign-in: SMART standalone patient launch

### Public client and PKCE

athena is a native app with no secret. "PKCE is required by the token API for
native or single-page browser apps that cannot securely store a client
secret." ([Token Endpoint][token]) The SMART configuration lists
`client-public`, `context-standalone-patient`, `permission-offline`,
`permission-v1`, `permission-v2`, `token_endpoint_auth_methods_supported`
including `none`, and `code_challenge_methods_supported: ["S256"]`.

### Redirect URI: exact match, so fixed loopback ports

"The redirect URI must exactly match a post-login redirect URI configured for
your app's OAuth client credentials during registration." ([Authorize
Endpoint][authorize]) Okta compares the whole URI, port included, so athena
does not use an ephemeral port: it listens on 127.0.0.1 at
`http://127.0.0.1:47816/callback`, or `:47817` when that is taken, and the
registration lists both. `athena config set redirect-ports` changes them,
and the registration must change with them.

### `aud` chooses the practice, or none

"The value is the FHIR base URL, used to specify the organization for which
the end user will be authenticated. The FHIR base URL may specify practice
ID, department ID, brand ID, chart sharing group ID, or none of the above to
indicate a global login." ([Authorize Endpoint][authorize])

For the athenahealth-wide base: "If cross-context authentication is used with
SMART on FHIR, in which patients must select a single patient record to grant
access, patients will encounter an updated prompt that indicates the
athenahealth Patient Portal brand associated with each of their records."
([22.7 release note][r227])

A practice profile with practice, brand and chart sharing group ids signs in
against that practice's base; one without them (the built-in `sandbox`) signs
in athenahealth-wide.

### One patient record per sign-in

"patients must select a single patient record to grant access" (above). A
caregiver who sees several children in the portal signs in once per child:
each sign-in yields one token set for one `Patient`, kept as its own keychain
item. The token answer names the patient (`"patient": "a-195900.E-60178"` in
athenahealth's shape: `a-<practiceid>.E-<chart id>`).

Whether the sign-in was the patient's own or a caregiver's is read from the id
token's `fhirUser`: the patient's own `Patient/<id>` is `self`, anything else
(a `RelatedPerson`) is `proxy`. **Unverified**: athenahealth's `fhirUser` for
a caregiver's sign-in.

### Scopes

- "athenahealth automatically approves all 3-legged OAuth apps for the
  following scopes ...: openid, fhirUser, offline_access" ([Authorization
  Overview][authz]), and, for "patient-facing apps using 3-legged OAuth ... for
  use with the standalone SMART App Launch sequence", `launch/patient` and
  `patient/<Type>.read` for each listed type.
- "By default, athenahealth does not permit apps to request wildcard scopes
  ... nor does athenahealth permit write scopes" ([Authorization
  Overview][authz]). athena names every type: `src/smart.rs`, `PATIENT_TYPES`.
- "To obtain a refresh token in the token endpoint response, you must request
  the offline access scope." ([Authorize Endpoint][authorize])
- `nonce` is "Required if requesting the openid scope" ([Authorize
  Endpoint][authorize]); athena checks it against the id token.

athena asks for the R4 types it reads. The auto-approved list also names
DSTU2-era and proprietary types (`Assessment`, `ClinicalImpression`,
`MedicalAdministration`, `MedicationOrder`, `MedicationStatement`,
`PracticeConfiguration`, `Provider`) that the R4 CapabilityStatement does not
serve, and `Appointment`, whose R4 search takes no `patient` parameter.

### The "Log in with athenahealth" button

athenahealth asks patient-facing apps to start sign-in from its "Log in with
athenahealth" button (CSS and logo from
`identity-static-assets.platform.athenahealth.com/login-with-athenahealth/latest/`).
Its sample script builds a production-only authorize URL with neither `aud`
nor PKCE, so athena does not use the script: it serves its own start page on
the loopback listener with the button's markup and classes, linking to the
full authorize URL.

## Tokens

From the [Token Endpoint][token] page:

- "expires_in - represents the lifetime of the access token in seconds
  (default is 60 minutes ...)"
- "refresh_token – JWT used to obtain a new access token without requiring
  re-authentication by an end user (3-legged OAuth only; default expiration
  is 90 days from the most recent token request that used or generated that
  refresh token)"
- `scope` on a refresh: "Required if grant_type is ... refresh_token (3-legged
  OAuth only) ... If grant_type is refresh_token, the requested scopes must be
  a subset of those provided to the authorize endpoint when the refresh token
  was originally generated." athena sends the whole granted set.
- `redirect_uri` on the code exchange "must match the value for redirect_uri
  provided to the authorize endpoint".

athena keeps a refresh token until a token answer carries a new one, records
when it was last used, and reports the 90-day horizon as `signin_expires_at`.
Every renewal runs under the family's refresh lock
(`pk_cli_auth::refresh_lock`), so two processes never present one refresh
token at once. **Unverified**: whether a refresh answer carries a new refresh
token.

Revocation is `POST /oauth2/v1/revoke` (RFC 7009); `auth logout` revokes the
refresh and access tokens, then deletes the keychain item. The logout
endpoint "Terminates an end user's ... login session in the athenahealth login
widget, which otherwise expires after 10 minutes of idle time ... terminating
a login session will not invalidate any active access or refresh tokens"
([Additional OAuth Endpoints][oauth-extra]); athena has no use for it.

## FHIR R4

The CapabilityStatement (`/fhir/r4/metadata`) is FHIR 4.0.1, instantiating US
Core 3.1.1 and 6.1.0 and Bulk Data. Searches page with an opaque `cursor`
parameter in `Bundle.link[next]`.

athena exports, by `patient=<id>` search (all take `patient`, `_lastUpdated`
for `--since`): AllergyIntolerance, Condition, MedicationRequest,
MedicationDispense, Immunization, Encounter, Procedure, Observation,
DiagnosticReport, DocumentReference, ServiceRequest, Specimen, CarePlan,
CareTeam, Goal, Device, Coverage, RelatedPerson; then `Patient/<id>` by read,
and Practitioner, Organization, Location, Medication and Media by read when an
exported resource refers to them.

### Documents and Binary

- `Binary` is read-only (`GET Binary/<id>`), answering FHIR JSON with base64
  `data` and `contentType`. From [Lab & Imaging Documentation
  Retrieval][labimg]: "A JSON array with the Binary will be provided if there
  is an image associated with the document" (`"presentedForm": [{"url":
  "Binary/{logicalID}", "contentType": "image/png"}]`), and "The response will
  display the base64 encoded "data"."
- DocumentReference attachments point at `Binary/<id>` the same way.
- What a patient token sees is what the portal shows: "When called using
  patient 3-legged OAuth ... the response includes only documents and results
  published to the Patient Portal (those without the NOPAT tag)." ([Patient
  Portal Access to Documents/Sensitive Result Filtering][nopat]) A practice
  setting ("Publish clinical notes to patient portal", "Autopublishing of lab
  and imaging results") widens that; the patient cannot.

athena fetches only `Binary` on the signed-in FHIR server's own origin; an
attachment elsewhere is a skip (`unsupported`), never a request with the token.

### Imaging

- The R4 CapabilityStatement has **no `ImagingStudy`**.
- `Media` is served by read only, with no search, so athena reaches it through
  a `DiagnosticReport.media` link.
- What a patient token can download is the imaging *document*: a
  `DiagnosticReport` with a `presentedForm` `Binary` (an image of the report,
  such as `image/png`, or a PDF). No DICOM and no DICOMweb are offered to a
  patient. Studies themselves come from the imaging facility.

## The directory of practices

"Click here to download a FHIR Resource Bundle containing the global FHIR R4
base URL as well as all site-specific FHIR R4 base URLs for all of
athenahealth's live customers." ([FHIR Base URLs][base])

- `https://service-base-urls.api.fhir.athena.io/athena-fhir-service-base-urls.json`:
  a `collection` Bundle of about 135 MB (2026-11-12: 127,576 `Organization`
  and 23,434 `Endpoint` entries). Each `Organization` carries its name,
  address and NPI, the extensions
  `https://fhir.athena.io/StructureDefinition/ah-practice`
  (`Organization/a-1.Practice-<practiceid>`) and `.../ah-brand`
  (`Organization/a-<practiceid>.Brand-<brandid>`), and references to two
  `Endpoint`s: the global base and its brand base (which carries the chart
  sharing group).
- The CSV files beside it "are updated daily".

`athena orgs refresh` downloads the Bundle once and keeps only name, city,
state, ZIP and the three ids; `orgs search` reads that copy.

## Retries

From [Timeouts, Retries, and Backoff][retries]: "Do implement Retry for status
codes 502, 503 and 504", "Do use an exponential backoff strategy", "Do
consider use of jitter", and "Don't implement Retry for status code 429
without ensuring the failed request is related to excessive concurrent
requests and not the exceeding of a daily limit."

athena sends one request at a time, retries 502 to 504 up to three times
(1 s, 2 s, 4 s plus jitter, or the server's `Retry-After`), and retries a 429
only when it carries a `Retry-After` of 30 s or less. A search that still
fails is an `upstream` skip, but when three requests in a row fail that way
the export stops with `complete: false` and exit 5 (the circuit breaker), and
a failed `Patient` read stops it at once: exit 5, or exit 3 when the read is
refused (403), with the remedy to sign in again, since the practice may have
turned off access for the app.

An answer that is not a 2xx maps to an exit code by medical-common's
`pk_med_fhir::outcome::status_error`. The `OperationOutcome`'s issue code is
used when the contract knows it: `login`, `unknown` or `expired` is exit 3
(sign in again), `forbidden`, `suppressed` or `security` exit 3 (refused),
`not-found` or `deleted` exit 4. Otherwise the HTTP status decides: 401 and
403 exit 3, 404 and 410 exit 4, any other 4xx exit 5 (an `unsupported`
skip), and 5xx exit 5. A 429, a 5xx, or a 403 whose body is an HTML page
(athenahealth's edge rather than the FHIR server) is exit 5 with no reason,
so it counts toward the circuit breaker instead of reading as a refusal.

## The sandbox

From the [Onboarding Overview][onboarding]: "We have also configured a dummy
patient record and patient login credentials for PHR testing in Preview:
Practice ID: #80000 Patient ID: #14545 Email / Password (for Login with
athenahealth)": `phrtest_preview@mailinator.com` and the password on that
page. Preview practice 195900 also holds synthetic test patients
(`a-195900.E-60178` to `a-195900.E-60184`, family name `Sandboxtest`;
[Testing in the Sandbox][sandbox]). A sign-in to the sandbox needs a Preview
client id.

## Practice migrations

A practice that moves to a new athenaOne practice id gets a new FHIR base and
a new patient portal host, and its patients' portal accounts are registered
again on the new portal. For athena that is a new practice profile and a new
sign-in per patient. Records from before the move stay on the old practice,
so the old profile is exported first, and kept while the old portal is.

## Traps

| Trap | What athena does |
|---|---|
| The SMART configuration's `grant_types_supported` lists `authorization_code` and `client_credentials` only, though refresh works | Relies on the token documentation, not that list |
| `issuer` is an Okta URL, not the FHIR host | Compares an RFC 9207 `iss` on the callback with the discovered issuer only |
| `expires_in` is a number in one documented example and a string (`"300"`) in another | Reads both |
| A refresh without `scope` | Always sends the granted scope |
| The redirect URI is matched exactly, port included | Fixed registered ports, never an ephemeral one |
| The button's script builds a production authorize URL without `aud` or PKCE | Own start page with the button's markup |
| A patient token sees only what the portal publishes (`NOPAT`) | Documents it; nothing to work around |
| One sign-in grants one patient record | One token set per (practice profile, patient) |
| `Appointment` search takes no `patient` parameter | Not exported |
| `Media` has no search | Read through `DiagnosticReport.media` |
| A 429 can mean the daily limit, where a retry only adds load | Retried only with a short `Retry-After` |

[r233]: https://docs.athenahealth.com/api/resources/233-release-developer-console-allows-self-service-onboarding-all-apps-using-only
[r227]: https://docs.athenahealth.com/api/resources/227-release-updated-enable-authentication-against-multiple-athenaone-practices
[certified]: https://docs.athenahealth.com/api/guides/certified-apis
[naming]: https://docs.athenahealth.com/api/guides/app-naming-guidelines
[terms]: https://docs.athenahealth.com/api/guides/termsofservice
[onboarding]: https://docs.athenahealth.com/api/guides/onboarding-overview
[base]: https://docs.athenahealth.com/api/guides/base-fhir-urls
[token]: https://docs.athenahealth.com/api/guides/token-endpoint
[authorize]: https://docs.athenahealth.com/api/guides/authorize-endpoint
[authz]: https://docs.athenahealth.com/api/guides/authorization-overview
[oauth-extra]: https://docs.athenahealth.com/api/guides/additional-oauth-endpoints
[labimg]: https://docs.athenahealth.com/api/workflows/fhir-r4-lab-and-imaging-documentation-retrieval
[nopat]: https://docs.athenahealth.com/api/workflows/fhir-r4-api-patient-portal-access-to-documents-sensitive-result-filtering
[retries]: https://docs.athenahealth.com/api/guides/timeouts-retries-and-backoff
[sandbox]: https://docs.athenahealth.com/api/guides/testing-sandbox
