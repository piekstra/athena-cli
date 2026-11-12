# Security

Report a vulnerability privately through GitHub's "Report a vulnerability"
on this repository. Please do not open a public issue.

## What athena protects

- **Tokens** live only in the OS keychain, one item per patient (service
  `piekstra.athena`). They are never printed, logged, written to a file, or
  passed in argv. `athena auth logout` revokes them at athenahealth and
  deletes the item.
- **No client secret exists**: athena is a public client, and each sign-in is
  bound to its PKCE verifier (S256), so a stolen authorization code is
  useless.
- **The sign-in redirect** goes to `127.0.0.1` only, and its `state`, the
  issuer it names and the id token's `nonce` are checked.
- **Tokens go only to the practice's own FHIR server**: paths, next links and
  attachment URLs on another origin are refused or skipped, and redirects are
  not followed with a token.
- **Renewals** are serialized across processes by a refresh lock, so two
  processes never present one refresh token at once.
- **Records** go to stdout (`--ndjson`) or, for athenahealth's sandbox and
  local test servers only, to a `0600` file in a `0700` directory. Saved
  documents are `0600`; config and the session index are `0600`.

`athena` is read-only: it makes no request that changes a record.
