# Contributing

1. `make verify` must pass: formatting, clippy with warnings denied, the
   offline tests and the smoke run.
2. Test data is invented (`tests/fixtures/README.md`). Never commit a
   capture of a real record, token, or response from a real practice, nor a
   real practice's name or ids.
3. Change `docs/api.md` with any change to how athena talks to athenahealth.
4. Keep `records-stream/v1` exactly as medical-common defines it; medrec
   reads it.

Pull requests are reviewed before merge; `main` is protected.
