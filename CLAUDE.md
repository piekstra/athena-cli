# CLAUDE.md

See **[AGENTS.md](AGENTS.md)**, the canonical guide for this repo. Claude-specific notes:

- Never read, print or summarize a real record, document or patient name.
  Use the mock (`make mock`) or athenahealth's sandbox; against real data,
  report counts, statuses and exit codes only.
- A sign-in and the app registration are the owner's to do. Record each as a
  `twapp action` with the exact command; do not drive the patient portal.
- If an `athena` call hangs, it is waiting on a Keychain approval. Stop
  calling it; a retry only raises another dialog.
- Read `docs/api.md` before changing sign-in or export, and update it in the
  same change.
