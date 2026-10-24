# AI prompts and review log

This log is intentionally honest. The implementation work began before this Git repository was initialized on 2026-10-24. Earlier changes therefore do not have individual commit links; those links cannot be reconstructed or invented. The repository history starts with `6ef25b1` on 2026-10-24. Later changes should be committed as they happen and linked to their real commit.

## Reused context

- User-provided Snovasys Fresher Hiring Challenge 2026 brief (TrustVault requirements, attack standard, submission checklist).
- Working instruction: choose a stack suitable for a clean local run; enforce authorization at the server for every operation; include tests that exercise direct endpoint access.

## Entries

### 2026-10-20 — Initial implementation (security and authorization)

- **Prompt:** Build the TrustVault challenge project in the empty workspace, implementing named per-document read/edit grants, immediate revocation, private uploads/downloads, role separation, append-only audit evidence, UI, tests, and submission documentation.
- **Produced:** Flask/SQLite application skeleton with server-side authorization, HMAC-linked append-only audit records, tests, and documentation.
- **What was wrong / checked:** Generated code is not evidence of correctness by itself. The first implementation still needs to be run and tests reviewed; local HMAC plus SQLite triggers do not stop host root from replacing the application and key. UI visibility must not be mistaken for security.
- **What I did instead:** Added endpoint-level authorization tests for outsider access, read-only access, revocation, admin access boundaries, and invalid uploads; documented the local audit trust boundary. These changes predate the repository's first commit, so there is no individual commit link for them.

### 2026-10-20 — Email notification when granting access

- **Prompt:** Add email notifications when an owner grants a specific existing TrustVault user read/edit permission. Keep the grant tied to the account, not the recipient's email link.
- **Produced:** SMTP notification code, account email fields, a grant-form checkbox, and a status result for send/failure.
- **What was wrong / checked:** A naive notification could accidentally become a bearer link or imply mail delivery equals authorization; SMTP may also fail after the permission is stored. Seeded `.test` addresses are not deliverable.
- **What I did instead:** Kept the email free of attachments and document download URLs, required a normal authenticated session/current grant for access, made delivery opt-in in API calls (and an explicit checkbox in the UI), and reported/logged SMTP failure without silently undoing or misreporting the access grant. Added mocked SMTP, mail-failure, and permission tests. These changes predate the repository's first commit and are included in its initial snapshot, not an individual change commit.

### 2026-10-21 — Adapting TruthShield concepts to private documents

- **Prompt:** Review the linked TruthShield project and add only the useful concepts to TrustVault.
- **Produced:** A deterministic, explainable document privacy-risk review with a risk score and downloadable PDF report.
- **What was wrong / checked:** A general answer fact-checker would be a poor fit for confidential document storage, and sending file text to a third-party AI would create a new disclosure path. Initial PDF generation testing also caught that a `BytesIO` stream was mistakenly converted to a path, yielding an empty PDF.
- **What I did instead:** Kept processing local, restricted reviews to current document readers, redacted detected values, scoped reports to the reviewer, audited review/report events, fixed stream output, and tested the generated PDF by parsing its pages. These changes predate the repository's first commit and are included in its initial snapshot, not an individual change commit.

### 2026-10-21 — Verifying the email-sharing request

- **Prompt:** “if we want to edit /read the files i want to add a features in this to send the email to particular person so add that features.”
- **Produced:** Checked the existing named-user grant UI, email-notification implementation, and automated tests; confirmed that grant notification behavior was already present.
- **What was wrong / checked:** The code's seeded `.test` recipient addresses are intentionally undeliverable and SMTP was not configured, so “feature exists” did not mean an actual email would arrive. Mocked SMTP tests only verify application behavior, not delivery through a mail provider.
- **What I did instead:** Explained that real SMTP settings and a real recipient address are required, documented them in README, and made no claim of a successful live email. No code fix or commit resulted from this verification; the repository was initialized later.

### 2026-10-23 — Diagnosing why the documented URL did not work

- **Prompt:** “why it was not working, check through it and complete the assignment”
- **Produced:** Initial inspection showed the application tests pass and source is present, but `http://127.0.0.1:5000/` returned HTTP 403 with an `AirTunes` server header.
- **What was wrong:** Port 5000 was owned by macOS ControlCenter/AirPlay; the request was reaching that system service, not Flask. Documentation incorrectly directed the user to port 5000 and no health endpoint made the distinction easy to diagnose.
- **What I did instead:** Changed the default/documented local port to 5050, kept environment-variable override support, added a database-backed `/health` route, and verified login, seeded document access, review/PDF download, and logout on the live app. These changes predate the repository's first commit; no per-change link exists.

### 2026-10-24 — Correcting the project write-up and clean-clone instructions

- **Prompt:** The user supplied a draft submission narrative that described the project as starting from scratch and asked to create the project.
- **Produced:** A complete TrustVault application already existed, but the draft did not describe its implemented features and used a placeholder repository URL and a default port that did not match the application.
- **What was wrong / checked:** The claims “currently in development” and “starting from scratch” understated the current implementation. The setup text did not identify the actual public repository or explain that seeding exits before the web server starts.
- **What I did instead:** Rewrote `WRITEUP.md` to distinguish tested functionality from limitations, documented the actual clone/setup flow and port in `README.md`, corrected this log to explain that the earlier code changes predate the first Git commit, and then aligned the write-up with the six submission questions without inventing a live URL. **Commits:** [`ed6735a`](https://github.com/VunnamLakshmipravallika/TRUSTVAULT/commit/ed6735a), [`f63ffc4`](https://github.com/VunnamLakshmipravallika/TRUSTVAULT/commit/f63ffc4), [`0d4d3d7`](https://github.com/VunnamLakshmipravallika/TRUSTVAULT/commit/0d4d3d7).

### Future entries

Continue adding dated entries as you use AI. At least two entries should cover authorization, access control, or the audit trail. Each entry must state the prompt, actual output, a specific defect or verification result, and the real commit URL/SHA for any correction. Do not invent dates, prompt details, or commit links.
