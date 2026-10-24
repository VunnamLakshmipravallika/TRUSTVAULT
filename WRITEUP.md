# TrustVault — secure document sharing with a real audit trail

**Repository:** [VunnamLakshmipravallika/TRUSTVAULT](https://github.com/VunnamLakshmipravallika/TRUSTVAULT)
**Status:** Runnable local prototype; deployment and demo recording are not included.
**One-line description:** A Flask document-sharing app with named per-file permissions, server-checked revocation, and a tamper-evident activity log.

The following sections are formatted as answers for the six project-submission questions.

## 1. The problem you solved

Companies need to share confidential documents with specific people without accidentally exposing a whole folder or relying on a link that remains usable after access is revoked. They also need an accountable record of successful and refused access, permission changes, and other document activity.

TrustVault addresses this with named, per-document grants and server-side authorization. It is a security-focused prototype, not a claim of production certification.

## 2. What actually works right now

- Sign-in with administrator, document-owner, and viewer roles.
- Owner upload, search/filter, metadata editing, soft deletion, and private file download.
- Per-document `read` and `edit` grants to named accounts, with owner-controlled grant and revocation.
- Authorization checks on document routes, including download and review; revocation blocks the next request. A file already downloaded cannot be recalled.
- Optional owner-selected expiry date/time at upload. Expired content becomes inaccessible and the running app purges its file, document row, grants, and saved reviews, with an audit event.
- File extension/content checks and a 10 MiB upload limit.
- An administrative activity view and a locally HMAC-chained audit log with SQLite update/delete triggers. The chain detects changes made without the audit key; it does not protect against an attacker controlling the application host and key.
- Optional SMTP notifications on grants. Email is a notification only, contains no file or bearer download link, and does not itself grant access.
- Local heuristic privacy scanning for supported PDF, DOCX, and TXT documents, with redacted findings and a downloadable PDF report. The scan is not a compliance certification and does not support image OCR.
- Automated tests for authorization boundaries, revocation, upload validation, email behavior, audit behavior, and privacy-review output.

**Roles:** Owners upload and manage their own documents and grants. Viewers have no access unless explicitly granted. Administrators can inspect workspace metadata and audit activity but do not automatically receive document-content access.

## 3. How to run it

Requires Python 3.10+ and pip. Commands below are for macOS/Linux; on Windows, activate the virtual environment with `.venv\\Scripts\\activate`.

```sh
git clone https://github.com/VunnamLakshmipravallika/TRUSTVAULT.git
cd TRUSTVAULT
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python app.py --seed
python app.py
```

The seed command initializes the local SQLite database and demo accounts, then exits. Start the server with the next command and open <http://127.0.0.1:5050>. Port 5000 is avoided because it may be occupied by a macOS system service.

Seeded local-only demo accounts:

| Role | Username | Password |
|---|---|---|
| Administrator | `admin` | `Admin123!` |
| Owner | `owner` | `Owner123!` |
| Viewer | `viewer` | `Viewer123!` |
| Unauthorised viewer for access-denial demonstrations | `outsider` | `Outside123!` |

Run the tests in another terminal from the repository root:

```sh
python -m unittest discover -s tests -v
```

All 16 tests passed in the local verification on 2026-10-24. This is not evidence of a public deployment. Do not use the seeded passwords for a shared or production system.

## 4. AI tools used

ChatGPT was used to help implement and review the Flask application, tests, and documentation, and to troubleshoot the project layout and startup instructions. The AI prompt/review record is in [PROMPTS.md](PROMPTS.md). The implementation and authorization behavior were checked by running the automated tests and exercising the app locally; AI-generated output was not treated as proof by itself.

## 5. What the AI got wrong, and what I corrected

During troubleshooting, an earlier response said the app and tests had been verified, but the workspace files were split: the Git repository was in the `trustvault/` subfolder while the test and review modules, schema, templates, and static assets were outside it. Running tests from the workspace parent failed with `ModuleNotFoundError: No module named 'app'`; importing from the nested folder then failed to find `document_review`.

The missing runtime files were added to the Git repository, and its README now explains the correct repository root and startup commands. Verification from the repository root passed all 16 tests. A separate smoke test with a temporary database verified seeding, health check, owner login, document listing, metadata, and sample download. The local changes were pushed to the repository's `main` branch.

## 6. What is unfinished

- A live deployment URL and five-minute demo recording are not provided. Do not enter a placeholder URL in the submission form; deploy the app and verify the link in a private/incognito window first.
- Production account administration, MFA, rate limiting, malware scanning, external append-only audit storage, document versioning/recovery, and disaster-recovery testing are not implemented.
- Real email delivery requires SMTP credentials and real account email addresses; the seeded `.test` addresses cannot receive mail.
- The local development server is not hardened for direct internet exposure. A real deployment needs HTTPS, secure secrets, protected persistent storage, and operational monitoring.
- Audit chaining is tamper-evident only while the audit key and application host remain trustworthy.
- Expiry cleanup in the local app runs at startup, on HTTP requests, and periodically while the built-in server is running. A production multi-worker deployment needs a separately scheduled cleanup job. Filesystem deletion cannot guarantee forensic erasure from SSD storage or backups.

See [README.md](README.md) for the full endpoint permissions and setup details, and [THREATS.md](THREATS.md) for the threat model and accepted risks.

## Before submitting the form

- Complete your own Snovasys profile, including your personal and education details and resume link; those details are not in this code repository.
- Use the GitHub link above for the repository field.
- Leave the live-website field unsubmitted until you have deployed the application and confirmed it opens for a stranger. No deployment URL is available yet.
- Copy the six answers above into their respective form boxes, then tick “I am done. Submit this for evaluation” only when the required fields and live URL are ready.
- The challenge says not to make the repository public before the deadline. This repository is currently public, so change its GitHub visibility to private until the permitted time if that rule applies to your submission. Do not fabricate commit dates or history.
