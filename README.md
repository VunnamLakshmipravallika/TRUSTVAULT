# TrustVault

TrustVault is a small, runnable secure document-sharing demo built with Flask and SQLite. File contents live outside the web root and are only served by a download route that rechecks the current document permission on every request. A revoked grant therefore stops working on the next request. Owners can optionally notify a registered recipient by email when granting document access.

The document detail view also includes a local privacy-risk review for PDF, DOCX, and UTF-8 TXT files. It scans for heuristic patterns such as credentials, private key markers, possible government IDs, payment cards, email addresses, and phone numbers. Findings are redacted, the deterministic privacy score is higher when fewer sensitive patterns are detected, and a PDF report can be downloaded. This does not fact-check document claims or certify legal/compliance status. Review uses the TrustVault host only; it does not send document text to an external AI service. Image OCR is not supported.

This privacy-review feature adapts the explainable scoring/report idea from [TruthShield](https://github.com/CKaushikRaj/truthshield) to TrustVault's document-security use case; it does not reuse TruthShield source code or send private documents to an AI provider.

## Start from a clean clone

Requires Python 3.10+.

```sh
git clone https://github.com/VunnamLakshmipravallika/TRUSTVAULT.git
cd TRUSTVAULT
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python app.py --seed
python app.py
```

The seed command initializes the local SQLite database and demo users, then exits. The next command starts the server. Open <http://127.0.0.1:5050>. Port 5000 is commonly occupied by macOS AirPlay/ControlCenter, so TrustVault uses port 5050 by default; set `PORT` to another free port if necessary. The health endpoint is <http://127.0.0.1:5050/health>. Seeding creates a harmless sample document under `instance/`. Do not expose the development server directly to the internet. For deployment, use a production WSGI server behind HTTPS, set `TRUSTVAULT_COOKIE_SECURE=1`, set strong `TRUSTVAULT_SESSION_KEY` and `TRUSTVAULT_AUDIT_KEY` secrets, and persist the instance directory and backups securely.

When opening the provided VS Code workspace rather than cloning the repository, the Git repository and complete application are in its `trustvault/` subfolder. From the workspace parent, run `cd trustvault` before running the application commands above. Run commands from the repository root so Flask can find `app.py`, `document_review.py`, `schema.sql`, `templates/`, `static/`, and `tests/`.

### Troubleshooting

- If `http://127.0.0.1:5000` shows an AirPlay page or returns HTTP 403 on macOS, that port belongs to the operating system service, not TrustVault. Use port 5050.
- If another program already uses 5050, run `PORT=5051 python app.py` and open `http://127.0.0.1:5051`.
- If the browser keeps an old page/session, open the exact URL and hard-refresh. An authenticated session is stored in that browser's cookies.
- Check `/health` on the same host/port; `{"status":"ok"}` confirms Flask and SQLite are responding.

### Seeded demo accounts

| Role | Username | Password |
|---|---|---|
| Administrator | `admin` | `Admin123!` |
| Document owner | `owner` | `Owner123!` |
| Viewer | `viewer` | `Viewer123!` |
| Unauthorised viewer for demos/tests | `outsider` | `Outside123!` |

Change demo passwords and secrets before any shared deployment. Seed accounts are for evaluation only.

## Email notifications for access grants

Email is a notification only; it never contains the document or a bearer download link. Access is granted to the selected existing TrustVault account, and every view/download still requires that account's authenticated session and current permission. If SMTP delivery fails, the permission grant remains active and the UI explicitly reports that the email was not sent; both outcomes are recorded in the audit log.

Configure SMTP and real addresses for demo accounts using environment variables before seeding and starting the app. Never commit credentials:

```sh
export TRUSTVAULT_SMTP_HOST="smtp.example.com"
export TRUSTVAULT_SMTP_PORT="587"
export TRUSTVAULT_SMTP_USERNAME="your-smtp-user"
export TRUSTVAULT_SMTP_PASSWORD="your-smtp-app-password"
export TRUSTVAULT_SMTP_FROM="trustvault@example.com"
export TRUSTVAULT_SMTP_STARTTLS="1"
export TRUSTVAULT_BASE_URL="http://127.0.0.1:5050"
export TRUSTVAULT_EMAIL_OWNER="owner@your-domain.com"
export TRUSTVAULT_EMAIL_VIEWER="viewer@your-domain.com"
python app.py --seed
python app.py
```

Replace example values with addresses/accounts controlled by you and SMTP credentials from your mail provider. `TRUSTVAULT_EMAIL_ADMIN` and `TRUSTVAULT_EMAIL_OUTSIDER` may also be set. When granting access, choose the account, permission, and whether to send the notification. Seeded `.test` email addresses are placeholders and cannot receive mail.

## Permission model

- `owner` users can upload and own documents. Only the owner may grant/revoke named users, edit document metadata, or delete their document.
- `viewer` users have no document access by default. A grant is stored per document and per named user, with `read` or `edit` permission.
- `viewer` cannot upload or enumerate the recipient directory. `admin` can see all active document metadata and the administrative activity log, but **does not automatically get document-content access**. Admin must receive a normal explicit grant to download a file.
- `read` can view metadata and download. `edit` can also change document name/category. Ownership alone permits `edit`; deletion and grant management remain owner-only.
- Owners may set an optional expiry date/time during upload. The browser converts the selected local time to UTC; expired documents are denied immediately, then the running app's cleanup worker purges the file, document row, grants, and saved reviews and records the purge in the audit log. Cleanup runs at application startup, periodically while the built-in server is running, and on HTTP requests. Production multi-worker deployments must configure a reliable scheduled cleanup job. Local file deletion is not a forensic secure-erase guarantee for SSDs or backups.
- Every metadata, permission, and download route checks the current database state. The browser UI is not an authorization boundary. Document IDs and stored paths are not public URLs.

## Audit and limitations

Audit entries include successful uploads, downloads, edits, soft-deletions, grants, revocations, failed sign-ins, and authorization denials. Each append includes the previous entry hash and an HMAC-SHA256 signature. SQLite triggers reject updates/deletes to the audit table; the admin endpoint verifies the chain. Keep the audit key separate from database backups in production. A host/root administrator who can replace both the application and its key can still rewrite local evidence; stronger evidence requires remote append-only/WORM storage or an independently held signing key. This single-process demo does not claim to provide that.

Uploads are limited to 10 MiB and validated against an allowlist and basic file signatures/content. This is not malware scanning or content disarm/reconstruction. The app does not implement external sharing, folder inheritance, version history, recovery, SSO/MFA, rate limits, or production account administration.

## Tests

```sh
python -m unittest discover -s tests -v
```

The tests prove ungranted users cannot list, read, download, edit, delete, or review another user's file; test read-only grants; verify immediate revocation and browser sign-out; validate upload rejection; test successful and failed email-notification handling without turning email into an access link; and check review output redaction and PDF generation.

## API

All mutation calls require the session CSRF token in `X-CSRF-Token`. Obtain it from `/api/me` after signing in. API calls use the same secure session cookie as the UI.

| Method and path | Who may call | Behavior |
|---|---|---|
| `POST /api/login` | Anyone | Authenticate username/password |
| `GET /health` | Anyone | Health check verifies the application can query its database |
| `POST /api/logout` | Authenticated user | End current session |
| `POST /logout` | Authenticated browser session | CSRF-protected sign-out followed by redirect to sign-in |
| `GET /api/me` | Authenticated user | Current identity and CSRF token |
| `GET /api/users` | Owner | Named recipients available for grants |
| `GET /api/documents` | Authenticated user | Owner/viewer search only owned or granted documents; admin sees all active metadata |
| `POST /api/documents` | Owner role | Upload an allowlisted document; optional `expires_at` is a timezone-aware ISO-8601 timestamp |
| `GET /api/documents/{id}` | Owner, granted `read`/`edit` user, or admin | Read metadata; admin receives metadata-only access; owner also gets grants |
| `GET /api/documents/{id}/download` | Owner or granted `read`/`edit` user | Download; permission is rechecked each time |
| `POST /api/documents/{id}/review` | Owner or granted `read`/`edit` user | Run a local sensitive-data pattern scan and save a user-scoped report |
| `GET /api/documents/{id}/review/latest` | Owner or granted `read`/`edit` user | Fetch only the caller's latest review; current grant is rechecked |
| `GET /api/documents/{id}/review/latest.pdf` | Owner or granted `read`/`edit` user | Download the caller's latest redacted PDF report; current grant is rechecked |
| `PATCH /api/documents/{id}` | Owner or `edit` grantee | Change name/category |
| `DELETE /api/documents/{id}` | Owner only | Soft-delete and remove access |
| `GET /api/documents/{id}/permissions` | Owner only | List document grants |
| `POST /api/documents/{id}/permissions` | Owner only | Grant `read` or `edit` to a named user; optional `notify: true` sends the configured email notification |
| `DELETE /api/documents/{id}/permissions/{username}` | Owner only | Revoke named user's grant |
| `GET /api/admin/audit` | Admin only | View recent activity and verify audit chain |

Unauthorized document access uses a not-found response to reduce document-ID enumeration and is recorded as an authorization denial.

## Demo outline

1. Sign in as `owner`, upload a document, and show that it is private by default.
2. Sign in as `outsider`; show it is absent and a direct download request returns not found.
3. As the owner, grant `viewer` read access; sign in as `viewer` and download it.
4. Revoke access as owner, then retry the exact download URL as viewer. It is denied immediately.
5. Open an allowed document as owner/viewer, run its local privacy review, and download the redacted PDF report.
6. Sign in as `admin` and inspect successful/denied events and chain verification.

## Submission material

See [THREATS.md](THREATS.md), [PROMPTS.md](PROMPTS.md), and [WRITEUP.md](WRITEUP.md). The source repository is [VunnamLakshmipravallika/TRUSTVAULT](https://github.com/VunnamLakshmipravallika/TRUSTVAULT). A public deployment and demo recording are not included yet.
