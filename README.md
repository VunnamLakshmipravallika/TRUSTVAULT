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
python app.py --configure-owner
python app.py --seed
python app.py
```

The owner setup command asks for a password twice without echoing it; use 12–128 characters and keep it out of shell history and source control. It creates or updates the single owner account and stores only a password hash in the database. The seed command initializes the other demo users, then exits. The next command starts the server. Open <http://127.0.0.1:5050>. Port 5000 is commonly occupied by macOS AirPlay/ControlCenter, so TrustVault uses port 5050 by default; set `PORT` to another free port if necessary. The health endpoint is <http://127.0.0.1:5050/health>. Seeding creates a harmless sample document under `instance/`. Do not expose the development server directly to the internet. For deployment, configure the same owner password in the host's private environment settings or use the interactive owner setup against the persistent database, use a production WSGI server behind HTTPS, set `TRUSTVAULT_COOKIE_SECURE=1`, set strong `TRUSTVAULT_SESSION_KEY` and `TRUSTVAULT_AUDIT_KEY` secrets, and persist the instance directory and backups securely.

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
| Document owner | `pravallika` | Set interactively with `python app.py --configure-owner` |
| Viewer | `viewer` | `Viewer123!` |
| Unauthorised viewer for demos/tests | `outsider` | `Outside123!` |

Admin and viewer seed accounts are for local evaluation only. The owner account is not seeded with a public default password.

### Role-based sign in

Choose Admin or Viewer on the sign-in page; the selected role is checked against the authenticated account on the server. Choosing Owner opens the dedicated owner sign-in page. Only the `pravallika` account can authenticate as owner. Use `python app.py --configure-owner` to securely set or rotate its password; for deployments, `TRUSTVAULT_OWNER_PASSWORD` can be supplied through the host's private environment settings and the database updated at startup. Public registration reserves the owner username. If another account already uses it or more than one owner account exists, startup stops with an explicit error rather than silently changing account ownership or disabling accounts.

### Create an account

People who do not have an account can use **Create an account** on the sign-in page and choose Viewer or Admin. Viewer accounts activate immediately and start with no document permissions; an owner must grant access to each document. Choosing Admin creates a pending request, not an administrator account. The applicant cannot sign in as Admin or review their own request. An existing active Admin must sign in, complete the User ID step, and approve the request in **Admin requests**; pending requests are shown automatically in that Admin's workspace. Approval and rejection are audited; a rejected request remains unable to sign in. Owner accounts are not available through public registration. The server assigns roles and statuses regardless of client-supplied role fields. Email verification, password recovery, and registration rate limiting are not implemented.

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
- After authentication, `viewer` and `admin` users must submit a self-reported User ID before entering the workspace. Owners can view these sign-in submissions with the authenticated account name, role, and UTC timestamp in **User sign-ins**. The typed ID is not independently verified and must not be treated as proof of identity.
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

The tests prove ungranted users cannot list, read, download, edit, delete, or review another user's file; test read-only grants; verify immediate revocation and browser sign-out; validate upload rejection; test successful and failed email-notification handling without turning email into an access link; verify admin/viewer post-login identity gating and owner-only sign-in visibility; test viewer registration and login, pending admin requests, approval/rejection, admin-only decisions, input validation, and CSRF protection; test expiry purge; and check review output redaction and PDF generation.

## API

All mutation calls require the session CSRF token in `X-CSRF-Token`. Obtain it from `/api/me` after signing in. API calls use the same secure session cookie as the UI.

| Method and path | Who may call | Behavior |
|---|---|---|
| `POST /api/login` | Anyone | Authenticate username/password |
| `POST /api/session/user-id` | Authenticated viewer/admin with pending identity step | Submit a self-reported User ID to continue to the workspace; recorded in the audit log |
| `GET /api/owner/login-activity` | Owner | View successful viewer/admin logins with authenticated usernames, roles, timestamps, and optional self-reported IDs |
| `GET /health` | Anyone | Health check verifies the application can query its database |
| `POST /api/logout` | Authenticated user | End current session |
| `POST /logout` | Authenticated browser session | CSRF-protected sign-out followed by redirect to sign-in |
| `GET /api/me` | Authenticated user | Current identity and CSRF token |
| `GET /api/users` | Owner | Named recipients available for grants |
| `GET /api/owner/dashboard` | Owner | Owner-scoped document, sharing, expiry, and recent activity summary |
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
