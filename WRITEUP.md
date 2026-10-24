# TrustVault — project write-up

TrustVault is a secure-by-default document-sharing prototype. Uploaded files are stored under generated server-side filenames outside the web root. Every metadata, permission, and download request checks the current user against the document owner or an explicit per-document grant. Sharing is named and scoped to one document; there is no folder inheritance or public link. Owners may send a short email notification to an existing account when granting access, without emailing the file or creating a bearer link. Authorized readers can also run a local deterministic privacy-pattern review and download a redacted PDF report; document text is not sent to an external AI provider, and the score is not a truth or compliance guarantee.

## What is implemented

Authentication with three roles, document upload and search, read/edit grants, owner-only grant/revoke, metadata edits, owner deletion, private download, file validation, admin activity view, CSRF validation, and a chained audit log. Automated tests exercise direct attempts by an ungranted user. The detailed API access table is in [README.md](README.md).

## Permission model in my words

Being logged in does not imply access to a document. The owner role can upload; that user owns the document and can manage its grants. A named user can be granted read or edit. A read grant allows metadata and download; edit additionally allows changing name/category. Only the owner can delete or change grants. The viewer role cannot upload or enumerate users. Administrators can inspect workspace metadata and activity, but cannot read/download document contents unless explicitly granted. Revocation removes the grant row, so the next server-side request is denied; it cannot claw back a previously downloaded copy.

## Audit design

Each audit entry commits to the preceding hash and is HMAC-signed using a local secret. SQLite triggers reject update/delete statements on audit rows. The admin endpoint verifies the chain. This provides tamper evidence for ordinary application/database-level changes, not protection against an attacker who controls the host and audit key. For production I would export to independently controlled append-only storage.

## AI use and unfinished work

The initial implementation was built with AI assistance from the challenge brief. The AI log records the actual work known in this workspace; there is no pre-existing Git history here, so fabricated prior prompt/commit history would be misleading. See [PROMPTS.md](PROMPTS.md) for the honest log and future-entry requirements.

Not implemented: public deployment, public repository/history, demo video, production user provisioning, MFA, rate limiting, malware scanning, external immutable audit storage, versioning/recovery, and tested disaster recovery. Before evaluation, run the tests, rotate seeded passwords, deploy behind HTTPS, add test evidence and screenshots, and record further prompt corrections in Git history.
