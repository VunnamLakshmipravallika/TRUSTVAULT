import hashlib
import hmac
import io
import json
import mimetypes
import os
import secrets
import smtplib
import sqlite3
import ssl
import sys
import threading
import uuid
import zipfile
from datetime import datetime, timezone
from email.message import EmailMessage
from functools import wraps
from pathlib import Path

from flask import Flask, abort, g, jsonify, redirect, render_template, request, send_file, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from document_review import ReviewInputError, build_review, extract_text, render_pdf_report, serialize_review


ROOT = Path(__file__).resolve().parent
INSTANCE = Path(os.environ.get("TRUSTVAULT_INSTANCE", ROOT / "instance"))
UPLOADS = INSTANCE / "private-files"
DATABASE = Path(os.environ.get("TRUSTVAULT_DATABASE", INSTANCE / "trustvault.sqlite3"))
MAX_UPLOAD_BYTES = 10 * 1024 * 1024
ALLOWED_EXTENSIONS = {"pdf", "txt", "png", "jpg", "jpeg", "docx"}

app = Flask(__name__)
app.config.update(
    MAX_CONTENT_LENGTH=MAX_UPLOAD_BYTES + 256 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("TRUSTVAULT_COOKIE_SECURE") == "1",
)


def _load_secret(name, filename):
    configured = os.environ.get(name)
    if configured:
        return configured.encode()
    path = INSTANCE / filename
    if path.exists():
        return path.read_bytes()
    value = secrets.token_bytes(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(value)
    return value


INSTANCE.mkdir(parents=True, exist_ok=True)
UPLOADS.mkdir(parents=True, exist_ok=True)
app.secret_key = _load_secret("TRUSTVAULT_SESSION_KEY", ".session-key")
AUDIT_KEY = _load_secret("TRUSTVAULT_AUDIT_KEY", ".audit-key")


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        g.db.execute("PRAGMA secure_delete = ON")
        g.db.execute("PRAGMA busy_timeout = 5000")
    return g.db


@app.teardown_appcontext
def close_db(_error=None):
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


def initialize():
    connection = sqlite3.connect(DATABASE)
    connection.execute("PRAGMA foreign_keys = ON")
    connection.executescript((ROOT / "schema.sql").read_text())
    user_columns = {row[1] for row in connection.execute("PRAGMA table_info(users)")}
    if "email" not in user_columns:
        connection.execute("ALTER TABLE users ADD COLUMN email TEXT")
    document_columns = {row[1] for row in connection.execute("PRAGMA table_info(documents)")}
    if "expires_at" not in document_columns:
        connection.execute("ALTER TABLE documents ADD COLUMN expires_at TEXT")
    connection.commit()
    connection.close()


def parse_expiry(value):
    if not value:
        return None
    try:
        expiry = datetime.fromisoformat(value)
    except (TypeError, ValueError) as error:
        raise ValueError("Expiry must be a valid date and time.") from error
    if expiry.tzinfo is None or expiry.utcoffset() is None:
        raise ValueError("Expiry must include a timezone.")
    expiry = expiry.astimezone(timezone.utc)
    if expiry <= datetime.now(timezone.utc):
        raise ValueError("Expiry must be in the future.")
    return expiry.isoformat(timespec="seconds")


def purge_expired_documents():
    connection = db()
    expiry_cutoff = now()
    expired = connection.execute(
        """SELECT id, owner_id, stored_filename FROM documents
           WHERE expires_at IS NOT NULL AND expires_at <= ?
           ORDER BY expires_at""",
        (expiry_cutoff,),
    ).fetchall()
    if not expired:
        return

    connection.execute("BEGIN IMMEDIATE")
    expired = connection.execute(
        """SELECT id, owner_id, stored_filename FROM documents
           WHERE expires_at IS NOT NULL AND expires_at <= ?
           ORDER BY expires_at""",
        (now(),),
    ).fetchall()
    if not expired:
        connection.rollback()
        return

    purged_count = 0
    for document in expired:
        path = UPLOADS / document["stored_filename"]
        try:
            path.unlink(missing_ok=True)
        except OSError:
            app.logger.exception("Could not remove expired document file %s", path.name)
            continue
        connection.execute("DELETE FROM permissions WHERE document_id = ?", (document["id"],))
        connection.execute("DELETE FROM document_reviews WHERE document_id = ?", (document["id"],))
        connection.execute("DELETE FROM documents WHERE id = ?", (document["id"],))
        audit(None, "document.expired_and_purged", document["id"], {"owner_id": document["owner_id"]})
        purged_count += 1
    if not purged_count:
        connection.rollback()


@app.before_request
def purge_expired_documents_before_request():
    purge_expired_documents()


def _expiry_worker():
    while not _expiry_worker_stop.wait(5):
        try:
            with app.app_context():
                purge_expired_documents()
        except sqlite3.Error:
            app.logger.exception("Expired-document cleanup failed")


_expiry_worker_stop = threading.Event()


def start_expiry_worker():
    worker = threading.Thread(target=_expiry_worker, name="trustvault-expiry-cleanup", daemon=True)
    worker.start()


def send_access_email(recipient, owner_name, document_name, permission):
    host = os.environ.get("TRUSTVAULT_SMTP_HOST")
    sender = os.environ.get("TRUSTVAULT_SMTP_FROM")
    recipient_email = (recipient["email"] or "").strip()
    reserved_email = recipient_email.lower().endswith((".test", ".example", ".invalid", ".localhost"))
    if not host or not sender or not recipient_email or reserved_email:
        raise RuntimeError("Email delivery is not configured for this recipient.")
    port = int(os.environ.get("TRUSTVAULT_SMTP_PORT", "587"))
    username = os.environ.get("TRUSTVAULT_SMTP_USERNAME")
    password = os.environ.get("TRUSTVAULT_SMTP_PASSWORD")
    use_starttls = os.environ.get("TRUSTVAULT_SMTP_STARTTLS", "1") == "1"
    base_url = os.environ.get("TRUSTVAULT_BASE_URL", "http://127.0.0.1:5050").rstrip("/")
    message = EmailMessage()
    message["Subject"] = f"TrustVault: {owner_name} shared a document with you"
    message["From"] = sender
    message["To"] = recipient_email
    message.set_content(
        f"Hello {recipient['display_name']},\n\n"
        f"{owner_name} granted you {permission} access to \"{document_name}\" in TrustVault.\n"
        "Sign in to your TrustVault account to view the document. Access is checked each time "
        "you open or download it and may be revoked by its owner.\n\n"
        f"Open TrustVault: {base_url}\n"
    )
    with smtplib.SMTP(host, port, timeout=15) as server:
        server.ehlo()
        if use_starttls:
            server.starttls(context=ssl.create_default_context())
            server.ehlo()
        if username:
            server.login(username, password or "")
        server.send_message(message)


def audit(actor_id, action, document_id=None, details=None):
    connection = db()
    if not connection.in_transaction:
        connection.execute("BEGIN IMMEDIATE")
    previous = connection.execute(
        "SELECT entry_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
    ).fetchone()
    previous_hash = previous["entry_hash"] if previous else "0" * 64
    occurred_at = now()
    safe_details = json.dumps(details or {}, sort_keys=True, separators=(",", ":"))
    body = "\x1f".join(
        [occurred_at, str(actor_id) if actor_id is not None else "anonymous",
         action, document_id or "", safe_details, previous_hash]
    )
    entry_hash = hmac.new(AUDIT_KEY, body.encode(), hashlib.sha256).hexdigest()
    connection.execute(
        """INSERT INTO audit_events
           (occurred_at, actor_id, action, document_id, details, previous_hash, entry_hash)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (occurred_at, actor_id, action, document_id, safe_details, previous_hash, entry_hash),
    )
    connection.commit()


def verify_audit_chain():
    previous_hash = "0" * 64
    for row in db().execute("SELECT * FROM audit_events ORDER BY sequence"):
        body = "\x1f".join(
            [
                row["occurred_at"],
                str(row["actor_id"]) if row["actor_id"] is not None else "anonymous",
                row["action"],
                row["document_id"] or "",
                row["details"],
                previous_hash,
            ]
        )
        expected = hmac.new(AUDIT_KEY, body.encode(), hashlib.sha256).hexdigest()
        if row["previous_hash"] != previous_hash or not hmac.compare_digest(row["entry_hash"], expected):
            return False
        previous_hash = row["entry_hash"]
    return True


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    return db().execute("SELECT id, username, display_name, role FROM users WHERE id = ?", (user_id,)).fetchone()


def require_auth(fn):
    @wraps(fn)
    def decorated(*args, **kwargs):
        if current_user() is None:
            if request.path.startswith("/api/"):
                return jsonify(error="authentication_required"), 401
            return redirect(url_for("home"))
        if session.get("identity_pending") and request.path not in {"/logout"}:
            if request.path.startswith("/api/"):
                return jsonify(error="identity_required"), 403
            return redirect(url_for("home"))
        return fn(*args, **kwargs)
    return decorated


def require_admin(fn):
    @wraps(fn)
    @require_auth
    def decorated(*args, **kwargs):
        user = current_user()
        if user["role"] != "admin":
            audit(user["id"], "authorization.denied", details={"path": request.path, "reason": "admin_required"})
            return jsonify(error="not_found"), 404
        return fn(*args, **kwargs)
    return decorated


def document_access(document_id, minimum="read"):
    user = current_user()
    row = db().execute(
        """SELECT d.*, u.display_name AS owner_name,
                  CASE WHEN d.owner_id = ? THEN 'edit' ELSE p.permission END AS permission
           FROM documents d LEFT JOIN permissions p
             ON p.document_id = d.id AND p.user_id = ?
           JOIN users u ON u.id = d.owner_id
           WHERE d.id = ? AND d.deleted_at IS NULL
             AND (d.expires_at IS NULL OR d.expires_at > ?)""",
        (user["id"], user["id"], document_id, now()),
    ).fetchone()
    levels = {"read": 1, "edit": 2}
    if row is None or row["permission"] is None or levels.get(row["permission"], 0) < levels[minimum]:
        audit(user["id"], "authorization.denied", document_id, {"action": minimum, "path": request.path})
        abort(404)
    return row


def csrf_protect(fn):
    @wraps(fn)
    def decorated(*args, **kwargs):
        if request.method in {"POST", "PATCH", "DELETE"}:
            token = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
            if not token or not hmac.compare_digest(token, session.get("csrf_token", "")):
                user = current_user()
                audit(user["id"] if user else None, "authorization.denied", details={"reason": "csrf", "path": request.path})
                return jsonify(error="csrf_failed"), 403
        return fn(*args, **kwargs)
    return decorated


def json_body():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return {}
    return data


def clean_date(value):
    if not value:
        return None
    try:
        datetime.strptime(value, "%Y-%m-%d")
        return value
    except ValueError:
        abort(400, description="Dates must use YYYY-MM-DD.")


def file_is_valid(file_storage, extension):
    head = file_storage.stream.read(16)
    file_storage.stream.seek(0)
    if extension == "pdf":
        return head.startswith(b"%PDF-")
    if extension == "png":
        return head.startswith(b"\x89PNG\r\n\x1a\n")
    if extension in {"jpg", "jpeg"}:
        return head.startswith(b"\xff\xd8\xff")
    if extension == "txt":
        try:
            file_storage.stream.read().decode("utf-8")
            file_storage.stream.seek(0)
            return True
        except UnicodeDecodeError:
            file_storage.stream.seek(0)
            return False
    if extension == "docx":
        try:
            with zipfile.ZipFile(file_storage.stream) as archive:
                valid = "word/document.xml" in archive.namelist()
            file_storage.stream.seek(0)
            return valid
        except (zipfile.BadZipFile, OSError):
            file_storage.stream.seek(0)
            return False
    return False


@app.route("/", methods=["GET"])
def home():
    user = current_user()
    if user:
        csrf_token = session.setdefault("csrf_token", secrets.token_urlsafe(32))
        if session.get("identity_pending"):
            return render_template("user_id.html", user=user, csrf_token=csrf_token)
        return render_template("index.html", user=user, csrf_token=csrf_token)
    return render_template("login.html", csrf_token=session.setdefault("csrf_token", secrets.token_urlsafe(32)))


@app.get("/health")
def health():
    db().execute("SELECT 1").fetchone()
    return jsonify(status="ok")


@app.post("/api/login")
@csrf_protect
def login():
    data = json_body()
    username = str(data.get("username", "")).strip().lower()
    password = data.get("password", "")
    user = db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if user is None or not check_password_hash(user["password_hash"], str(password)):
        audit(None, "authentication.failed", details={"username": username[:120]})
        return jsonify(error="invalid_credentials"), 401
    session.clear()
    session["user_id"] = user["id"]
    session["csrf_token"] = secrets.token_urlsafe(32)
    session["identity_pending"] = user["role"] in {"admin", "viewer"}
    audit(user["id"], "authentication.succeeded")
    return jsonify(user={"username": user["username"], "display_name": user["display_name"], "role": user["role"]},
                   csrf_token=session["csrf_token"], identity_required=session["identity_pending"])


@app.post("/api/session/user-id")
@csrf_protect
def submit_user_id():
    user = current_user()
    if user is None:
        return jsonify(error="authentication_required"), 401
    if user["role"] not in {"admin", "viewer"} or not session.get("identity_pending"):
        return jsonify(error="identity_already_submitted"), 409
    submitted_user_id = json_body().get("user_id")
    if (not isinstance(submitted_user_id, str) or not submitted_user_id.strip()
            or len(submitted_user_id.strip()) > 100 or not submitted_user_id.strip().isprintable()):
        return jsonify(error="Enter a User ID of 1 to 100 printable characters."), 400
    submitted_user_id = submitted_user_id.strip()
    audit(user["id"], "session.identity_submitted", details={"self_reported_user_id": submitted_user_id})
    session["identity_pending"] = False
    return jsonify(ok=True)


@app.post("/api/logout")
@require_auth
@csrf_protect
def logout():
    user = current_user()
    audit(user["id"], "authentication.logout")
    session.clear()
    return jsonify(ok=True)


@app.post("/logout")
@require_auth
@csrf_protect
def browser_logout():
    user = current_user()
    audit(user["id"], "authentication.logout")
    session.clear()
    return redirect(url_for("home"), code=303)


@app.get("/api/me")
@require_auth
def me():
    user = current_user()
    return jsonify(user={"username": user["username"], "display_name": user["display_name"], "role": user["role"]},
                   csrf_token=session.setdefault("csrf_token", secrets.token_urlsafe(32)))


@app.get("/api/users")
@require_auth
def users():
    user = current_user()
    if user["role"] != "owner":
        abort(404)
    rows = db().execute("SELECT id, username, display_name, email, role FROM users WHERE id != ? ORDER BY username",
                        (user["id"],)).fetchall()
    return jsonify(users=[dict(row) for row in rows])


@app.get("/api/documents")
@require_auth
def list_documents():
    user = current_user()
    clauses = ["d.deleted_at IS NULL", "(d.expires_at IS NULL OR d.expires_at > ?)"]
    params = [now()]
    if user["role"] != "admin":
        clauses.append("(d.owner_id = ? OR p.user_id = ?)")
        params.extend([user["id"], user["id"]])
    for field in ("name", "category"):
        value = request.args.get(field, "").strip()
        if value:
            clauses.append(f"d.{field} LIKE ?")
            params.append(f"%{value}%")
    owner = request.args.get("owner", "").strip()
    if owner:
        clauses.append("u.display_name LIKE ?")
        params.append(f"%{owner}%")
    for field, operator in (("from", ">="), ("to", "<=")):
        value = clean_date(request.args.get(field))
        if value:
            clauses.append(f"date(d.created_at) {operator} date(?)")
            params.append(value)
    rows = db().execute(
        """SELECT d.id, d.name, d.category, d.mime_type, d.size_bytes, d.created_at, d.expires_at,
                  u.display_name AS owner,
                  CASE WHEN d.owner_id = ? THEN 'edit'
                       WHEN ? = 'admin' AND p.permission IS NULL THEN 'admin_metadata'
                       ELSE p.permission END AS permission
           FROM documents d JOIN users u ON u.id = d.owner_id
           LEFT JOIN permissions p ON p.document_id = d.id AND p.user_id = ?
           WHERE """ + " AND ".join(clauses) + " ORDER BY d.created_at DESC",
        [user["id"], user["role"], user["id"], *params],
    ).fetchall()
    return jsonify(documents=[dict(row) for row in rows])


@app.post("/api/documents")
@require_auth
@csrf_protect
def upload_document():
    user = current_user()
    if user["role"] != "owner":
        audit(user["id"], "authorization.denied", details={"action": "document.upload", "reason": "owner_required"})
        return jsonify(error="owner_required"), 403
    upload = request.files.get("file")
    if upload is None or not upload.filename:
        return jsonify(error="file_required"), 400
    original_name = secure_filename(upload.filename)
    if not original_name or "." not in original_name:
        return jsonify(error="invalid_filename"), 400
    extension = original_name.rsplit(".", 1)[1].lower()
    if extension not in ALLOWED_EXTENSIONS or not file_is_valid(upload, extension):
        audit(user["id"], "document.upload.rejected", details={"filename": original_name, "reason": "type_or_content"})
        return jsonify(error="unsupported_or_invalid_file"), 400
    upload.stream.seek(0, os.SEEK_END)
    size = upload.stream.tell()
    upload.stream.seek(0)
    if size > MAX_UPLOAD_BYTES:
        return jsonify(error="file_too_large"), 413
    title = str(request.form.get("name", original_name)).strip()[:200]
    category = str(request.form.get("category", "Uncategorised")).strip()[:80]
    if not title or not category:
        return jsonify(error="name_and_category_required"), 400
    try:
        expires_at = parse_expiry(request.form.get("expires_at", "").strip())
    except ValueError as error:
        return jsonify(error=str(error)), 400
    document_id = str(uuid.uuid4())
    stored_name = f"{document_id}.{extension}"
    path = UPLOADS / stored_name
    upload.save(path)
    try:
        connection = db()
        connection.execute(
            """INSERT INTO documents
               (id, owner_id, name, category, original_filename, stored_filename, mime_type, size_bytes,
                created_at, updated_at, expires_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (document_id, user["id"], title, category, original_name,
             stored_name, mimetypes.guess_type(original_name)[0] or "application/octet-stream",
             size, now(), now(), expires_at),
        )
        audit(user["id"], "document.uploaded", document_id,
              {"name": title, "category": category, "size": size, "expires_at": expires_at})
    except Exception:
        path.unlink(missing_ok=True)
        raise
    return jsonify(document={"id": document_id, "name": title, "category": category}), 201


@app.get("/api/documents/<document_id>")
@require_auth
def get_document(document_id):
    user = current_user()
    if user["role"] == "admin":
        row = db().execute(
            """SELECT d.*, u.display_name AS owner_name, p.permission
               FROM documents d JOIN users u ON u.id = d.owner_id
               LEFT JOIN permissions p ON p.document_id = d.id AND p.user_id = ?
               WHERE d.id = ? AND d.deleted_at IS NULL
                 AND (d.expires_at IS NULL OR d.expires_at > ?)""",
            (user["id"], document_id, now()),
        ).fetchone()
        if row is None:
            audit(user["id"], "authorization.denied", document_id, {"action": "metadata"})
            abort(404)
        audit(user["id"], "document.metadata_viewed", document_id, {"scope": "admin"})
        permission = row["permission"]
        metadata_only = permission is None
    else:
        row = document_access(document_id)
        permission = row["permission"]
        metadata_only = False
    grants = db().execute(
        """SELECT u.id, u.username, u.display_name, p.permission
           FROM permissions p JOIN users u ON u.id = p.user_id
           WHERE p.document_id = ? ORDER BY u.username""", (document_id,)
    ).fetchall() if row["owner_id"] == user["id"] else []
    details = {key: row[key] for key in
               ("id", "name", "category", "mime_type", "size_bytes", "created_at", "updated_at",
                "expires_at", "owner_name")}
    details["permission"] = permission or ("admin_metadata" if metadata_only else None)
    return jsonify(document=details, grants=[dict(grant) for grant in grants])


@app.get("/api/documents/<document_id>/download")
@require_auth
def download_document(document_id):
    row = document_access(document_id)
    audit(current_user()["id"], "document.downloaded", document_id)
    return send_file(UPLOADS / row["stored_filename"], mimetype=row["mime_type"],
                     as_attachment=True, download_name=row["original_filename"], conditional=True)


@app.post("/api/documents/<document_id>/review")
@require_auth
@csrf_protect
def review_document(document_id):
    row = document_access(document_id)
    user = current_user()
    audit(user["id"], "document.review.started", document_id)
    try:
        text = extract_text(UPLOADS / row["stored_filename"], row["original_filename"])
    except ReviewInputError as error:
        audit(user["id"], "document.review.rejected", document_id, {"reason": str(error)})
        return jsonify(error=str(error)), 415

    report = build_review(text, row, user)
    connection = db()
    connection.execute(
        """INSERT INTO document_reviews
           (id, document_id, reviewer_id, created_at, privacy_score, risk_level, report_json)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (report["id"], document_id, user["id"], report["created_at"],
         report["privacy_score"], report["risk_level"], serialize_review(report)),
    )
    audit(user["id"], "document.review.completed", document_id,
          {"review_id": report["id"], "privacy_score": report["privacy_score"],
           "risk_level": report["risk_level"], "finding_categories": len(report["findings"])})
    return jsonify(report=report), 201


@app.get("/api/documents/<document_id>/review/latest")
@require_auth
def latest_document_review(document_id):
    document_access(document_id)
    user = current_user()
    row = db().execute(
        """SELECT report_json FROM document_reviews
           WHERE document_id = ? AND reviewer_id = ?
           ORDER BY created_at DESC, rowid DESC LIMIT 1""",
        (document_id, user["id"]),
    ).fetchone()
    if row is None:
        return jsonify(error="no_review_found"), 404
    report = json.loads(row["report_json"])
    audit(user["id"], "document.review.report_viewed", document_id,
          {"review_id": report["id"], "format": "json"})
    response = jsonify(report=report)
    response.headers["Cache-Control"] = "private, no-store"
    return response


@app.get("/api/documents/<document_id>/review/latest.pdf")
@require_auth
def download_document_review(document_id):
    document_access(document_id)
    user = current_user()
    row = db().execute(
        """SELECT report_json FROM document_reviews
           WHERE document_id = ? AND reviewer_id = ?
           ORDER BY created_at DESC, rowid DESC LIMIT 1""",
        (document_id, user["id"]),
    ).fetchone()
    if row is None:
        return jsonify(error="no_review_found"), 404
    report = json.loads(row["report_json"])
    audit(user["id"], "document.review.report_downloaded", document_id,
          {"review_id": report["id"], "format": "pdf"})
    output = io.BytesIO()
    render_pdf_report(report, output)
    output.seek(0)
    filename = secure_filename(f"{report['document_name']}-privacy-review.pdf") or "document-review.pdf"
    response = send_file(output, mimetype="application/pdf", as_attachment=True, download_name=filename)
    response.headers["Cache-Control"] = "private, no-store"
    return response


@app.patch("/api/documents/<document_id>")
@require_auth
@csrf_protect
def update_document(document_id):
    row = document_access(document_id, "edit")
    data = json_body()
    name = str(data.get("name", row["name"])).strip()[:200]
    category = str(data.get("category", row["category"])).strip()[:80]
    if not name or not category:
        return jsonify(error="name_and_category_required"), 400
    db().execute("UPDATE documents SET name = ?, category = ?, updated_at = ? WHERE id = ?",
                 (name, category, now(), document_id))
    audit(current_user()["id"], "document.updated", document_id, {"name": name, "category": category})
    return jsonify(ok=True)


@app.delete("/api/documents/<document_id>")
@require_auth
@csrf_protect
def delete_document(document_id):
    row = document_access(document_id, "edit")
    user = current_user()
    if row["owner_id"] != user["id"]:
        abort(404)
    db().execute("UPDATE documents SET deleted_at = ? WHERE id = ?", (now(), document_id))
    audit(user["id"], "document.deleted", document_id)
    return jsonify(ok=True)


@app.get("/api/documents/<document_id>/permissions")
@require_auth
def list_permissions(document_id):
    row = document_access(document_id)
    if row["owner_id"] != current_user()["id"]:
        abort(404)
    grants = db().execute(
        """SELECT u.id, u.username, u.display_name, p.permission, p.created_at
           FROM permissions p JOIN users u ON u.id = p.user_id
           WHERE p.document_id = ? ORDER BY u.username""", (document_id,)
    ).fetchall()
    return jsonify(grants=[dict(grant) for grant in grants])


@app.post("/api/documents/<document_id>/permissions")
@require_auth
@csrf_protect
def grant_permission(document_id):
    row = document_access(document_id, "edit")
    user = current_user()
    if row["owner_id"] != user["id"]:
        abort(404)
    data = json_body()
    username = str(data.get("username", "")).strip().lower()
    permission = data.get("permission")
    target = db().execute("SELECT id, username, display_name, email, role FROM users WHERE username = ?", (username,)).fetchone()
    if target is None or target["id"] == user["id"]:
        return jsonify(error="user_not_found"), 404
    if permission not in {"read", "edit"}:
        return jsonify(error="permission_must_be_read_or_edit"), 400
    db().execute(
        """INSERT INTO permissions(document_id, user_id, permission, granted_by, created_at)
           VALUES (?, ?, ?, ?, ?)
           ON CONFLICT(document_id, user_id) DO UPDATE SET permission = excluded.permission,
             granted_by = excluded.granted_by, created_at = excluded.created_at""",
        (document_id, target["id"], permission, user["id"], now()),
    )
    audit(user["id"], "permission.granted", document_id,
          {"username": username, "permission": permission})
    notify = data.get("notify", False) is True
    notification = {"sent": False, "status": "not_requested"}
    if notify:
        try:
            send_access_email(target, user["display_name"], row["name"], permission)
            audit(user["id"], "permission.email_sent", document_id,
                  {"username": username, "email": target["email"], "permission": permission})
            notification = {"sent": True, "status": "sent"}
        except (OSError, RuntimeError, smtplib.SMTPException, ValueError) as error:
            app.logger.exception("Failed to send access notification for document %s to %s", document_id, username)
            audit(user["id"], "permission.email_failed", document_id,
                  {"username": username, "email": target["email"], "reason": str(error)[:200]})
            notification = {
                "sent": False,
                "status": "failed",
                "error": "Access was granted, but the email could not be sent. Check SMTP settings and recipient email.",
            }
    return jsonify(ok=True, notification=notification), 201


@app.delete("/api/documents/<document_id>/permissions/<username>")
@require_auth
@csrf_protect
def revoke_permission(document_id, username):
    row = document_access(document_id, "edit")
    user = current_user()
    if row["owner_id"] != user["id"]:
        abort(404)
    target = db().execute("SELECT id FROM users WHERE username = ?", (username.lower(),)).fetchone()
    if target is None:
        return jsonify(error="user_not_found"), 404
    db().execute("DELETE FROM permissions WHERE document_id = ? AND user_id = ?", (document_id, target["id"]))
    audit(user["id"], "permission.revoked", document_id, {"username": username.lower()})
    return jsonify(ok=True)


@app.get("/api/admin/audit")
@require_admin
def admin_audit():
    try:
        page = max(1, min(int(request.args.get("page", "1")), 10000))
    except ValueError:
        abort(400, description="Page must be a positive integer.")
    rows = db().execute(
        """SELECT a.sequence, a.occurred_at, a.actor_id, u.username, a.action, a.document_id,
                  a.details, a.previous_hash, a.entry_hash
           FROM audit_events a LEFT JOIN users u ON u.id = a.actor_id
           WHERE a.action != 'session.identity_submitted'
           ORDER BY a.sequence DESC LIMIT 100 OFFSET ?""", ((page - 1) * 100,)
    ).fetchall()
    return jsonify(events=[dict(row) for row in rows], chain_valid=verify_audit_chain())


@app.get("/api/owner/login-activity")
@require_auth
def owner_login_activity():
    user = current_user()
    if user["role"] != "owner":
        audit(user["id"], "authorization.denied", details={"path": request.path, "reason": "owner_required"})
        return jsonify(error="not_found"), 404
    rows = db().execute(
        """SELECT a.occurred_at, u.username AS account_username, u.role, a.details
           FROM audit_events a JOIN users u ON u.id = a.actor_id
           WHERE a.action = 'session.identity_submitted'
             AND u.role IN ('admin', 'viewer')
           ORDER BY a.sequence DESC"""
    ).fetchall()
    entries = []
    for row in rows:
        details = json.loads(row["details"])
        entries.append({
            "occurred_at": row["occurred_at"],
            "account_username": row["account_username"],
            "role": row["role"],
            "self_reported_user_id": details["self_reported_user_id"],
        })
    response = jsonify(entries=entries)
    response.headers["Cache-Control"] = "private, no-store"
    return response


@app.errorhandler(413)
def too_large(_error):
    return jsonify(error="file_too_large"), 413


@app.errorhandler(400)
def bad_request(error):
    return jsonify(error=getattr(error, "description", "bad_request")), 400


@app.errorhandler(404)
def not_found(_error):
    return jsonify(error="not_found"), 404


def seed():
    initialize()
    connection = sqlite3.connect(DATABASE)
    users = [
        ("admin", "Administrator", "admin", "Admin123!", "admin@example.test"),
        ("owner", "Olivia Owner", "owner", "Owner123!", "owner@example.test"),
        ("viewer", "Victor Viewer", "viewer", "Viewer123!", "viewer@example.test"),
        ("outsider", "Oscar Outsider", "viewer", "Outside123!", "outsider@example.test"),
    ]
    for username, display_name, role, password, default_email in users:
        email = os.environ.get(f"TRUSTVAULT_EMAIL_{username.upper()}", default_email).strip().lower()
        connection.execute(
            """INSERT OR IGNORE INTO users(username, display_name, role, password_hash, created_at, email)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (username, display_name, role, generate_password_hash(password), now(), email),
        )
        configured_email = os.environ.get(f"TRUSTVAULT_EMAIL_{username.upper()}")
        if configured_email:
            connection.execute("UPDATE users SET email = ? WHERE username = ?",
                               (configured_email.strip().lower(), username))
        else:
            connection.execute("UPDATE users SET email = COALESCE(email, ?) WHERE username = ?",
                               (default_email, username))
    sample_id = "00000000-0000-4000-8000-000000000001"
    exists = connection.execute("SELECT 1 FROM documents WHERE id = ?", (sample_id,)).fetchone()
    if exists is None:
        owner = connection.execute("SELECT id FROM users WHERE username = 'owner'").fetchone()
        viewer = connection.execute("SELECT id FROM users WHERE username = 'viewer'").fetchone()
        sample_name = "Welcome to TrustVault.txt"
        sample_path = UPLOADS / sample_id
        sample_path.write_text(
            "TrustVault demo document\n\n"
            "This sample demonstrates per-document sharing. "
            "Only its owner and explicitly granted users may download the file.\n",
            encoding="utf-8",
        )
        created = now()
        connection.execute(
            """INSERT INTO documents
               (id, owner_id, name, category, original_filename, stored_filename, mime_type, size_bytes, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (sample_id, owner[0], "Welcome to TrustVault", "Getting Started", sample_name,
             sample_id, "text/plain", sample_path.stat().st_size, created, created),
        )
        connection.execute(
            """INSERT INTO permissions(document_id, user_id, permission, granted_by, created_at)
               VALUES (?, ?, 'read', ?, ?)""",
            (sample_id, viewer[0], owner[0], created),
        )
    connection.commit()
    connection.close()


if __name__ == "__main__":
    if "--seed" in sys.argv:
        seed()
        print("Database initialized. Demo users: admin, owner, viewer, outsider.")
    else:
        initialize()
        with app.app_context():
            purge_expired_documents()
        start_expiry_worker()
        app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "5050")), debug=False)
