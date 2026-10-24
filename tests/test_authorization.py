import io
import json
import os
import tempfile
import unittest
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

import app as trustvault
from document_review import extract_text
from reportlab.pdfgen import canvas


class TrustVaultAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.owner_settings = patch.dict(
            os.environ,
            {"TRUSTVAULT_OWNER_PASSWORD": "ownerpass-test-123"},
        )
        self.owner_settings.start()
        trustvault.DATABASE = root / "test.sqlite3"
        trustvault.UPLOADS = root / "private-files"
        trustvault.UPLOADS.mkdir()
        trustvault.AUDIT_KEY = b"test-only-audit-key"
        trustvault.initialize()
        connection = trustvault.sqlite3.connect(trustvault.DATABASE)
        from werkzeug.security import generate_password_hash
        for username, role, password in [
            ("viewer", "viewer", "viewerpass"),
            ("outsider", "viewer", "outsiderpass"),
            ("admin", "admin", "adminpass"),
        ]:
            connection.execute(
                """INSERT INTO users
                   (username, display_name, role, password_hash, created_at, email, requested_role, account_status)
                   VALUES (?, ?, ?, ?, '2026-10-20', ?, ?, 'active')""",
                (
                    username,
                    username.title(),
                    role,
                    generate_password_hash(password),
                    f"{username}@example.test",
                    role,
                ),
            )
        connection.execute(
            "UPDATE users SET email = ? WHERE username = ?",
            ("owner@example.test", trustvault.OWNER_USERNAME),
        )
        connection.commit()
        connection.close()
        self.client = trustvault.app.test_client()

    def tearDown(self):
        self.temp.cleanup()
        self.owner_settings.stop()

    def login(self, username, password):
        role = {"owner": "owner", "admin": "admin"}.get(username, "viewer")
        username = trustvault.OWNER_USERNAME if username == "owner" else username
        with self.client.session_transaction() as session:
            session["csrf_token"] = "test-csrf"
        response = self.client.post("/api/login", json={"username": username, "password": password, "role": role},
                                    headers={"X-CSRF-Token": "test-csrf"})
        self.assertEqual(response.status_code, 200)
        csrf_token = response.json["csrf_token"]
        if response.json["identity_required"]:
            identity_response = self.client.post(
                "/api/session/user-id",
                json={"user_id": f"self-reported-{username}"},
                headers={"X-CSRF-Token": csrf_token},
            )
            self.assertEqual(identity_response.status_code, 200)
        return csrf_token

    def upload_as_owner(self, expires_at=None):
        self.login("owner", "ownerpass-test-123")
        data = {"name": "Private agreement", "category": "Contracts",
                "file": (io.BytesIO(b"%PDF-1.4\nprivate document"), "agreement.pdf")}
        if expires_at is not None:
            data["expires_at"] = expires_at
        response = self.client.post(
            "/api/documents",
            data=data,
            headers={"X-CSRF-Token": self.csrf()},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 201)
        return response.json["document"]["id"]

    def upload_text_as_owner(self, text):
        self.login("owner", "ownerpass-test-123")
        response = self.client.post(
            "/api/documents",
            data={"name": "Review source", "category": "Test",
                  "file": (io.BytesIO(text.encode("utf-8")), "review-source.txt")},
            headers={"X-CSRF-Token": self.csrf()},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 201)
        return response.json["document"]["id"]

    def csrf(self):
        with self.client.session_transaction() as session:
            return session["csrf_token"]

    def test_public_registration_creates_only_a_viewer_and_can_log_in(self):
        with self.client.session_transaction() as session:
            session["csrf_token"] = "test-csrf"
        response = self.client.post(
            "/api/register",
            json={
                "username": "NewViewer",
                "display_name": "New Viewer",
                "password": "a-long-password-123",
                "password_confirmation": "a-long-password-123",
                "role": "admin",
            },
            headers={"X-CSRF-Token": "test-csrf"},
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json["user"]["role"], "viewer")

        with trustvault.app.app_context():
            account = trustvault.db().execute(
                """SELECT username, display_name, role, password_hash, account_status, requested_role
                   FROM users WHERE username = ?""",
                ("newviewer",),
            ).fetchone()
            self.assertEqual(account["role"], "viewer")
            self.assertEqual(account["account_status"], "active")
            self.assertEqual(account["requested_role"], "viewer")
            self.assertTrue(trustvault.check_password_hash(account["password_hash"], "a-long-password-123"))
            self.assertTrue(trustvault.verify_audit_chain())
            self.assertEqual(
                trustvault.db().execute(
                    "SELECT COUNT(*) FROM permissions WHERE user_id = (SELECT id FROM users WHERE username = ?)",
                    ("newviewer",),
                ).fetchone()[0],
                0,
            )

        login_response = self.client.post(
            "/api/login",
            json={"username": "NEWVIEWER", "password": "a-long-password-123", "role": "viewer"},
            headers={"X-CSRF-Token": "test-csrf"},
        )
        self.assertEqual(login_response.status_code, 200)
        self.assertTrue(login_response.json["identity_required"])

    def test_admin_registration_stays_pending_until_admin_approves(self):
        with self.client.session_transaction() as session:
            session["csrf_token"] = "test-csrf"
        password = "pending-admin-password"
        registration = self.client.post(
            "/api/register",
            json={
                "username": "admin-applicant",
                "display_name": "Admin Applicant",
                "password": password,
                "password_confirmation": password,
                "requested_role": "admin",
                "role": "owner",
            },
            headers={"X-CSRF-Token": "test-csrf"},
        )
        self.assertEqual(registration.status_code, 202)
        self.assertTrue(registration.json["pending_approval"])
        self.assertEqual(registration.json["user"]["role"], "viewer")
        self.assertEqual(registration.json["user"]["account_status"], "pending")

        with trustvault.app.app_context():
            applicant = trustvault.db().execute(
                "SELECT id, role, requested_role, account_status FROM users WHERE username = ?",
                ("admin-applicant",),
            ).fetchone()
            self.assertEqual(
                (applicant["role"], applicant["requested_role"], applicant["account_status"]),
                ("viewer", "admin", "pending"),
            )
            self.assertEqual(
                trustvault.db().execute(
                    "SELECT COUNT(*) FROM permissions WHERE user_id = ?", (applicant["id"],)
                ).fetchone()[0],
                0,
            )

        blocked_login = self.client.post(
            "/api/login",
            json={"username": "admin-applicant", "password": password, "role": "admin"},
            headers={"X-CSRF-Token": "test-csrf"},
        )
        self.assertEqual(blocked_login.status_code, 403)
        self.assertEqual(blocked_login.json["error"], "account_pending_approval")

        admin_client = trustvault.app.test_client()
        with admin_client.session_transaction() as session:
            session["csrf_token"] = "admin-csrf"
        admin_login = admin_client.post(
            "/api/login",
            json={"username": "admin", "password": "adminpass", "role": "admin"},
            headers={"X-CSRF-Token": "admin-csrf"},
        )
        self.assertEqual(admin_login.status_code, 200)
        admin_identity = admin_client.post(
            "/api/session/user-id",
            json={"user_id": "test-admin"},
            headers={"X-CSRF-Token": admin_login.json["csrf_token"]},
        )
        self.assertEqual(admin_identity.status_code, 200)

        requests = admin_client.get("/api/admin/account-requests")
        self.assertEqual(requests.status_code, 200)
        self.assertEqual([item["username"] for item in requests.json["requests"]], ["admin-applicant"])
        request_id = requests.json["requests"][0]["id"]
        approval_url = f"/api/admin/account-requests/{request_id}/approve"
        rejected_csrf = admin_client.post(
            approval_url,
            headers={"X-CSRF-Token": "invalid"},
        )
        self.assertEqual(rejected_csrf.status_code, 403)
        approved = admin_client.post(
            approval_url,
            headers={"X-CSRF-Token": admin_login.json["csrf_token"]},
        )
        self.assertEqual(approved.status_code, 200)

        with trustvault.app.app_context():
            approved_account = trustvault.db().execute(
                "SELECT role, requested_role, account_status, reviewed_by FROM users WHERE id = ?",
                (applicant["id"],),
            ).fetchone()
            self.assertEqual(approved_account["role"], "admin")
            self.assertEqual(approved_account["requested_role"], "admin")
            self.assertEqual(approved_account["account_status"], "active")
            self.assertIsNotNone(approved_account["reviewed_by"])
            self.assertTrue(trustvault.verify_audit_chain())

        approved_login = self.client.post(
            "/api/login",
            json={"username": "admin-applicant", "password": password, "role": "admin"},
            headers={"X-CSRF-Token": "test-csrf"},
        )
        self.assertEqual(approved_login.status_code, 200)
        self.assertTrue(approved_login.json["identity_required"])

    def test_non_admin_cannot_review_admin_account_requests(self):
        self.login("viewer", "viewerpass")
        self.assertEqual(self.client.get("/api/admin/account-requests").status_code, 404)
        response = self.client.post(
            "/api/admin/account-requests/1/approve",
            headers={"X-CSRF-Token": self.csrf()},
        )
        self.assertEqual(response.status_code, 404)

    def test_rejected_admin_request_remains_unable_to_sign_in(self):
        with self.client.session_transaction() as session:
            session["csrf_token"] = "test-csrf"
        password = "rejected-admin-password"
        registration = self.client.post(
            "/api/register",
            json={
                "username": "rejected-admin",
                "display_name": "Rejected Admin",
                "password": password,
                "password_confirmation": password,
                "requested_role": "admin",
            },
            headers={"X-CSRF-Token": "test-csrf"},
        )
        self.assertEqual(registration.status_code, 202)

        admin_client = trustvault.app.test_client()
        with admin_client.session_transaction() as session:
            session["csrf_token"] = "admin-csrf"
        admin_login = admin_client.post(
            "/api/login",
            json={"username": "admin", "password": "adminpass", "role": "admin"},
            headers={"X-CSRF-Token": "admin-csrf"},
        )
        self.assertEqual(admin_login.status_code, 200)
        admin_client.post(
            "/api/session/user-id",
            json={"user_id": "test-admin"},
            headers={"X-CSRF-Token": admin_login.json["csrf_token"]},
        )
        request_id = admin_client.get("/api/admin/account-requests").json["requests"][0]["id"]
        rejected = admin_client.post(
            f"/api/admin/account-requests/{request_id}/reject",
            headers={"X-CSRF-Token": admin_login.json["csrf_token"]},
        )
        self.assertEqual(rejected.status_code, 200)

        blocked_login = self.client.post(
            "/api/login",
            json={"username": "rejected-admin", "password": password, "role": "admin"},
            headers={"X-CSRF-Token": "test-csrf"},
        )
        self.assertEqual(blocked_login.status_code, 403)
        self.assertEqual(blocked_login.json["error"], "account_inactive")

    def test_login_enforces_selected_role_and_single_owner_username(self):
        from werkzeug.security import generate_password_hash

        with trustvault.app.app_context():
            trustvault.db().execute(
                """INSERT INTO users(username, display_name, role, password_hash, created_at)
                   VALUES (?, ?, 'owner', ?, ?)""",
                ("rogueowner", "Rogue Owner", generate_password_hash("rogue-owner-password"), trustvault.now()),
            )
            trustvault.db().commit()
        with self.assertRaisesRegex(ValueError, "Multiple owner accounts"):
            trustvault.initialize()
        with trustvault.app.app_context():
            trustvault.db().execute("DELETE FROM users WHERE username = ?", ("rogueowner",))
            trustvault.db().commit()
        with trustvault.app.app_context():
            self.assertEqual(
                trustvault.db().execute("SELECT COUNT(*) FROM users WHERE role = 'owner'").fetchone()[0],
                1,
            )
        with self.client.session_transaction() as session:
            session["csrf_token"] = "test-csrf"
        headers = {"X-CSRF-Token": "test-csrf"}

        wrong_role = self.client.post(
            "/api/login",
            json={"username": "viewer", "password": "viewerpass", "role": "admin"},
            headers=headers,
        )
        self.assertEqual(wrong_role.status_code, 401)

        wrong_owner_name = self.client.post(
            "/api/login",
            json={"username": "rogueowner", "password": "rogue-owner-password", "role": "owner"},
            headers=headers,
        )
        self.assertEqual(wrong_owner_name.status_code, 401)

        correct_owner = self.client.post(
            "/api/login",
            json={"username": trustvault.OWNER_USERNAME, "password": "ownerpass-test-123", "role": "owner"},
            headers=headers,
        )
        self.assertEqual(correct_owner.status_code, 200)

    def test_registration_rejects_invalid_input_and_duplicate_usernames(self):
        with self.client.session_transaction() as session:
            session["csrf_token"] = "test-csrf"
        headers = {"X-CSRF-Token": "test-csrf"}
        valid = {
            "username": "NewViewer",
            "display_name": "New Viewer",
            "password": "a-long-password-123",
            "password_confirmation": "a-long-password-123",
        }
        invalid_password = {**valid, "username": "ShortPass", "password": "short",
                            "password_confirmation": "short"}
        self.assertEqual(self.client.post("/api/register", json=invalid_password, headers=headers).status_code, 400)
        mismatch = {**valid, "username": "Mismatch", "password_confirmation": "different-password"}
        self.assertEqual(self.client.post("/api/register", json=mismatch, headers=headers).status_code, 400)
        invalid_username = {**valid, "username": "bad username"}
        self.assertEqual(self.client.post("/api/register", json=invalid_username, headers=headers).status_code, 400)
        reserved_username = {**valid, "username": "PRAVALLIKA"}
        reserved_response = self.client.post("/api/register", json=reserved_username, headers=headers)
        self.assertEqual(reserved_response.status_code, 409)

        self.assertEqual(self.client.post("/api/register", json=valid, headers=headers).status_code, 201)
        duplicate = {**valid, "username": "NEWVIEWER"}
        duplicate_response = self.client.post("/api/register", json=duplicate, headers=headers)
        self.assertEqual(duplicate_response.status_code, 409)

    def test_owner_configuration_can_rename_the_existing_owner_once(self):
        with trustvault.app.app_context():
            trustvault.db().execute(
                "UPDATE users SET username = ?, display_name = ? WHERE role = 'owner'",
                ("old-owner", "Old Owner"),
            )
            trustvault.db().commit()
        with patch.dict(
            os.environ,
            {"TRUSTVAULT_OWNER_PASSWORD": "private-owner-password"},
        ):
            trustvault.initialize()
            with trustvault.app.app_context():
                owners = trustvault.db().execute(
                    "SELECT username, display_name, password_hash FROM users WHERE role = 'owner'"
                ).fetchall()
                self.assertEqual(len(owners), 1)
                self.assertEqual(owners[0]["username"], "pravallika")
                self.assertEqual(owners[0]["display_name"], "Pravallika")
                self.assertTrue(
                    trustvault.check_password_hash(owners[0]["password_hash"], "private-owner-password")
                )

    def test_rotating_owner_password_invalidates_existing_owner_session(self):
        self.login("owner", "ownerpass-test-123")
        self.assertEqual(self.client.get("/api/me").status_code, 200)

        with patch.dict(
            os.environ,
            {"TRUSTVAULT_OWNER_PASSWORD": "rotated-owner-password"},
        ):
            trustvault.initialize()

        self.assertEqual(self.client.get("/api/me").status_code, 401)
        with self.client.session_transaction() as session:
            session["csrf_token"] = "test-csrf"
        old_password = self.client.post(
            "/api/login",
            json={"username": trustvault.OWNER_USERNAME, "password": "ownerpass-test-123", "role": "owner"},
            headers={"X-CSRF-Token": "test-csrf"},
        )
        self.assertEqual(old_password.status_code, 401)
        new_password = self.client.post(
            "/api/login",
            json={"username": trustvault.OWNER_USERNAME, "password": "rotated-owner-password", "role": "owner"},
            headers={"X-CSRF-Token": "test-csrf"},
        )
        self.assertEqual(new_password.status_code, 200)

    def test_registration_requires_csrf_token(self):
        response = self.client.post(
            "/api/register",
            json={"username": "NewViewer", "display_name": "New Viewer",
                  "password": "a-long-password-123", "password_confirmation": "a-long-password-123"},
        )
        self.assertEqual(response.status_code, 403)

    def test_sign_in_displays_role_selection_and_dedicated_owner_login(self):
        login_page = self.client.get("/")
        self.assertIn(b'name="role" value="admin"', login_page.data)
        self.assertIn(b'name="role" value="viewer"', login_page.data)
        self.assertIn(b'name="role" value="owner"', login_page.data)

        owner_page = self.client.get("/owner-login")
        self.assertEqual(owner_page.status_code, 200)
        self.assertIn(b'value="pravallika"', owner_page.data)
        self.assertIn(b'name="role" value="owner"', owner_page.data)

        registration_page = self.client.get("/register")
        self.assertIn(b'name="requested_role" value="viewer"', registration_page.data)
        self.assertIn(b'name="requested_role" value="admin"', registration_page.data)
        self.assertIn(b"Requires approval from an existing administrator", registration_page.data)

    def test_authenticated_user_cannot_create_an_additional_account(self):
        self.login("owner", "ownerpass-test-123")
        response = self.client.post(
            "/api/register",
            json={"username": "NewViewer", "display_name": "New Viewer",
                  "password": "a-long-password-123", "password_confirmation": "a-long-password-123"},
            headers={"X-CSRF-Token": self.csrf()},
        )
        self.assertEqual(response.status_code, 409)

    def test_ungranted_user_cannot_list_read_download_edit_or_delete(self):
        document_id = self.upload_as_owner()
        self.login("outsider", "outsiderpass")
        self.assertEqual(self.client.get("/api/documents").json["documents"], [])
        self.assertEqual(self.client.get(f"/api/documents/{document_id}").status_code, 404)
        self.assertEqual(self.client.get(f"/api/documents/{document_id}/download").status_code, 404)
        self.assertEqual(self.client.patch(f"/api/documents/{document_id}", json={"name": "Stolen"},
                                           headers={"X-CSRF-Token": self.csrf()}).status_code, 404)
        self.assertEqual(self.client.delete(f"/api/documents/{document_id}",
                                            headers={"X-CSRF-Token": self.csrf()}).status_code, 404)
        self.assertTrue(any(event["action"] == "authorization.denied" for event in self._audit_events()))

    def test_upload_stores_future_expiry_in_utc_and_returns_it_in_listing(self):
        expiry = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(timespec="seconds")
        document_id = self.upload_as_owner(expiry)
        row = self._document(document_id)
        self.assertEqual(row["expires_at"], expiry)
        listed = self.client.get("/api/documents").json["documents"]
        self.assertEqual(listed[0]["expires_at"], expiry)

    def test_expired_upload_is_rejected(self):
        past = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(timespec="seconds")
        self.login("owner", "ownerpass-test-123")
        response = self.client.post(
            "/api/documents",
            data={"name": "Already expired", "category": "Test", "expires_at": past,
                  "file": (io.BytesIO(b"%PDF-1.4\nprivate document"), "expired.pdf")},
            headers={"X-CSRF-Token": self.csrf()},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json["error"], "Expiry must be in the future.")

    def test_expiry_purges_file_document_grants_and_reviews_and_audits_it(self):
        document_id = self.upload_as_owner()
        grant = self.client.post(
            f"/api/documents/{document_id}/permissions",
            json={"username": "viewer", "permission": "read"},
            headers={"X-CSRF-Token": self.csrf()},
        )
        self.assertEqual(grant.status_code, 201)
        stored_name = self._document(document_id)["stored_filename"]
        stored_file = trustvault.UPLOADS / stored_name
        self.assertTrue(stored_file.exists())

        connection = trustvault.sqlite3.connect(trustvault.DATABASE)
        owner_id = connection.execute(
            "SELECT owner_id FROM documents WHERE id = ?", (document_id,)
        ).fetchone()[0]
        connection.execute(
            """INSERT INTO document_reviews
               (id, document_id, reviewer_id, created_at, privacy_score, risk_level, report_json)
               VALUES ('expiry-review', ?, ?, ?, 50, 'moderate', '{}')""",
            (document_id, owner_id, trustvault.now()),
        )
        connection.execute(
            "UPDATE documents SET expires_at = ? WHERE id = ?",
            ((datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(timespec="seconds"), document_id),
        )
        connection.commit()
        connection.close()

        self.login("viewer", "viewerpass")
        response = self.client.get(f"/api/documents/{document_id}/download")
        self.assertEqual(response.status_code, 404)
        self.assertFalse(stored_file.exists())
        self.assertIsNone(self._document(document_id))
        self.assertEqual(self._permissions(document_id), [])
        self.assertEqual(self._reviews(document_id), [])
        self.assertTrue(any(
            event["action"] == "document.expired_and_purged" and event["document_id"] == document_id
            for event in self._audit_events()
        ))

    def test_viewer_and_admin_must_submit_user_id_before_entering_workspace(self):
        for username, password, role in [
            ("viewer", "viewerpass", "viewer"),
            ("admin", "adminpass", "admin"),
        ]:
            with self.subTest(role=role):
                client = trustvault.app.test_client()
                with client.session_transaction() as session:
                    session["csrf_token"] = "test-csrf"
                login = client.post(
                    "/api/login",
                    json={"username": username, "password": password},
                    headers={"X-CSRF-Token": "test-csrf"},
                )
                self.assertEqual(login.status_code, 200)
                self.assertTrue(login.json["identity_required"])
                workspace = client.get("/")
                self.assertIn(b"Enter your User ID", workspace.data)
                blocked = client.get("/api/documents")
                self.assertEqual(blocked.status_code, 403)
                self.assertEqual(blocked.json["error"], "identity_required")
                invalid_id = client.post(
                    "/api/session/user-id",
                    json={"user_id": " "},
                    headers={"X-CSRF-Token": login.json["csrf_token"]},
                )
                self.assertEqual(invalid_id.status_code, 400)
                self.assertEqual(client.get("/api/documents").status_code, 403)

                submitted_id = f"candidate-{role}-123"
                submit = client.post(
                    "/api/session/user-id",
                    json={"user_id": submitted_id},
                    headers={"X-CSRF-Token": login.json["csrf_token"]},
                )
                self.assertEqual(submit.status_code, 200)
                self.assertEqual(client.get("/api/documents").status_code, 200)
                if role == "admin":
                    admin_audit = client.get("/api/admin/audit")
                    self.assertEqual(admin_audit.status_code, 200)
                    self.assertTrue(admin_audit.json["chain_valid"])
                    self.assertNotIn(
                        "session.identity_submitted",
                        [event["action"] for event in admin_audit.json["events"]],
                    )

                owner_client = trustvault.app.test_client()
                with owner_client.session_transaction() as session:
                    session["csrf_token"] = "owner-csrf"
                owner_login = owner_client.post(
                    "/api/login",
                    json={"username": trustvault.OWNER_USERNAME, "password": "ownerpass-test-123"},
                    headers={"X-CSRF-Token": "owner-csrf"},
                )
                self.assertFalse(owner_login.json["identity_required"])
                activity = owner_client.get("/api/owner/login-activity")
                self.assertEqual(activity.status_code, 200)
                self.assertTrue(any(
                    entry["self_reported_user_id"] == submitted_id
                    and entry["role"] == role
                    and entry["username"] == username
                    for entry in activity.json["entries"]
                ))

    def test_owner_login_activity_includes_authenticated_username_before_id_submission(self):
        viewer = trustvault.app.test_client()
        with viewer.session_transaction() as session:
            session["csrf_token"] = "viewer-csrf"
        login = viewer.post(
            "/api/login",
            json={"username": "viewer", "password": "viewerpass"},
            headers={"X-CSRF-Token": "viewer-csrf"},
        )
        self.assertEqual(login.status_code, 200)
        self.assertTrue(login.json["identity_required"])

        owner = trustvault.app.test_client()
        with owner.session_transaction() as session:
            session["csrf_token"] = "owner-csrf"
        self.assertEqual(owner.post(
            "/api/login",
            json={"username": trustvault.OWNER_USERNAME, "password": "ownerpass-test-123"},
            headers={"X-CSRF-Token": "owner-csrf"},
        ).status_code, 200)
        activity = owner.get("/api/owner/login-activity")
        viewer_login = next(
            entry for entry in activity.json["entries"]
            if entry["username"] == "viewer"
        )
        self.assertEqual(viewer_login["role"], "viewer")
        self.assertIsNone(viewer_login["self_reported_user_id"])

    def test_owner_login_activity_is_not_available_to_viewer_or_admin(self):
        for username, password in [("viewer", "viewerpass"), ("admin", "adminpass")]:
            with self.subTest(username=username):
                client = trustvault.app.test_client()
                with client.session_transaction() as session:
                    session["csrf_token"] = "test-csrf"
                login = client.post("/api/login", json={"username": username, "password": password},
                                    headers={"X-CSRF-Token": "test-csrf"})
                self.assertEqual(login.status_code, 200)
                if login.json["identity_required"]:
                    self.assertEqual(client.post(
                        "/api/session/user-id",
                        json={"user_id": f"self-reported-{username}"},
                        headers={"X-CSRF-Token": login.json["csrf_token"]},
                    ).status_code, 200)
                self.assertEqual(client.get("/api/owner/login-activity").status_code, 404)
                self.assertEqual(client.get("/api/owner/dashboard").status_code, 404)

    def test_owner_dashboard_shows_owned_document_shares_expiry_and_activity(self):
        expiry = (datetime.now(timezone.utc) + timedelta(days=3)).isoformat(timespec="seconds")
        document_id = self.upload_as_owner(expiry)
        grant = self.client.post(
            f"/api/documents/{document_id}/permissions",
            json={"username": "viewer", "permission": "read"},
            headers={"X-CSRF-Token": self.csrf()},
        )
        self.assertEqual(grant.status_code, 201)

        response = self.client.get("/api/owner/dashboard")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["Cache-Control"], "private, no-store")
        self.assertEqual(response.json["stats"], {
            "total_documents": 1,
            "shared_documents": 1,
            "active_grants": 1,
            "expiring_soon": 1,
        })
        self.assertTrue(any(
            event["document_id"] == document_id and event["action"] == "permission.granted"
            for event in response.json["recent_activity"]
        ))

    def test_owner_dashboard_does_not_include_another_owners_documents(self):
        own_document_id = self.upload_as_owner()
        connection = trustvault.sqlite3.connect(trustvault.DATABASE)
        from werkzeug.security import generate_password_hash
        connection.execute(
            """INSERT INTO users(username, display_name, role, password_hash, created_at, email)
               VALUES ('second-owner', 'Second Owner', 'owner', ?, ?, 'second@example.test')""",
            (generate_password_hash("secondpass"), trustvault.now()),
        )
        second_owner_id = connection.execute(
            "SELECT id FROM users WHERE username = 'second-owner'"
        ).fetchone()[0]
        other_document_id = "another-owners-document"
        connection.execute(
            """INSERT INTO documents
               (id, owner_id, name, category, original_filename, stored_filename, mime_type,
                size_bytes, created_at, updated_at)
               VALUES (?, ?, 'Private other', 'Other', 'other.txt', 'other.txt',
                       'text/plain', 10, ?, ?)""",
            (other_document_id, second_owner_id, trustvault.now(), trustvault.now()),
        )
        connection.commit()
        connection.close()

        response = self.client.get("/api/owner/dashboard")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["stats"]["total_documents"], 1)
        self.assertTrue(all(
            event["document_id"] != other_document_id
            for event in response.json["recent_activity"]
        ))
        self.assertTrue(any(
            event["document_id"] == own_document_id
            for event in response.json["recent_activity"]
        ))

    def test_granted_viewer_can_download_but_cannot_change_or_grant(self):
        document_id = self.upload_as_owner()
        self.assertEqual(self.client.post(
            f"/api/documents/{document_id}/permissions",
            json={"username": "viewer", "permission": "read"},
            headers={"X-CSRF-Token": self.csrf()},
        ).status_code, 201)
        self.login("viewer", "viewerpass")
        response = self.client.get(f"/api/documents/{document_id}/download")
        self.assertEqual(response.status_code, 200)
        response.close()
        self.assertEqual(self.client.patch(f"/api/documents/{document_id}", json={"name": "Changed"},
                                           headers={"X-CSRF-Token": self.csrf()}).status_code, 404)
        self.assertEqual(self.client.post(f"/api/documents/{document_id}/permissions",
                                          json={"username": "outsider", "permission": "read"},
                                          headers={"X-CSRF-Token": self.csrf()}).status_code, 404)

    def test_grant_sends_email_to_registered_recipient_without_sharing_a_link(self):
        document_id = self.upload_as_owner()
        with patch.object(trustvault, "send_access_email") as send_email:
            response = self.client.post(
                f"/api/documents/{document_id}/permissions",
                json={"username": "viewer", "permission": "read", "notify": True},
                headers={"X-CSRF-Token": self.csrf()},
            )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json["notification"], {"sent": True, "status": "sent"})
        recipient, owner_name, document_name, permission = send_email.call_args.args
        self.assertEqual(recipient["email"], "viewer@example.test")
        self.assertEqual((owner_name, document_name, permission), ("Pravallika", "Private agreement", "read"))
        actions = [event["action"] for event in self._audit_events()]
        self.assertIn("permission.granted", actions)
        self.assertIn("permission.email_sent", actions)

    def test_notification_email_contains_no_file_attachment_or_bearer_url(self):
        smtp_server = Mock()
        smtp_context = Mock()
        smtp_context.__enter__ = Mock(return_value=smtp_server)
        smtp_context.__exit__ = Mock(return_value=False)
        with patch.dict(os.environ, {
            "TRUSTVAULT_SMTP_HOST": "smtp.example.test",
            "TRUSTVAULT_SMTP_PORT": "587",
            "TRUSTVAULT_SMTP_FROM": "vault@example.test",
            "TRUSTVAULT_SMTP_USERNAME": "smtp-user",
            "TRUSTVAULT_SMTP_PASSWORD": "test-secret",
            "TRUSTVAULT_SMTP_STARTTLS": "1",
            "TRUSTVAULT_BASE_URL": "https://vault.example.test",
        }), patch.object(trustvault.smtplib, "SMTP", return_value=smtp_context):
            trustvault.send_access_email(
                {"email": "viewer@company.com", "display_name": "Viewer"},
                "Owner",
                "Private agreement",
                "read",
            )
        message = smtp_server.send_message.call_args.args[0]
        self.assertEqual(message["To"], "viewer@company.com")
        self.assertIn("read access", message.get_content())
        self.assertIn("https://vault.example.test", message.get_content())
        self.assertNotIn("/api/documents/", message.get_content())
        self.assertFalse(list(message.iter_attachments()))
        smtp_server.starttls.assert_called_once()
        smtp_server.login.assert_called_once_with("smtp-user", "test-secret")

    def test_existing_database_is_migrated_with_email_and_expiry_columns(self):
        legacy_database = Path(self.temp.name) / "legacy.sqlite3"
        connection = trustvault.sqlite3.connect(legacy_database)
        connection.execute(
            """CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                display_name TEXT NOT NULL,
                role TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )"""
        )
        connection.commit()
        connection.close()
        original_database = trustvault.DATABASE
        try:
            trustvault.DATABASE = legacy_database
            trustvault.initialize()
            migrated = trustvault.sqlite3.connect(legacy_database)
            try:
                columns = {row[1] for row in migrated.execute("PRAGMA table_info(users)")}
                document_columns = {row[1] for row in migrated.execute("PRAGMA table_info(documents)")}
            finally:
                migrated.close()
            self.assertIn("email", columns)
            self.assertIn("expires_at", document_columns)
        finally:
            trustvault.DATABASE = original_database

    def test_document_review_detects_and_redacts_sensitive_values(self):
        document_id = self.upload_text_as_owner(
            "Contact jane.doe@example.com or +1 555 123 4567. "
            "password=supersecretvalue. SSN: 123-45-6789."
        )
        response = self.client.post(
            f"/api/documents/{document_id}/review",
            json={},
            headers={"X-CSRF-Token": self.csrf()},
        )
        self.assertEqual(response.status_code, 201)
        report = response.json["report"]
        self.assertEqual(report["privacy_score"], 0)
        finding_codes = {item["code"] for item in report["findings"]}
        self.assertTrue({"credential", "government_id", "email", "phone"} <= finding_codes)
        serialized = json.dumps(report)
        self.assertNotIn("jane.doe@example.com", serialized)
        self.assertNotIn("supersecretvalue", serialized)
        self.assertNotIn("123-45-6789", serialized)
        self.assertIn("***", serialized)

        latest = self.client.get(f"/api/documents/{document_id}/review/latest")
        self.assertEqual(latest.status_code, 200)
        self.assertEqual(latest.json["report"]["id"], report["id"])
        pdf = self.client.get(f"/api/documents/{document_id}/review/latest.pdf")
        self.assertEqual(pdf.status_code, 200)
        self.assertTrue(pdf.data.startswith(b"%PDF-"))
        from pypdf import PdfReader
        self.assertGreaterEqual(len(PdfReader(io.BytesIO(pdf.data)).pages), 1)
        pdf.close()
        with trustvault.app.app_context():
            self.assertTrue(trustvault.verify_audit_chain())

    def test_review_extracts_text_from_pdf_and_docx(self):
        pdf_path = Path(self.temp.name) / "source.pdf"
        pdf_buffer = io.BytesIO()
        pdf = canvas.Canvas(pdf_buffer)
        pdf.drawString(72, 720, "PDF review@example.com")
        pdf.save()
        pdf_path.write_bytes(pdf_buffer.getvalue())
        self.assertIn("review@example.com", extract_text(pdf_path, "source.pdf"))

        docx_path = Path(self.temp.name) / "source.docx"
        document_xml = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            '<w:body><w:p><w:r><w:t>DOCX review@example.com</w:t></w:r></w:p></w:body></w:document>'
        )
        with zipfile.ZipFile(docx_path, "w") as archive:
            archive.writestr("word/document.xml", document_xml)
        self.assertIn("review@example.com", extract_text(docx_path, "source.docx"))

    def test_review_routes_require_current_document_grant_and_are_user_scoped(self):
        document_id = self.upload_text_as_owner("A document with no supported sensitive patterns.")
        owner_review = self.client.post(
            f"/api/documents/{document_id}/review", json={},
            headers={"X-CSRF-Token": self.csrf()},
        )
        self.assertEqual(owner_review.status_code, 201)

        self.login("outsider", "outsiderpass")
        self.assertEqual(self.client.post(
            f"/api/documents/{document_id}/review", json={},
            headers={"X-CSRF-Token": self.csrf()},
        ).status_code, 404)
        self.assertEqual(self.client.get(f"/api/documents/{document_id}/review/latest").status_code, 404)
        self.assertEqual(self.client.get(f"/api/documents/{document_id}/review/latest.pdf").status_code, 404)

        self.login("owner", "ownerpass-test-123")
        self.client.post(
            f"/api/documents/{document_id}/permissions",
            json={"username": "viewer", "permission": "read", "notify": False},
            headers={"X-CSRF-Token": self.csrf()},
        )
        self.login("viewer", "viewerpass")
        self.assertEqual(self.client.get(f"/api/documents/{document_id}/review/latest").status_code, 404)
        viewer_review = self.client.post(
            f"/api/documents/{document_id}/review", json={},
            headers={"X-CSRF-Token": self.csrf()},
        )
        self.assertEqual(viewer_review.status_code, 201)
        self.assertEqual(self.client.get(f"/api/documents/{document_id}/review/latest").json["report"]["reviewed_by"], "Viewer")
        self.login("owner", "ownerpass-test-123")
        self.client.delete(
            f"/api/documents/{document_id}/permissions/viewer",
            headers={"X-CSRF-Token": self.csrf()},
        )
        self.login("viewer", "viewerpass")
        self.assertEqual(self.client.get(f"/api/documents/{document_id}/review/latest").status_code, 404)

    def test_mail_failure_is_reported_but_does_not_undo_the_explicit_grant(self):
        document_id = self.upload_as_owner()
        with patch.object(trustvault, "send_access_email", side_effect=OSError("SMTP unavailable")):
            with self.assertLogs(trustvault.app.logger, level="ERROR"):
                response = self.client.post(
                    f"/api/documents/{document_id}/permissions",
                    json={"username": "viewer", "permission": "edit", "notify": True},
                    headers={"X-CSRF-Token": self.csrf()},
                )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json["notification"]["status"], "failed")
        self.login("viewer", "viewerpass")
        download = self.client.get(f"/api/documents/{document_id}/download")
        self.assertEqual(download.status_code, 200)
        download.close()
        self.assertIn("permission.email_failed", [event["action"] for event in self._audit_events()])

    def test_revocation_takes_effect_on_the_next_download(self):
        document_id = self.upload_as_owner()
        self.client.post(f"/api/documents/{document_id}/permissions",
                         json={"username": "viewer", "permission": "read"},
                         headers={"X-CSRF-Token": self.csrf()})
        self.login("viewer", "viewerpass")
        response = self.client.get(f"/api/documents/{document_id}/download")
        self.assertEqual(response.status_code, 200)
        response.close()
        self.login("owner", "ownerpass-test-123")
        self.assertEqual(self.client.delete(f"/api/documents/{document_id}/permissions/viewer",
                                            headers={"X-CSRF-Token": self.csrf()}).status_code, 200)
        self.login("viewer", "viewerpass")
        self.assertEqual(self.client.get(f"/api/documents/{document_id}/download").status_code, 404)
        self.assertEqual(self.client.post(
            f"/api/documents/{document_id}/review", json={},
            headers={"X-CSRF-Token": self.csrf()},
        ).status_code, 404)

    def test_admin_audit_is_available_but_admin_does_not_get_document_access(self):
        document_id = self.upload_as_owner()
        self.login("admin", "adminpass")
        audit_response = self.client.get("/api/admin/audit")
        self.assertEqual(audit_response.status_code, 200)
        self.assertTrue(audit_response.json["chain_valid"])
        self.assertEqual(self.client.get("/api/documents").json["documents"][0]["id"], document_id)
        metadata = self.client.get(f"/api/documents/{document_id}")
        self.assertEqual(metadata.status_code, 200)
        self.assertEqual(metadata.json["document"]["permission"], "admin_metadata")
        self.assertEqual(self.client.get(f"/api/documents/{document_id}/download").status_code, 404)
        self.assertEqual(self.client.post(
            f"/api/documents/{document_id}/review", json={},
            headers={"X-CSRF-Token": self.csrf()},
        ).status_code, 404)

    def test_browser_logout_clears_session(self):
        self.login("admin", "adminpass")
        response = self.client.post("/logout", data={"csrf_token": self.csrf()})
        self.assertEqual(response.status_code, 303)
        self.assertEqual(self.client.get("/api/me").status_code, 401)

    def test_public_health_endpoint_checks_database(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, {"status": "ok"})

    def test_viewer_cannot_upload_or_enumerate_recipients(self):
        self.login("viewer", "viewerpass")
        response = self.client.post(
            "/api/documents",
            data={"file": (io.BytesIO(b"%PDF-1.4\nvalid"), "viewer.pdf")},
            headers={"X-CSRF-Token": self.csrf()},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.client.get("/api/users").status_code, 404)

    def test_invalid_upload_is_rejected(self):
        self.login("owner", "ownerpass-test-123")
        response = self.client.post("/api/documents",
                                    data={"file": (io.BytesIO(b"not a pdf"), "fake.pdf")},
                                    headers={"X-CSRF-Token": self.csrf()},
                                    content_type="multipart/form-data")
        self.assertEqual(response.status_code, 400)

    def test_audit_chain_verifies_and_database_rejects_mutation(self):
        self.login("owner", "ownerpass-test-123")
        with trustvault.app.app_context():
            self.assertTrue(trustvault.verify_audit_chain())
            with self.assertRaises(trustvault.sqlite3.IntegrityError):
                trustvault.db().execute("UPDATE audit_events SET action = 'changed' WHERE sequence = 1")
            self.assertTrue(trustvault.verify_audit_chain())

    def _audit_events(self):
        with trustvault.app.app_context():
            return [dict(row) for row in trustvault.db().execute("SELECT * FROM audit_events")]

    def _document(self, document_id):
        connection = trustvault.sqlite3.connect(trustvault.DATABASE)
        connection.row_factory = trustvault.sqlite3.Row
        row = connection.execute("SELECT * FROM documents WHERE id = ?", (document_id,)).fetchone()
        connection.close()
        return dict(row) if row else None

    def _permissions(self, document_id):
        connection = trustvault.sqlite3.connect(trustvault.DATABASE)
        connection.row_factory = trustvault.sqlite3.Row
        rows = connection.execute(
            "SELECT * FROM permissions WHERE document_id = ?", (document_id,)
        ).fetchall()
        connection.close()
        return [dict(row) for row in rows]

    def _reviews(self, document_id):
        connection = trustvault.sqlite3.connect(trustvault.DATABASE)
        rows = connection.execute(
            "SELECT id FROM document_reviews WHERE document_id = ?", (document_id,)
        ).fetchall()
        connection.close()
        return rows


if __name__ == "__main__":
    unittest.main()
