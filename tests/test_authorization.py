import io
import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import Mock, patch

import app as trustvault
from document_review import extract_text
from reportlab.pdfgen import canvas


class TrustVaultAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        trustvault.DATABASE = root / "test.sqlite3"
        trustvault.UPLOADS = root / "private-files"
        trustvault.UPLOADS.mkdir()
        trustvault.AUDIT_KEY = b"test-only-audit-key"
        trustvault.initialize()
        connection = trustvault.sqlite3.connect(trustvault.DATABASE)
        from werkzeug.security import generate_password_hash
        for username, role, password in [
            ("owner", "owner", "ownerpass"),
            ("viewer", "viewer", "viewerpass"),
            ("outsider", "viewer", "outsiderpass"),
            ("admin", "admin", "adminpass"),
        ]:
            connection.execute(
                """INSERT INTO users(username, display_name, role, password_hash, created_at, email)
                   VALUES (?, ?, ?, ?, '2026-10-20', ?)""",
                (username, username.title(), role, generate_password_hash(password), f"{username}@example.test"),
            )
        connection.commit()
        connection.close()
        self.client = trustvault.app.test_client()

    def tearDown(self):
        self.temp.cleanup()

    def login(self, username, password):
        with self.client.session_transaction() as session:
            session["csrf_token"] = "test-csrf"
        response = self.client.post("/api/login", json={"username": username, "password": password},
                                    headers={"X-CSRF-Token": "test-csrf"})
        self.assertEqual(response.status_code, 200)
        return response.json["csrf_token"]

    def upload_as_owner(self):
        self.login("owner", "ownerpass")
        response = self.client.post(
            "/api/documents",
            data={"name": "Private agreement", "category": "Contracts",
                  "file": (io.BytesIO(b"%PDF-1.4\nprivate document"), "agreement.pdf")},
            headers={"X-CSRF-Token": self.csrf()},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 201)
        return response.json["document"]["id"]

    def upload_text_as_owner(self, text):
        self.login("owner", "ownerpass")
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
        self.assertEqual((owner_name, document_name, permission), ("Owner", "Private agreement", "read"))
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

    def test_existing_database_is_migrated_with_email_column(self):
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
            finally:
                migrated.close()
            self.assertIn("email", columns)
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

        self.login("owner", "ownerpass")
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
        self.login("owner", "ownerpass")
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
        self.login("owner", "ownerpass")
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
        self.login("owner", "ownerpass")
        response = self.client.post("/api/documents",
                                    data={"file": (io.BytesIO(b"not a pdf"), "fake.pdf")},
                                    headers={"X-CSRF-Token": self.csrf()},
                                    content_type="multipart/form-data")
        self.assertEqual(response.status_code, 400)

    def test_audit_chain_verifies_and_database_rejects_mutation(self):
        self.login("owner", "ownerpass")
        with trustvault.app.app_context():
            self.assertTrue(trustvault.verify_audit_chain())
            with self.assertRaises(trustvault.sqlite3.IntegrityError):
                trustvault.db().execute("UPDATE audit_events SET action = 'changed' WHERE sequence = 1")
            self.assertTrue(trustvault.verify_audit_chain())

    def _audit_events(self):
        with trustvault.app.app_context():
            return [dict(row) for row in trustvault.db().execute("SELECT * FROM audit_events")]


if __name__ == "__main__":
    unittest.main()
