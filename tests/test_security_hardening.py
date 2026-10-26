import base64
import os
import tempfile
import unittest
import uuid
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from sutra_net.api.server import app
from sutra_net.storage.query_engine import ForensicQueryEngine
from sutra_net.compliance import bsa_section63 as cert_module
from sutra_net.compliance.bsa_section63 import BSASection63Certificate


TEST_USERNAME = "sutra-test"
TEST_PASSWORD = "test-only-password"

AUTH_HEADERS = {
    "Authorization": "Basic " + base64.b64encode(
        f"{TEST_USERNAME}:{TEST_PASSWORD}".encode()
    ).decode()
}

TEST_ENV = {
    "SUTRA_AUTH_USERNAME": TEST_USERNAME,
    "SUTRA_AUTH_PASSWORD": TEST_PASSWORD,
}


@contextmanager
def authenticated_client():
    with patch.dict(os.environ, TEST_ENV):
        with TestClient(app) as client:
            yield client


class TestSecurityHardening(unittest.TestCase):

    def test_static_assets_load_without_auth(self):
        with patch.dict(os.environ, TEST_ENV):
            with TestClient(app) as client:
                response = client.get("/static/app.js")

        self.assertEqual(response.status_code, 200)

    def test_authentication_is_required(self):
        with patch.dict(os.environ, TEST_ENV):
            with TestClient(app) as client:
                response = client.get("/api/graph")

        self.assertEqual(response.status_code, 401)
        self.assertIn("Basic", response.headers["www-authenticate"])

    def test_wrong_credentials_are_rejected(self):
        wrong = {
            "Authorization": "Basic " + base64.b64encode(
                b"wrong-user:wrong-password"
            ).decode()
        }

        with patch.dict(os.environ, TEST_ENV):
            with TestClient(app) as client:
                response = client.get("/", headers=wrong)

        self.assertEqual(response.status_code, 401)

    def test_missing_auth_configuration_fails_closed(self):
        with patch.dict(
            os.environ,
            {"SUTRA_AUTH_USERNAME": "", "SUTRA_AUTH_PASSWORD": ""},
        ):
            with TestClient(app) as client:
                response = client.get("/")

        self.assertEqual(response.status_code, 503)

    def test_valid_credentials_open_dashboard(self):
        with authenticated_client() as client:
            response = client.get("/", headers=AUTH_HEADERS)

        self.assertEqual(response.status_code, 200)

    def test_arbitrary_sql_is_disabled(self):
        engine = ForensicQueryEngine()
        result = engine.execute_sql("SELECT 1")
        self.assertFalse(result["success"])

    def test_unknown_saved_query_is_rejected(self):
        engine = ForensicQueryEngine()
        result = engine.run_saved_query("invalid_query_id")
        self.assertFalse(result["success"])

    def test_api_rejects_raw_sql_payload(self):
        with authenticated_client() as client:
            response = client.post(
                "/api/query/sql",
                json={"query": "SELECT 1"},
                headers=AUTH_HEADERS,
            )

        self.assertEqual(response.status_code, 422)

    def test_pdf_path_traversal_is_rejected(self):
        with authenticated_client() as client:
            response = client.get(
                "/api/compliance/download_pdf",
                params={"path": "../../sutra_net/config.py"},
                headers=AUTH_HEADERS,
            )

        self.assertEqual(response.status_code, 404)

    def test_certificate_requires_acquisition_record(self):
        case_id = "SECURITY-TEST-" + uuid.uuid4().hex[:12]

        with authenticated_client() as client:
            response = client.post(
                "/api/compliance/certificate",
                json={
                    "case_id": case_id,
                    "examiner_name": "Security Test Examiner",
                    "agency_name": "Local Security Test",
                    "artifact_name": "sample_network.pcap",
                },
                headers=AUTH_HEADERS,
            )

        self.assertEqual(response.status_code, 409)

    def test_certificate_escapes_untrusted_paragraph_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            generator = BSASection63Certificate(output_dir=Path(tmp))
            original_paragraph = cert_module.Paragraph
            captured = []

            def recording_paragraph(text, style, *args, **kwargs):
                captured.append(str(text))
                return original_paragraph(text, style, *args, **kwargs)

            manifest = {
                "filename": "evidence<script>.pcap",
                "file_size_bytes": 100,
                "hashes": {
                    "sha256": "abc<script>",
                    "sha3_256": "def&ghi",
                },
                "acquired_utc": "2026-10-26T00:00:00Z",
            }

            with patch.object(
                cert_module, "Paragraph", side_effect=recording_paragraph
            ):
                result = generator.generate_certificate(
                    case_id="CASE-ESCAPE-TEST",
                    evidence_manifest=manifest,
                    examiner_name="Examiner<script>",
                    agency_name="Lab <script>&",
                    key_findings=["<script>alert(1)</script>&"],
                )

            self.assertTrue(Path(result["pdf_path"]).is_file())
            rendered_inputs = "\n".join(captured)
            self.assertIn("&lt;script&gt;", rendered_inputs)
            self.assertNotIn("<script>", rendered_inputs)

    def test_unsafe_case_id_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            generator = BSASection63Certificate(output_dir=Path(tmp))

            with self.assertRaises(ValueError):
                generator.generate_certificate(
                    case_id="../escape",
                    evidence_manifest={"filename": "test.pcap"},
                )


if __name__ == "__main__":
    unittest.main()
