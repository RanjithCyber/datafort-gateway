"""
tests/test_interceptor.py — V3.0 Integration Tests for Middleware, Dashboard, Steganography & RBAC
"""

from __future__ import annotations

import json
import pytest
from starlette.testclient import TestClient

from core.tokenizer import TOKEN_EMAIL, TOKEN_MOBILE, TOKEN_PAN
from main import app


@pytest.fixture()
def client():
    return TestClient(app, raise_server_exceptions=False)


class TestHealthAndDashboard:
    def test_health_returns_200(self, client: TestClient) -> None:
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"

    def test_ready_returns_200(self, client: TestClient) -> None:
        resp = client.get("/ready")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ready"

    def test_dashboard_html_renders(self, client: TestClient) -> None:
        resp = client.get("/dashboard")
        assert resp.status_code == 200
        assert "DataFort-Gateway" in resp.text
        assert "Real-Time DLP Sandbox" in resp.text
        assert "Forensic Leak Detective" in resp.text

    def test_viewer_html_renders(self, client: TestClient) -> None:
        resp = client.get("/viewer")
        assert resp.status_code == 200
        assert "Dynamic Photo-Proof DRM Active" in resp.text

    def test_stats_and_audit_logs(self, client: TestClient) -> None:
        stats_resp = client.get("/api/v1/stats")
        assert stats_resp.status_code == 200
        assert "total_requests_inspected" in stats_resp.json()

        logs_resp = client.get("/api/v1/audit-logs")
        assert logs_resp.status_code == 200
        assert isinstance(logs_resp.json(), list)


class TestRBACMasking:
    def test_default_role_full_token(self, client: TestClient) -> None:
        payload = {
            "name": "Customer A",
            "mobile": "+91-9876543210",
            "pan": "ABCDE1234F",
        }
        resp = client.post("/api/v1/export", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["masking_mode"] == "FULL_TOKEN"
        assert data["sanitized_payload"]["mobile"] == TOKEN_MOBILE
        assert data["sanitized_payload"]["pan"] == TOKEN_PAN

    def test_manager_role_partial_mask(self, client: TestClient) -> None:
        payload = {
            "name": "Customer B",
            "mobile": "+91-9876543210",
            "pan": "ABCDE1234F",
        }
        resp = client.post(
            "/api/v1/export",
            json=payload,
            headers={"X-User-Role": "manager"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["masking_mode"] == "PARTIAL_MASK"
        assert data["sanitized_payload"]["mobile"] == "******3210"
        assert data["sanitized_payload"]["pan"] == "AB*****F"

    def test_investigator_role_unmasked(self, client: TestClient) -> None:
        payload = {
            "name": "Customer C",
            "mobile": "+91-9876543210",
            "pan": "ABCDE1234F",
        }
        resp = client.post(
            "/api/v1/export",
            json=payload,
            headers={"X-User-Role": "investigator"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["masking_mode"] == "UNMASKED"
        assert data["sanitized_payload"]["mobile"] == "+91-9876543210"
        assert data["sanitized_payload"]["pan"] == "ABCDE1234F"


class TestAnomaliesAndFourEyes:
    def test_oversized_payload_returns_413(self, client: TestClient) -> None:
        oversized = json.dumps({"data": "x" * 200_000})
        resp = client.post(
            "/api/v1/export",
            content=oversized,
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 413

    def test_bulk_export_four_eyes_staged(self, client: TestClient) -> None:
        # Request with 25 records triggers Four-Eyes Quorum (20 threshold)
        payload = {"records": [{"id": i} for i in range(25)]}
        resp = client.post("/api/v1/export", json=payload)
        assert resp.status_code == 202
        assert "PENDING_SUPERVISORY_APPROVAL" in resp.json()["status"]
        assert "approval_request_id" in resp.json()

    def test_absolute_bulk_limit_403(self, client: TestClient) -> None:
        # Request with 150 records exceeds 100 limit
        payload = {"records": [{"id": i} for i in range(150)]}
        resp = client.post("/api/v1/export", json=payload)
        assert resp.status_code == 403
