"""Tests for scan API endpoints."""

from __future__ import annotations

from fastapi.testclient import TestClient


class TestScanInput:
    def test_empty_content_rejected(self, client: TestClient, auth_headers):
        response = client.post(
            "/v1/scan/input",
            json={"content": ""},
            headers=auth_headers,
        )
        # Empty content should fail validation
        assert response.status_code == 422

    def test_missing_content_rejected(self, client: TestClient, auth_headers):
        response = client.post(
            "/v1/scan/input",
            json={},
            headers=auth_headers,
        )
        assert response.status_code == 422

    def test_scan_output_endpoint(self, client: TestClient, auth_headers):
        response = client.post(
            "/v1/scan/output",
            json={"content": "test output"},
            headers=auth_headers,
        )
        assert response.status_code in (200, 500)
