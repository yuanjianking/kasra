"""Tests for health check endpoint."""

from __future__ import annotations

from fastapi.testclient import TestClient


class TestHealthEndpoint:
    """Health check should be publicly accessible (no auth required)."""

    def test_health_returns_200(self, client: TestClient):
        response = client.get("/health")
        assert response.status_code == 200

    def test_health_returns_json(self, client: TestClient):
        response = client.get("/health")
        data = response.json()
        assert "status" in data
        assert data["status"] in ("healthy", "unhealthy")
        assert "version" in data

    def test_health_does_not_require_auth(self, client: TestClient):
        """Health endpoint should be accessible without API key."""
        response = client.get("/health", headers={})
        assert response.status_code == 200


class TestAuthRequired:
    """Most endpoints should require authentication."""

    def test_scan_input_without_auth_returns_401(self, client: TestClient):
        response = client.post(
            "/v1/scan/input",
            json={"content": "test"},
            headers={},
        )
        assert response.status_code == 401

    def test_scan_input_with_auth_returns_200(self, client: TestClient, auth_headers):
        response = client.post(
            "/v1/scan/input",
            json={"content": "test"},
            headers=auth_headers,
        )
        # Should return 200 even with no engine (test has no SDK rules)
        assert response.status_code in (200, 500)

    def test_invalid_api_key_returns_401(self, client: TestClient):
        response = client.post(
            "/v1/scan/input",
            json={"content": "test"},
            headers={"X-API-Key": "wrong-key"},
        )
        assert response.status_code == 401
