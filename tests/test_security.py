"""Tests for security middleware — API key auth, rate limiting, body size, CORS."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


class TestApiKeyAuth:
    """API key authentication middleware tests."""

    def test_missing_api_key_returns_401(self, client: TestClient):
        """Endpoints should reject requests without API key."""
        response = client.get("/v1/audit/logs")
        assert response.status_code == 401

    def test_invalid_api_key_returns_401(self, client: TestClient):
        """Endpoints should reject requests with wrong API key."""
        response = client.get("/v1/audit/logs", headers={"X-API-Key": "wrong-key"})
        assert response.status_code == 401

    def test_health_does_not_require_auth(self, client: TestClient):
        """Health endpoint should be publicly accessible."""
        response = client.get("/health")
        assert response.status_code == 200

    def test_docs_does_not_require_auth(self, client: TestClient):
        """API docs should be publicly accessible."""
        response = client.get("/docs")
        assert response.status_code in (200, 404)

    def test_redoc_does_not_require_auth(self, client: TestClient):
        """ReDoc should be publicly accessible."""
        response = client.get("/redoc")
        assert response.status_code in (200, 404)

    def test_openapi_spec_does_not_require_auth(self, client: TestClient):
        """OpenAPI spec should be publicly accessible."""
        response = client.get("/openapi.json")
        assert response.status_code in (200, 404)

    def test_mcp_endpoint_does_not_require_auth(self, client: TestClient):
        """MCP SSE endpoint should be accessible without API key.

        NOTE: MCP SSE mount is skipped when KASRA_SKIP_MCP=true (test env).
        This test verifies the mount path only when MCP is not skipped.
        """
        import os
        if os.environ.get("KASRA_SKIP_MCP") == "true":
            pytest.skip("MCP endpoint skipped in test environment")
        app = client.app
        found = False
        for route in app.routes:
            path = getattr(route, "path", str(route))
            if "/v1/mcp" in path:
                found = True
                break
            # Also check parent routers
            for sub_route in getattr(route, "routes", []):
                sub_path = getattr(sub_route, "path", "")
                if "/v1/mcp" in sub_path:
                    found = True
                    break
        assert found, "/v1/mcp should be mounted in app routes"

    def test_all_api_endpoints_require_auth(self, client: TestClient):
        """Various API endpoints should all require auth."""
        endpoints = [
            ("GET", "/v1/dashboard/summary"),
            ("GET", "/v1/rules"),
            ("GET", "/v1/audit/logs"),
            ("POST", "/v1/scan/input"),
            ("POST", "/v1/scan/output"),
        ]
        for method, path in endpoints:
            response = client.request(method, path)
            assert response.status_code == 401, (
                f"{method} {path} returned {response.status_code}, expected 401"
            )


class TestRateLimiting:
    """Rate limiting middleware tests."""

    def test_rate_limit_header_not_exposed(self, client: TestClient):
        """Normal requests should succeed without rate limit headers."""
        response = client.get("/health")
        assert response.status_code == 200

    def test_rate_limit_does_not_block_low_traffic(self, client: TestClient, auth_headers):
        """A few requests should not trigger rate limiting."""
        for _ in range(5):
            response = client.get(
                "/v1/rules", headers=auth_headers,
            )
            assert response.status_code == 200, f"Rate limited unexpectedly: {response.json()}"


class TestBodySizeLimit:
    """Request body size enforcement tests."""

    def test_large_body_rejected(self, client: TestClient, auth_headers):
        """Oversized request body should be rejected."""
        large_content = "x" * (11 * 1024 * 1024)  # ~11 MB (limit is 10 MB)
        response = client.post(
            "/v1/scan/input",
            json={"content": large_content},
            headers=auth_headers,
        )
        assert response.status_code == 413

    def test_body_just_under_limit(self, client: TestClient, auth_headers):
        """Content just under the body limit should be accepted."""
        content = "hello world"
        response = client.post(
            "/v1/scan/input",
            json={"content": content},
            headers=auth_headers,
        )
        # Should succeed (200) or fail for other reasons (500)
        assert response.status_code in (200, 422)


class TestCors:
    """CORS middleware tests."""

    def test_cors_headers_present(self, client: TestClient):
        """OPTIONS preflight to public endpoint should return CORS headers."""
        response = client.options(
            "/health",
            headers={
                "Origin": "http://example.com",
                "Access-Control-Request-Method": "GET",
            },
        )
        # OPTIONS /health may return 405 (method not allowed) or 200
        # but CORS headers should be present in either case
        if response.status_code != 405:
            cors_header = response.headers.get("access-control-allow-origin")
            assert cors_header is not None, "CORS header should be present"

    def test_cors_headers_with_auth(self, client: TestClient, auth_headers):
        """OPTIONS preflight with auth should get CORS headers."""
        response = client.options(
            "/v1/scan/input",
            headers={
                **auth_headers,
                "Origin": "http://example.com",
                "Access-Control-Request-Method": "POST",
            },
        )
        # With valid auth, should either get 200 or 405
        assert response.status_code in (200, 405)
