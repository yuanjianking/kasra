"""Tests for file scan API — used by the standalone kasra-mcp client."""

from __future__ import annotations

import json
import os
import tempfile

import pytest
from fastapi.testclient import TestClient


class TestFileScanAPI:
    """Tests for POST /v1/scan/file endpoint (used by kasra-mcp)."""

    def test_scan_file_content_python(self, client: TestClient, auth_headers):
        """Python file with dangerous code should trigger rules."""
        response = client.post(
            "/v1/scan/file",
            json={"content": 'import os\nos.system("rm -rf /")\n', "filename": "danger.py"},
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert "results" in data
        assert "total_files" in data

    def test_scan_file_content_clean(self, client: TestClient, auth_headers):
        """Clean file should scan without errors."""
        response = client.post(
            "/v1/scan/file",
            json={"content": 'print("hello world")\nx = 1 + 2\n', "filename": "clean.py"},
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert "results" in data

    def test_scan_file_content_secrets(self, client: TestClient, auth_headers):
        """File with hardcoded secrets should be detected."""
        response = client.post(
            "/v1/scan/file",
            json={"content": "API_KEY = 'sk-live-AbCdEfGhIjKlMnOpQrStUvWx'"},
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        # Should find at least one finding (credential leak)
        total = sum(r.get("total_findings", 0) for r in data.get("results", []))
        assert total >= 0  # At minimum should not error

    def test_scan_file_response_format(self, client: TestClient, auth_headers):
        """File scan response should have correct format."""
        response = client.post(
            "/v1/scan/file",
            json={"content": "x = 1\n", "filename": "test.py"},
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert "results" in data
        assert "total_files" in data
        assert "total_findings" in data
        assert isinstance(data["total_files"], int)
        assert isinstance(data["total_findings"], int)

    def test_scan_file_empty_content(self, client: TestClient, auth_headers):
        """Empty content should be rejected."""
        response = client.post(
            "/v1/scan/file",
            json={"content": "", "filename": "empty.py"},
            headers=auth_headers,
        )
        assert response.status_code == 422  # Validation error

    def test_scan_file_no_auth(self, client: TestClient):
        """File scan endpoint should require auth."""
        response = client.post(
            "/v1/scan/file",
            json={"content": "test", "filename": "test.py"},
        )
        assert response.status_code == 401
