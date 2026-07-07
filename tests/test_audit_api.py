"""Tests for audit log API endpoints."""

from __future__ import annotations

from fastapi.testclient import TestClient


class TestAuditLogs:
    def test_list_logs_requires_auth(self, client: TestClient):
        response = client.get("/v1/audit/logs")
        assert response.status_code == 401

    def test_list_logs_returns_paginated(self, client: TestClient, auth_headers):
        response = client.get("/v1/audit/logs?page=1&page_size=10", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert "total" in data
        assert "page" in data
        assert data["page"] == 1

    def test_list_logs_invalid_sort_rejected(self, client: TestClient, auth_headers):
        response = client.get(
            "/v1/audit/logs?sort_by=invalid_column",
            headers=auth_headers,
        )
        assert response.status_code == 400

    def test_list_logs_valid_sort(self, client: TestClient, auth_headers):
        response = client.get(
            "/v1/audit/logs?sort_by=severity&sort_order=asc",
            headers=auth_headers,
        )
        assert response.status_code == 200
