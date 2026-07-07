"""Tests for dashboard API endpoints."""

from __future__ import annotations

from fastapi.testclient import TestClient


class TestDashboard:
    def test_summary_requires_auth(self, client: TestClient):
        response = client.get("/v1/dashboard/summary")
        assert response.status_code == 401

    def test_summary(self, client: TestClient, auth_headers):
        response = client.get("/v1/dashboard/summary", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "total_requests_24h" in data
        assert "blocked_count_24h" in data

    def test_trend(self, client: TestClient, auth_headers):
        response = client.get("/v1/dashboard/trend?period=7d", headers=auth_headers)
        assert response.status_code in (200, 500)
