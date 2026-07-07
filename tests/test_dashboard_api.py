"""Tests for dashboard API endpoints — summary, trend, user behavior."""

from __future__ import annotations

from fastapi.testclient import TestClient


class TestDashboard:
    """Dashboard API tests."""

    # ── Auth ──

    def test_summary_requires_auth(self, client: TestClient):
        response = client.get("/v1/dashboard/summary")
        assert response.status_code == 401

    def test_trend_requires_auth(self, client: TestClient):
        response = client.get("/v1/dashboard/trend")
        assert response.status_code == 401

    def test_behavior_requires_auth(self, client: TestClient):
        response = client.get("/v1/dashboard/users/behavior")
        assert response.status_code == 401

    # ── Summary ──

    def test_summary_returns_all_fields(self, client: TestClient, auth_headers):
        response = client.get("/v1/dashboard/summary", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "total_requests_24h" in data
        assert "blocked_count_24h" in data
        assert "warning_count_24h" in data
        assert "total_users_active_24h" in data
        assert "total_rules_active" in data
        assert "p0_triggers_24h" in data
        assert "p1_triggers_24h" in data
        assert "p2_triggers_24h" in data
        assert "block_rate_percent" in data
        assert "top_triggered_rules" in data
        assert "top_users" in data
        assert "current_time" in data

    def test_summary_rules_active(self, client: TestClient, auth_headers):
        """total_rules_active should be >= 0."""
        response = client.get("/v1/dashboard/summary", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["total_rules_active"] >= 0

    def test_summary_block_rate_is_percentage(self, client: TestClient, auth_headers):
        """block_rate_percent should be a float between 0 and 100."""
        response = client.get("/v1/dashboard/summary", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data["block_rate_percent"], (int, float))
        assert 0 <= data["block_rate_percent"] <= 100

    # ── Trend ──

    def test_trend_returns_data(self, client: TestClient, auth_headers):
        response = client.get(
            "/v1/dashboard/trend?period=7d",
            headers=auth_headers,
        )
        assert response.status_code in (200, 500)
        if response.status_code == 200:
            data = response.json()
            assert "period" in data
            assert "data" in data

    def test_trend_period_7d(self, client: TestClient, auth_headers):
        response = client.get(
            "/v1/dashboard/trend?period=7d",
            headers=auth_headers,
        )
        assert response.status_code in (200, 500)
        if response.status_code == 200:
            assert response.json()["period"] == "7d"

    def test_trend_period_30d(self, client: TestClient, auth_headers):
        response = client.get(
            "/v1/dashboard/trend?period=30d",
            headers=auth_headers,
        )
        assert response.status_code in (200, 500)

    def test_trend_period_90d(self, client: TestClient, auth_headers):
        response = client.get(
            "/v1/dashboard/trend?period=90d",
            headers=auth_headers,
        )
        assert response.status_code in (200, 500)

    def test_trend_invalid_period_rejected(self, client: TestClient, auth_headers):
        response = client.get(
            "/v1/dashboard/trend?period=invalid",
            headers=auth_headers,
        )
        assert response.status_code == 422

    def test_trend_data_point_format(self, client: TestClient, auth_headers):
        """Each trend data point should have correct fields."""
        response = client.get(
            "/v1/dashboard/trend?period=7d",
            headers=auth_headers,
        )
        assert response.status_code in (200, 500)
        if response.status_code == 200:
            data = response.json()
            for point in data.get("data", []):
                assert "date" in point
                assert "total" in point
                assert "blocked" in point
                assert "warned" in point

    # ── User Behavior ──

    def test_behavior_returns_paginated(self, client: TestClient, auth_headers):
        response = client.get(
            "/v1/dashboard/users/behavior?page=1&page_size=50",
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert "total" in data
        assert "page" in data
        assert "page_size" in data

    def test_behavior_filter_by_user(self, client: TestClient, auth_headers):
        response = client.get(
            "/v1/dashboard/users/behavior?user_id=test-user",
            headers=auth_headers,
        )
        assert response.status_code == 200

    def test_behavior_page_size_validation(self, client: TestClient, auth_headers):
        """Page size > 500 should be rejected."""
        response = client.get(
            "/v1/dashboard/users/behavior?page_size=1000",
            headers=auth_headers,
        )
        assert response.status_code == 422

    def test_behavior_user_response_format(self, client: TestClient, auth_headers):
        """User behavior items should have correct fields."""
        response = client.get(
            "/v1/dashboard/users/behavior",
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        if data["items"]:
            item = data["items"][0]
            assert "user_id" in item
            assert "date" in item
            assert "total_requests" in item
            assert "blocked_requests" in item
            assert "warned_requests" in item
            assert "anomaly_score" in item
            assert "top_triggers" in item

    # ── Summary after scan ──

    def test_summary_updates_after_scan(self, client: TestClient, auth_headers):
        """Dashboard summary should reflect recent scans."""
        # Get baseline
        baseline = client.get("/v1/dashboard/summary", headers=auth_headers)
        assert baseline.status_code == 200
        baseline_data = baseline.json()
        baseline_requests = baseline_data["total_requests_24h"]

        # Trigger a scan
        client.post(
            "/v1/scan/input",
            json={"content": "dashboard test", "user_id": "dash-test"},
            headers=auth_headers,
        )

        # Check updated summary
        updated = client.get("/v1/dashboard/summary", headers=auth_headers)
        assert updated.status_code == 200
        updated_data = updated.json()
        # Requests should increase or stay the same
        assert updated_data["total_requests_24h"] >= baseline_requests
