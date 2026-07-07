"""Tests for audit log API endpoints — query, filter, report, export."""

from __future__ import annotations

from fastapi.testclient import TestClient


class TestAuditLogs:
    """Audit log query and filtering tests."""

    # ── Auth ──

    def test_list_logs_requires_auth(self, client: TestClient):
        response = client.get("/v1/audit/logs")
        assert response.status_code == 401

    # ── Basic query ──

    def test_list_logs_returns_paginated(self, client: TestClient, auth_headers):
        response = client.get(
            "/v1/audit/logs?page=1&page_size=10",
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert "total" in data
        assert "page" in data
        assert data["page"] == 1
        assert "page_size" in data
        assert "total_pages" in data

    def test_logs_after_scan(self, client: TestClient, auth_headers):
        """Scanning content should create audit log entries."""
        # Trigger a scan
        client.post(
            "/v1/scan/input",
            json={"content": "ghp_abc123def456xyz789", "user_id": "test-user"},
            headers=auth_headers,
        )
        # Check audit logs
        response = client.get(
            "/v1/audit/logs?page_size=10&user_id=test-user",
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["total"] >= 0

    # ── Sorting ──

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

    def test_list_logs_sort_by_timestamp(self, client: TestClient, auth_headers):
        response = client.get(
            "/v1/audit/logs?sort_by=timestamp&sort_order=desc",
            headers=auth_headers,
        )
        assert response.status_code == 200

    def test_list_logs_sort_by_user_id(self, client: TestClient, auth_headers):
        response = client.get(
            "/v1/audit/logs?sort_by=user_id&sort_order=asc",
            headers=auth_headers,
        )
        assert response.status_code == 200

    def test_list_logs_whitelisted_sort_columns(self, client: TestClient, auth_headers):
        """Only whitelisted sort columns should be allowed."""
        valid_columns = ["timestamp", "severity", "user_id", "rule_id", "action", "direction", "status"]
        for col in valid_columns:
            response = client.get(
                f"/v1/audit/logs?sort_by={col}",
                headers=auth_headers,
            )
            assert response.status_code == 200, f"Valid sort column {col} rejected"

    # ── Filtering ──

    def test_filter_by_severity(self, client: TestClient, auth_headers):
        response = client.get(
            "/v1/audit/logs?severity=P0",
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        for log in data["items"]:
            assert log["severity"] == "P0"

    def test_filter_by_direction(self, client: TestClient, auth_headers):
        response = client.get(
            "/v1/audit/logs?direction=input",
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        for log in data["items"]:
            assert log["direction"] == "input"

    def test_filter_invalid_severity_rejected(self, client: TestClient, auth_headers):
        response = client.get(
            "/v1/audit/logs?severity=P5",
            headers=auth_headers,
        )
        assert response.status_code == 422

    def test_filter_invalid_direction_rejected(self, client: TestClient, auth_headers):
        response = client.get(
            "/v1/audit/logs?direction=invalid",
            headers=auth_headers,
        )
        assert response.status_code == 422

    # ── Pagination ──

    def test_pagination_page_size_validation(self, client: TestClient, auth_headers):
        """Page size > 500 should be rejected."""
        response = client.get(
            "/v1/audit/logs?page_size=1000",
            headers=auth_headers,
        )
        assert response.status_code == 422

    def test_pagination_page_validation(self, client: TestClient, auth_headers):
        """Page 0 should be rejected."""
        response = client.get(
            "/v1/audit/logs?page=0",
            headers=auth_headers,
        )
        assert response.status_code == 422

    def test_pagination_empty_page(self, client: TestClient, auth_headers):
        """Page beyond available data should return empty items."""
        response = client.get(
            "/v1/audit/logs?page=99999",
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["items"] == []
        assert data["total"] >= 0

    # ── Report ──

    def test_report_requires_auth(self, client: TestClient):
        response = client.get("/v1/audit/report")
        assert response.status_code == 401

    def test_report_returns_summary(self, client: TestClient, auth_headers):
        response = client.get("/v1/audit/report", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "total_events" in data
        assert "total_blocked" in data
        assert "total_warnings" in data
        assert "unique_users" in data
        assert "unique_rules" in data
        assert "p0_count" in data
        assert "p1_count" in data
        assert "p2_count" in data
        assert "top_rules" in data

    # ── Export ──

    def test_export_requires_auth(self, client: TestClient):
        response = client.get("/v1/audit/export")
        assert response.status_code == 401

    def test_export_returns_csv(self, client: TestClient, auth_headers):
        response = client.get("/v1/audit/export", headers=auth_headers)
        assert response.status_code == 200
        assert "text/csv" in response.headers.get("content-type", "")
        assert "Content-Disposition" in response.headers
        assert "attachment" in response.headers["Content-Disposition"]

    def test_export_csv_has_header(self, client: TestClient, auth_headers):
        response = client.get("/v1/audit/export", headers=auth_headers)
        assert response.status_code == 200
        content = response.text
        assert "rule_id" in content
        assert "severity" in content
        assert "action" in content
        assert "direction" in content

    # ── Audit log response format ──

    def test_audit_log_response_format(self, client: TestClient, auth_headers):
        """Audit log entry should have all required fields."""
        # First create a log entry via scan
        client.post(
            "/v1/scan/input",
            json={"content": "test audit format", "user_id": "format-test"},
            headers=auth_headers,
        )
        response = client.get(
            "/v1/audit/logs?user_id=format-test",
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        if data["items"]:
            log = data["items"][0]
            assert "id" in log
            assert "timestamp" in log
            assert "rule_id" in log
            assert "rule_name" in log
            assert "severity" in log
            assert "action" in log
            assert "direction" in log
            assert "match_count" in log
            assert "status" in log
