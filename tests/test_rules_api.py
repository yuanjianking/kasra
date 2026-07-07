"""Tests for rule management API endpoints — CRUD operations and filtering."""

from __future__ import annotations

from fastapi.testclient import TestClient


class TestRulesAPI:
    """Rule management API tests."""

    # ── Auth ──

    def test_list_rules_requires_auth(self, client: TestClient):
        response = client.get("/v1/rules")
        assert response.status_code == 401

    # ── List ──

    def test_list_rules(self, client: TestClient, auth_headers):
        response = client.get("/v1/rules", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert "total" in data
        assert isinstance(data["items"], list)
        assert data["total"] >= 0

    def test_list_rules_pagination(self, client: TestClient, auth_headers):
        response = client.get(
            "/v1/rules?page=1&page_size=10",
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["page"] == 1
        assert data["page_size"] == 10
        assert len(data["items"]) <= 10

    def test_list_rules_filter_by_severity(self, client: TestClient, auth_headers):
        response = client.get(
            "/v1/rules?severity=P0",
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        for rule in data["items"]:
            assert rule["severity"] == "P0"

    def test_list_rules_filter_by_category(self, client: TestClient, auth_headers):
        response = client.get(
            "/v1/rules?category=credential_leak",
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        for rule in data["items"]:
            assert rule["category"] == "credential_leak"

    def test_list_rules_filter_enabled_only(self, client: TestClient, auth_headers):
        response = client.get(
            "/v1/rules?enabled_only=true",
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        for rule in data["items"]:
            assert rule["enabled"] is True

    def test_list_rules_invalid_severity_rejected(self, client: TestClient, auth_headers):
        response = client.get(
            "/v1/rules?severity=P5",
            headers=auth_headers,
        )
        assert response.status_code == 422

    # ── Get single rule ──

    def test_get_rule_by_id(self, client: TestClient, auth_headers):
        # First get list to find a valid rule ID
        list_resp = client.get("/v1/rules", headers=auth_headers)
        assert list_resp.status_code == 200
        rules = list_resp.json()["items"]
        if rules:
            rule_id = rules[0]["id"]
            response = client.get(f"/v1/rules/{rule_id}", headers=auth_headers)
            assert response.status_code == 200
            data = response.json()
            assert data["id"] == rule_id
            assert "name" in data
            assert "severity" in data

    def test_get_non_existent_rule_returns_404(self, client: TestClient, auth_headers):
        response = client.get("/v1/rules/ZZ-99", headers=auth_headers)
        assert response.status_code == 404

    # ── Create custom rule ──

    def test_create_custom_rule(self, client: TestClient, auth_headers):
        response = client.post(
            "/v1/rules",
            json={
                "id": "U-01",
                "name": "Test Custom Rule",
                "description": "A test custom rule",
                "severity": "P1",
                "action": "warn",
                "category": "custom",
            },
            headers=auth_headers,
        )
        assert response.status_code == 201
        data = response.json()
        assert data["id"] == "U-01"
        assert data["is_custom"] is True
        assert data["enabled"] is True

    def test_create_duplicate_rule_returns_400(self, client: TestClient, auth_headers):
        # Create first
        client.post(
            "/v1/rules",
            json={"id": "U-02", "name": "Dupe Rule", "severity": "P2"},
            headers=auth_headers,
        )
        # Create duplicate
        response = client.post(
            "/v1/rules",
            json={"id": "U-02", "name": "Dupe Rule Again", "severity": "P1"},
            headers=auth_headers,
        )
        assert response.status_code == 400

    def test_create_rule_with_invalid_prefix(self, client: TestClient, auth_headers):
        """Custom rule IDs must start with U-."""
        response = client.post(
            "/v1/rules",
            json={"id": "X-01", "name": "Invalid Rule", "severity": "P2"},
            headers=auth_headers,
        )
        assert response.status_code == 422  # Pydantic validation rejects non U- pattern

    def test_create_rule_verify_in_list(self, client: TestClient, auth_headers):
        """Created rule should appear in the rules list."""
        client.post(
            "/v1/rules",
            json={"id": "U-10", "name": "Verify List Rule", "severity": "P1"},
            headers=auth_headers,
        )
        response = client.get(
            "/v1/rules?custom_only=true",
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        rule_ids = [r["id"] for r in data["items"]]
        assert "U-10" in rule_ids

    # ── Update rule ──

    def test_update_rule_enabled(self, client: TestClient, auth_headers):
        """Toggle rule enabled/disabled."""
        # Find an SDK rule
        list_resp = client.get("/v1/rules", headers=auth_headers)
        rules = list_resp.json()["items"]
        if rules:
            rule_id = rules[0]["id"]
            # Create override via update
            response = client.put(
                f"/v1/rules/{rule_id}",
                json={"enabled": False},
                headers=auth_headers,
            )
            assert response.status_code == 200
            data = response.json()
            assert data["enabled"] is False

    def test_update_non_existent_rule_returns_404(self, client: TestClient, auth_headers):
        response = client.put(
            "/v1/rules/ZZ-99",
            json={"enabled": False},
            headers=auth_headers,
        )
        assert response.status_code == 404

    # ── Delete rule ──

    def test_delete_custom_rule(self, client: TestClient, auth_headers):
        """Delete a custom rule."""
        # Create first
        client.post(
            "/v1/rules",
            json={"id": "U-20", "name": "Delete Me", "severity": "P2"},
            headers=auth_headers,
        )
        # Delete
        response = client.delete("/v1/rules/U-20", headers=auth_headers)
        assert response.status_code == 204

    def test_delete_non_existent_rule_returns_404(self, client: TestClient, auth_headers):
        response = client.delete("/v1/rules/ZZ-99", headers=auth_headers)
        assert response.status_code == 404

    # ── Rule response format ──

    def test_rule_response_format(self, client: TestClient, auth_headers):
        """Rule response should have all required fields."""
        response = client.get("/v1/rules?page_size=1", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        if data["items"]:
            rule = data["items"][0]
            assert "id" in rule
            assert "name" in rule
            assert "severity" in rule
            assert "action" in rule
            assert "enabled" in rule
            assert "is_custom" in rule
            assert "category" in rule
            assert "source" in rule
