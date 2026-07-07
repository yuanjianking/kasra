"""Tests for rule management API endpoints."""

from __future__ import annotations

from fastapi.testclient import TestClient


class TestRulesAPI:
    def test_list_rules_requires_auth(self, client: TestClient):
        response = client.get("/v1/rules")
        assert response.status_code == 401

    def test_list_rules(self, client: TestClient, auth_headers):
        response = client.get("/v1/rules", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert "total" in data
