"""Tests for app configuration."""

from __future__ import annotations

from app.config import AppSettings, settings


class TestAppSettings:
    def test_default_host(self):
        assert settings.host == "0.0.0.0"

    def test_default_port(self):
        assert settings.port == 8080

    def test_default_log_level_default_value(self):
        """The model's default log level is 'info' (env may override at runtime)."""
        assert AppSettings.model_fields["log_level"].default == "info"

    def test_api_key_from_env(self):
        """Set by conftest.py to test-api-key."""
        assert settings.api_key == "test-api-key"

    def test_rate_limit_default(self):
        assert settings.rate_limit_rpm == 120

    def test_audit_retention_default(self):
        assert settings.audit_retention_days == 90
