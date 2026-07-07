"""Kasra Application Configuration.

Loads settings from:
  1. Code defaults
  2. .env file (optional)
  3. Environment variables (KASRA_APP_* prefix)
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class AppSettings(BaseSettings):
    """Application-level settings for the Kasra server."""

    # ── Server ──
    host: str = "0.0.0.0"
    port: int = 8080
    workers: int = 4
    log_level: Literal["debug", "info", "warning", "error"] = "info"

    # ── Database ──
    database_url: str = "sqlite:///./data/kasra.db"

    # ── Security ──
    api_key: str = "dev-api-key-change-in-production"
    jwt_secret: str = "change-this-to-a-random-secret"

    # ── Proxy ──
    proxy_targets: str = "api.anthropic.com,api.openai.com"

    # ── Rate Limiting ──
    rate_limit_rpm: int = 120  # Requests per minute per IP

    # ── CORS ──
    allowed_origins: list[str] = ["*"]  # Change to specific origins in production

    # ── HTTPS CONNECT Proxy ──
    https_proxy_enabled: bool = False  # Opt-in: disabled by default
    https_proxy_host: str = "0.0.0.0"
    https_proxy_port: int = 8443

    # ── Audit ──
    audit_retention_days: int = 90  # Auto-delete audit logs older than this

    # ── Paths ──
    data_dir: str = "./data"
    config_dir: str = "./config"

    model_config = SettingsConfigDict(
        env_prefix="KASRA_APP_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


def validate_settings(settings: AppSettings) -> None:
    """Validate that production secrets have been changed from defaults."""
    _warnings = []
    if settings.api_key == "dev-api-key-change-in-production":
        _warnings.append("KASRA_APP_API_KEY is still set to the default development key!")
    if settings.jwt_secret == "change-this-to-a-random-secret":
        _warnings.append("KASRA_APP_JWT_SECRET is still set to the default development secret!")
    if _warnings:
        _logger = logging.getLogger("kasra")
        for w in _warnings:
            _logger.warning("SECURITY: %s", w)


settings = AppSettings()

