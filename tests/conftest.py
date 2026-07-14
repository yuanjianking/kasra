"""Test fixtures for Kasra App tests."""
from __future__ import annotations

import logging
import os
import tempfile
from typing import Generator

import pytest
from fastapi.testclient import TestClient

# Create a temporary database file for testing
_test_db_fd, _test_db_path = tempfile.mkstemp(suffix="_kasra_test.db")

# Override settings for testing BEFORE importing app modules
os.environ["KASRA_APP_DATABASE_URL"] = f"sqlite:///{_test_db_path}"
os.environ["KASRA_APP_API_KEY"] = "test-api-key"
os.environ["KASRA_APP_SEED_DATA"] = "false"
os.environ["KASRA_SKIP_FRONTEND"] = "true"
os.environ["KASRA_SKIP_MCP"] = "true"
os.environ["KASRA_APP_HTTPS_PROXY_ENABLED"] = "false"

from app.database import Base, engine, init_db
from app.services.engine_service import engine_service

# Import ALL models so Base.metadata knows about them
from app.models import (  # noqa: F401
    AuditLog, AuditChain, Category, CustomRule,
    PatternType, Rule, User, UserBehavior,
)

# Suppress app logging during tests
logging.getLogger("kasra").setLevel(logging.CRITICAL)


@pytest.fixture(scope="function")
def client() -> Generator[TestClient, None, None]:
    """Test client with clean database per test."""
    if engine_service.is_initialized:
        engine_service.shutdown()
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    # Seed master data + rules
    from app.db_migration import seed_sdk_rules_from_dml
    from app.models import Category, PatternType
    from app.database import SessionLocal
    from sqlalchemy import text

    # Seed categories and pattern types directly
    db = SessionLocal()
    for name, label, desc, color in [
        ('I', 'Input Detection', 'Input detection rules', '#ef4444'),
        ('O', 'Output Detection', 'Output detection rules', '#f97316'),
        ('SEC', 'Code Security', 'Code review security rules', '#8b5cf6'),
        ('IAC', 'Infrastructure as Code', 'IAC misconfiguration rules', '#06b6d4'),
        ('BEHAVIOR', 'Behavior Monitoring', 'Behavior monitoring rules', '#ec4899'),
    ]:
        db.execute(text("INSERT OR IGNORE INTO categories (name, label, description, color) VALUES (:n, :l, :d, :c)"),
                   {'n': name, 'l': label, 'd': desc, 'c': color})
    for name, label, desc in [
        ('regex', 'Regex Match', 'Regex matching'),
        ('keyword', 'Keyword Match', 'Keyword matching'),
        ('dictionary', 'Dictionary Match', 'Dictionary matching'),
        ('yaml_path', 'YAML Path Match', 'YAML path matching'),
        ('dockerfile', 'Dockerfile Match', 'Dockerfile matching'),
        ('keyvalue', 'Key-Value Match', 'Key-value matching'),
    ]:
        db.execute(text("INSERT OR IGNORE INTO pattern_types (name, label, description) VALUES (:n, :l, :d)"),
                   {'n': name, 'l': label, 'd': desc})
    db.commit()

    seed_sdk_rules_from_dml()

    # Initialize engine with rules
    engine_service.initialize()
    db.close()
    db2 = SessionLocal()
    engine_service.reload_rules_from_db(db2)
    db2.close()

    # Create app with lifespan disabled
    from app.main import create_app
    app = create_app()

    with TestClient(app) as c:
        yield c

    if engine_service.is_initialized:
        engine_service.shutdown()


@pytest.fixture(scope="function")
def auth_headers() -> dict[str, str]:
    """Default auth headers for tests."""
    return {"X-API-Key": "test-api-key"}
