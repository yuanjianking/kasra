"""Integration test fixtures — shared across all integration test suites.

Optimised for speed: tables created once per session, data cleaned per function.
"""
from __future__ import annotations

import logging
import os
import tempfile
from typing import Generator

import pytest
from fastapi.testclient import TestClient

# Create a temporary database file for testing
_test_db_fd, _test_db_path = tempfile.mkstemp(suffix="_kasra_integration_test.db")

# Override settings BEFORE importing app modules — also skip heavy services
os.environ["KASRA_APP_DATABASE_URL"] = f"sqlite:///{_test_db_path}"
os.environ["KASRA_APP_API_KEY"] = "integration-test-api-key"
os.environ["KASRA_SKIP_FRONTEND"] = "true"
os.environ["KASRA_SKIP_MCP"] = "true"
os.environ["KASRA_APP_HTTPS_PROXY_ENABLED"] = "false"
os.environ["KASRA_APP_SEED_DATA"] = "false"

from app.database import Base, engine
from app.services.engine_service import engine_service

# Import models so Base.metadata knows about them
from app.models.audit_log import AuditLog  # noqa: F401
from app.models.audit_chain import AuditChain  # noqa: F401
from app.models.rule_config import Rule  # noqa: F401
from app.models.custom_rule import CustomRule  # noqa: F401
from app.models.user import User  # noqa: F401
from app.models.user_behavior import UserBehavior  # noqa: F401

# Suppress app logging during tests
logging.getLogger("kasra").setLevel(logging.CRITICAL)


@pytest.fixture(scope="session", autouse=True)
def _setup_db():
    """Create all tables once per test session."""
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)
    try:
        os.unlink(_test_db_path)
    except OSError:
        pass


def _clear_tables():
    """Delete all rows from all tables (much faster than drop/create)."""
    from sqlalchemy import text
    with engine.begin() as conn:
        conn.execute(text("PRAGMA foreign_keys=OFF"))
        for table in reversed(Base.metadata.sorted_tables):
            conn.execute(table.delete())
        conn.execute(text("PRAGMA foreign_keys=ON"))


@pytest.fixture(scope="function")
def client() -> Generator[TestClient, None, None]:
    """Test client with clean database and freshly initialised engine."""
    from app.main import create_app

    _clear_tables()

    # Fresh engine per test so rule state never leaks
    if engine_service.is_initialized:
        engine_service.shutdown()
    engine_service.initialize()

    # Seed SDK rules from DML and load into engine
    from app.database import SessionLocal, init_db
    from app.db_migration import seed_sdk_rules_from_dml
    init_db()
    seed_sdk_rules_from_dml()
    load_db = SessionLocal()
    engine_service.reload_rules_from_db(load_db)
    load_db.close()

    app = create_app()

    with TestClient(app) as c:
        yield c

    if engine_service.is_initialized:
        engine_service.shutdown()


@pytest.fixture(scope="function")
def auth_headers() -> dict[str, str]:
    """Default auth headers for integration tests."""
    return {"X-API-Key": "integration-test-api-key"}
