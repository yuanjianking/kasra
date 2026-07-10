"""Integration test fixtures — shared across all integration test suites."""
from __future__ import annotations

import logging
import os
import tempfile
from typing import Generator

import pytest
from fastapi.testclient import TestClient

# Create a temporary database file for testing
_test_db_fd, _test_db_path = tempfile.mkstemp(suffix="_kasra_integration_test.db")

# Override settings BEFORE importing app modules
os.environ["KASRA_APP_DATABASE_URL"] = f"sqlite:///{_test_db_path}"
os.environ["KASRA_APP_API_KEY"] = "integration-test-api-key"

from app.database import Base, engine
from app.services.engine_service import engine_service

# Import models so Base.metadata knows about them
from app.models.audit_log import AuditLog  # noqa: F401
from app.models.audit_chain import AuditChain  # noqa: F401
from app.models.rule_config import RuleConfig  # noqa: F401
from app.models.custom_rule import CustomRule  # noqa: F401
from app.models.user import User  # noqa: F401
from app.models.user_behavior import UserBehavior  # noqa: F401

# Suppress app logging during tests
logging.getLogger("kasra").setLevel(logging.CRITICAL)


@pytest.fixture(scope="function")
def client() -> Generator[TestClient, None, None]:
    """Test client with fresh database and initialized engine."""
    from app.main import create_app

    # Reset database
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    # Initialize engine before app starts
    if not engine_service.is_initialized:
        engine_service.initialize()

    app = create_app()

    with TestClient(app) as c:
        yield c

    # Cleanup
    if engine_service.is_initialized:
        engine_service.shutdown()


@pytest.fixture(scope="function")
def auth_headers() -> dict[str, str]:
    """Default auth headers for integration tests."""
    return {"X-API-Key": "integration-test-api-key"}
