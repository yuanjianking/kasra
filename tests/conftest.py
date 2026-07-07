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

from app.config import settings
from app.database import Base, engine, get_db
from app.main import create_app

# Suppress app logging during tests
logging.getLogger("kasra").setLevel(logging.CRITICAL)


@pytest.fixture(scope="session")
def test_app():
    """Create a fresh FastAPI app for testing."""
    app = create_app()
    return app


@pytest.fixture(scope="function", autouse=True)
def _clean_db():
    """Ensure a clean database for each test.

    Drops and recreates all tables so that each test starts
    with an empty slate.
    """
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield


@pytest.fixture(scope="function")
def client(test_app) -> Generator[TestClient, None, None]:
    """Test client backed by a clean database per test.

    The autouse ``_clean_db`` fixture runs first, so each test
    starts with a fully reset database.
    """
    with TestClient(test_app) as c:
        yield c


@pytest.fixture(scope="function")
def auth_headers() -> dict[str, str]:
    """Default auth headers for tests."""
    return {"X-API-Key": "test-api-key"}
