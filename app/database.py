"""Database connection and session management.

Supports both SQLite (development) and PostgreSQL (production).
Uses SQLAlchemy with connection pooling for production workloads.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any, Generator

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import settings

logger = logging.getLogger("kasra.database")


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""
    pass


# ── Database type detection ────────────────────────────────────────────────

def is_sqlite(url: str) -> bool:
    return url.startswith("sqlite")

def is_postgres(url: str) -> bool:
    return url.startswith("postgresql")

def get_db_type(url: str) -> str:
    if is_sqlite(url):
        return "sqlite"
    elif is_postgres(url):
        return "postgres"
    return "unknown"


# ── Engine creation ─────────────────────────────────────────────────────────

def _create_engine(database_url: str, echo: bool = False) -> Engine:
    """Create a SQLAlchemy engine with appropriate configuration.

    SQLite:
      - ``check_same_thread=False`` for FastAPI thread safety
      - WAL mode for better concurrent read/write
      - Foreign keys enabled

    PostgreSQL:
      - Connection pooling via SQLAlchemy's QueuePool
      - Statement timeout to prevent runaway queries
      - ``application_name`` for identifying connections
    """
    db_type = get_db_type(database_url)
    connect_args: dict[str, Any] = {}

    if db_type == "sqlite":
        connect_args["check_same_thread"] = False
        connect_args["timeout"] = 30  # SQLite busy timeout in seconds

        # Ensure the parent directory exists
        db_path = database_url.replace("sqlite:///", "")
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    elif db_type == "postgres":
        connect_args["application_name"] = "kasra"

    engine = create_engine(
        database_url,
        connect_args=connect_args,
        echo=echo,
        # PostgreSQL pool settings (ignored by SQLite)
        pool_size=10 if db_type == "postgres" else 5,
        max_overflow=20 if db_type == "postgres" else 10,
        pool_pre_ping=True,  # Verify connections before using them
        pool_recycle=3600,   # Recycle connections after 1 hour
    )

    # ── SQLite pragmas ──
    if db_type == "sqlite":
        @event.listens_for(engine, "connect")
        def _set_sqlite_pragma(dbapi_connection: Any, _: Any) -> None:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.execute("PRAGMA cache_size=-8000")  # 8 MB
            cursor.execute("PRAGMA busy_timeout=30000")
            cursor.close()

        # Removed: The @event.listens_for(engine, "begin") hook that executed SELECT 1
        # on every transaction start. This caused unnecessary overhead for SQLite.

    # ── PostgreSQL connection logging ──
    if db_type == "postgres":
        @event.listens_for(engine, "connect")
        def _receive_connect(dbapi_connection: Any, _: Any) -> None:
            logger.debug("PostgreSQL connection established")

        @event.listens_for(engine, "checkout")
        def _receive_checkout(dbapi_connection: Any, _: Any, _exc: Any) -> None:
            logger.debug("PostgreSQL connection checked out from pool")

    logger.info("Database engine created: %s (pool_size=%d)", db_type,
                engine.pool.size() if hasattr(engine.pool, 'size') else 'default')

    return engine


# ── Engine & Session factory ──
data_dir = Path(settings.data_dir)
data_dir.mkdir(parents=True, exist_ok=True)

engine = _create_engine(settings.database_url, echo=(settings.log_level == "debug"))
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


# ── Health check ────────────────────────────────────────────────────────────

def check_db_health() -> dict[str, Any]:
    """Check database connectivity and return status info.

    Returns:
        Dict with ``status``, ``db_type``, and optional ``error``.
    """
    db_type = get_db_type(settings.database_url)
    try:
        with SessionLocal() as session:
            if db_type == "postgres":
                result = session.execute(
                    __import__("sqlalchemy").text("SELECT version()")
                ).scalar()
            else:
                result = session.execute(
                    __import__("sqlalchemy").text("SELECT sqlite_version()")
                ).scalar()
            return {
                "status": "healthy",
                "db_type": db_type,
                "version": result,
            }
    except Exception as e:
        logger.error("Database health check failed: %s", e)
        return {
            "status": "unhealthy",
            "db_type": db_type,
            "error": str(e),
        }


# ── Table initialization ───────────────────────────────────────────────────

def init_db(retry: int = 3, retry_delay: float = 2.0) -> None:
    """Create all tables. Safe to call multiple times.

    For PostgreSQL, retries on transient connection failures (e.g., while
    the database container is still starting up).

    Args:
        retry: Number of times to retry on failure.
        retry_delay: Seconds between retries.
    """
    from app.models.audit_log import AuditLog  # noqa: F401
    from app.models.audit_chain import AuditChain  # noqa: F401
    from app.models.rule_config import Rule  # noqa: F401
    from app.models.custom_rule import CustomRule  # noqa: F401
    from app.models.user_behavior import UserBehavior  # noqa: F401
    from app.models.user import User  # noqa: F401
    from app.models.category import Category  # noqa: F401
    from app.models.pattern_type import PatternType  # noqa: F401

    last_error: Exception | None = None
    for attempt in range(1, retry + 1):
        try:
            Base.metadata.create_all(bind=engine)
            logger.info("Database tables initialized (attempt %d/%d)", attempt, retry)
            return
        except Exception as exc:
            last_error = exc
            if "does not exist" in str(exc).lower() and attempt < retry:
                logger.warning(
                    "Database not ready yet (attempt %d/%d): %s",
                    attempt, retry, exc,
                )
                time.sleep(retry_delay)
            else:
                raise

    if last_error:
        raise RuntimeError(f"Failed to initialize database after {retry} attempts") from last_error


# ── Dependency ──────────────────────────────────────────────────────────────

def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency: yields a database session.

    Usage::

        @app.get("/items")
        def list_items(db: Session = Depends(get_db)):
            ...

    The session is automatically closed when the request finishes.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
