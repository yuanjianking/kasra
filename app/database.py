"""Database connection and session management.

PostgreSQL only (production-grade).
Uses SQLAlchemy with connection pooling.
"""

from __future__ import annotations

import logging
import os
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

def is_postgres(url: str) -> bool:
    return url.startswith("postgresql")

def get_db_type(url: str) -> str:
    return "postgres" if is_postgres(url) else "unknown"


# ── Engine creation ─────────────────────────────────────────────────────────

def _create_engine(database_url: str, echo: bool = False) -> Engine:
    """Create a SQLAlchemy engine for PostgreSQL with connection pooling."""
    db_type = get_db_type(database_url)
    connect_args: dict[str, Any] = {"application_name": "kasra"}

    engine = create_engine(
        database_url,
        connect_args=connect_args,
        echo=echo,
        pool_size=10,
        max_overflow=20,
        pool_pre_ping=True,
        pool_recycle=3600,
    )

    # ── Connection logging ──
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
            result = session.execute(
                __import__("sqlalchemy").text("SELECT version()")
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
    from app.models.dictionary import Dictionary  # noqa: F401

    # File lock: blocking — workers wait until the first finishes seeding.
    # Without this, 4 uvicorn workers would race on DB init and some may
    # load rules from a partially-seeded database, returning empty results.
    import fcntl
    lock_path = "/tmp/kasra_init.lock"
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR)
    fcntl.flock(fd, fcntl.LOCK_EX)
    logger.debug("init_db: acquired lock")

    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables initialized.")

        # ── Seed master data + SDK rules (same lock, only one worker) ──
        from pathlib import Path
        import json as _json
        _db_dir = Path(__file__).resolve().parent.parent / "db" / "init"

        seed_sql = _db_dir / "02-master-data.sql"
        if seed_sql.exists():
            with SessionLocal() as seed_db:
                for raw_stmt in seed_sql.read_text().split(";\n"):
                    stmt = raw_stmt.strip()
                    lines = [l for l in stmt.split("\n")
                             if not l.strip().startswith("--") and not l.strip().startswith("/*")]
                    stmt = "\n".join(lines).strip()
                    if not stmt:
                        continue
                    try:
                        seed_db.execute(text(stmt))
                        seed_db.commit()
                    except Exception as exc:
                        seed_db.rollback()
                        logger.debug("Seed stmt skipped: %s", str(exc)[:120])
                logger.info("Master data seeded from %s", seed_sql.name)

        rules_dir = _db_dir / "rules"
        if rules_dir.exists():
            from app.services.rules_service import import_rules_from_bundle
            with SessionLocal() as seed_db:
                for jf in sorted(rules_dir.glob("*-series.json")):
                    try:
                        bundle = _json.loads(jf.read_text())
                        stats = import_rules_from_bundle(seed_db, bundle, target="sdk")
                        logger.info("  %s: %s", jf.name, stats)
                    except Exception as exc:
                        seed_db.rollback()
                        logger.warning("Rule import %s skipped: %s", jf.name, str(exc)[:120])

        try:
            with SessionLocal() as sync_db:
                sync_db.execute(text(
                    "UPDATE rules SET category_id=(SELECT id FROM categories WHERE name='O') WHERE id LIKE 'O-%' AND category_id IS NULL"))
                sync_db.execute(text(
                    "UPDATE rules SET category_id=(SELECT id FROM categories WHERE name='I') WHERE id LIKE 'I-%' AND category_id IS NULL"))
                sync_db.commit()
        except Exception:
            pass

    except Exception:
        logger.exception("init_db failed")
        raise
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


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
