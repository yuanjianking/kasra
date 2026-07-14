"""Database migration helper — schema upgrades, master data seeding.

Handles incremental schema changes that go beyond what
``Base.metadata.create_all()`` can do (e.g. adding columns
to existing tables, seeding reference data).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine

from app.database import Base, SessionLocal, engine

logger = logging.getLogger("kasra.migration")


# ── Schema upgrades ──────────────────────────────────────────────────────


def _column_exists(engine: Engine, table: str, column: str) -> bool:
    """Check if a column exists in a table."""
    inspector = inspect(engine)
    columns = [c["name"] for c in inspector.get_columns(table)]
    return column in columns


def _table_exists(engine: Engine, table: str) -> bool:
    """Check if a table exists."""
    inspector = inspect(engine)
    return table in inspector.get_table_names()


def _upgrade_to_v2(engine: Engine) -> None:
    """Upgrade schema to v2: add master tables and FK columns.

    1. Create ``categories`` table
    2. Create ``pattern_types`` table
    3. Add ``category_id``, ``rule_type``, ``detection_config`` to ``rules`` table
    4. Add ``category_id``, ``rule_type``, ``pattern_type_id`` to ``custom_rules`` table
    """
    db_type = "postgresql" if "postgresql" in str(engine.url) else "sqlite"

    # -- 1. Create categories table --
    if not _table_exists(engine, "categories"):
        logger.info("Creating categories table...")
        with engine.connect() as conn:
            if db_type == "sqlite":
                conn.execute(text("""
                    CREATE TABLE categories (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name VARCHAR(50) NOT NULL UNIQUE,
                        label VARCHAR(100) NOT NULL,
                        description TEXT,
                        color VARCHAR(7) DEFAULT '#6366f1',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """))
            else:
                conn.execute(text("""
                    CREATE TABLE categories (
                        id SERIAL PRIMARY KEY,
                        name VARCHAR(50) NOT NULL UNIQUE,
                        label VARCHAR(100) NOT NULL,
                        description TEXT,
                        color VARCHAR(7) DEFAULT '#6366f1',
                        created_at TIMESTAMPTZ DEFAULT NOW()
                    )
                """))
            conn.commit()
        logger.info("categories table created.")
    else:
        logger.debug("categories table already exists.")

    # -- 2. Create pattern_types table --
    if not _table_exists(engine, "pattern_types"):
        logger.info("Creating pattern_types table...")
        with engine.connect() as conn:
            if db_type == "sqlite":
                conn.execute(text("""
                    CREATE TABLE pattern_types (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name VARCHAR(50) NOT NULL UNIQUE,
                        label VARCHAR(100) NOT NULL,
                        description TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """))
            else:
                conn.execute(text("""
                    CREATE TABLE pattern_types (
                        id SERIAL PRIMARY KEY,
                        name VARCHAR(50) NOT NULL UNIQUE,
                        label VARCHAR(100) NOT NULL,
                        description TEXT,
                        created_at TIMESTAMPTZ DEFAULT NOW()
                    )
                """))
            conn.commit()
        logger.info("pattern_types table created.")
    else:
        logger.debug("pattern_types table already exists.")

    # -- 3. Add columns to rules table --
    rules_additions = [
        ("category_id", "INTEGER REFERENCES categories(id)" if db_type == "sqlite" else "INTEGER REFERENCES categories(id)"),
        ("rule_type", "VARCHAR(20) NOT NULL DEFAULT 'io'"),
        ("applicable_stages", "JSON NOT NULL DEFAULT '[]'"),
        ("detection_config", "JSON NOT NULL DEFAULT '{}'"),
        ("bundle_series", "VARCHAR(20)"),
        ("sdk_version", "INTEGER DEFAULT 1"),
        ("updated_at", "TIMESTAMP" if db_type == "sqlite" else "TIMESTAMPTZ DEFAULT NOW()"),
    ]
    if _table_exists(engine, "rules"):
        for col_name, col_def in rules_additions:
            if not _column_exists(engine, "rules", col_name):
                logger.info("Adding column rules.%s ...", col_name)
                with engine.connect() as conn:
                    conn.execute(text(
                        f"ALTER TABLE rules ADD COLUMN {col_name} {col_def}"
                    ))
                    conn.commit()
                logger.info("Column rules.%s added.", col_name)

    # -- 4. Add columns to custom_rules table --
    cr_additions = [
        ("category_id", "INTEGER REFERENCES categories(id)" if db_type == "sqlite" else "INTEGER REFERENCES categories(id)"),
        ("rule_type", "VARCHAR(20) NOT NULL DEFAULT 'io'"),
        ("pattern_type_id", "INTEGER REFERENCES pattern_types(id)" if db_type == "sqlite" else "INTEGER REFERENCES pattern_types(id)"),
        ("detection_config", "JSON"),
        ("created_by", "VARCHAR(100)"),
        ("updated_at", "TIMESTAMP" if db_type == "sqlite" else "TIMESTAMPTZ DEFAULT NOW()"),
    ]
    if _table_exists(engine, "custom_rules"):
        for col_name, col_def in cr_additions:
            if not _column_exists(engine, "custom_rules", col_name):
                logger.info("Adding column custom_rules.%s ...", col_name)
                with engine.connect() as conn:
                    conn.execute(text(
                        f"ALTER TABLE custom_rules ADD COLUMN {col_name} {col_def}"
                    ))
                    conn.commit()
                logger.info("Column custom_rules.%s added.", col_name)


# ── Master data seeding ────────────────────────────────────────────────


SEED_CATEGORIES = [
    {"name": "I",   "label": "Input Detection",       "description": "Rules that detect security issues in user input",        "color": "#ef4444"},
    {"name": "O",   "label": "Output Detection",      "description": "Rules that detect security issues in AI output",        "color": "#f97316"},
    {"name": "SEC", "label": "Code Security",         "description": "Code review rules for security vulnerabilities",         "color": "#8b5cf6"},
    {"name": "IAC", "label": "Infrastructure as Code", "description": "Rules for Docker, K8s, and IaC misconfigurations",     "color": "#06b6d4"},
    {"name": "BEHAVIOR", "label": "Behavior Monitoring", "description": "Rules for detecting anomalous user/agent behavior", "color": "#ec4899"},
]

SEED_PATTERN_TYPES = [
    {"name": "regex",      "label": "Regex Match",       "description": "Regular expression pattern matching"},
    {"name": "keyword",    "label": "Keyword Match",     "description": "Exact keyword or substring matching"},
    {"name": "dictionary", "label": "Dictionary Match",       "description": "Dictionary/list-based matching"},
    {"name": "yaml_path",  "label": "YAML Path Match",  "description": "YAML key path with value regex"},
    {"name": "dockerfile", "label": "Dockerfile Match", "description": "Dockerfile instruction matching"},
    {"name": "keyvalue",   "label": "Key-Value Match",    "description": "Key=value pair matching for .env files"},
]


def seed_master_data() -> None:
    """Seed master data into categories and pattern_types tables.

    Safe to call multiple times — uses INSERT OR IGNORE / ON CONFLICT.
    """
    db = SessionLocal()
    db_type = "postgresql" if "postgresql" in str(engine.url) else "sqlite"
    try:
        # -- Seed categories --
        for cat in SEED_CATEGORIES:
            if db_type == "sqlite":
                existing = db.execute(
                    text("SELECT id FROM categories WHERE name = :name"),
                    {"name": cat["name"]},
                ).scalar()
            else:
                existing = db.execute(
                    text("SELECT id FROM categories WHERE name = :name"),
                    {"name": cat["name"]},
                ).scalar()
            if existing is None:
                db.execute(
                    text(
                        "INSERT INTO categories (name, label, description, color) "
                        "VALUES (:name, :label, :description, :color)"
                    ),
                    cat,
                )
                logger.info("Seeded category: %s", cat["name"])

        # -- Seed pattern types --
        for pt in SEED_PATTERN_TYPES:
            if db_type == "sqlite":
                existing = db.execute(
                    text("SELECT id FROM pattern_types WHERE name = :name"),
                    {"name": pt["name"]},
                ).scalar()
            else:
                existing = db.execute(
                    text("SELECT id FROM pattern_types WHERE name = :name"),
                    {"name": pt["name"]},
                ).scalar()
            if existing is None:
                db.execute(
                    text(
                        "INSERT INTO pattern_types (name, label, description) "
                        "VALUES (:name, :label, :description)"
                    ),
                    pt,
                )
                logger.info("Seeded pattern_type: %s", pt["name"])

        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Failed to seed master data")
        raise
    finally:
        db.close()


# ── SDK rule seeding (from DML SQL file) ──────────────────────────────


def seed_sdk_rules_from_dml() -> None:
    """Seed SDK rules into the ``rules`` table from the DML SQL file.

    The canonical rule data lives in ``db/init/02-dml.sql`` (193 INSERT
    statements, one per SDK rule). This function reads and executes that
    file for SQLite development environments where the DML is not run
    separately.

    Safe to call multiple times — all INSERTs use WHERE NOT EXISTS.
    For PostgreSQL production, the DML is run directly by the DBA/deploy.
    """
    dml_path = Path(__file__).resolve().parent.parent / "db" / "init" / "02-dml.sql"
    if not dml_path.exists():
        logger.warning("DML file not found at %s — cannot seed rules.", dml_path)
        return

    db = SessionLocal()
    try:
        existing_count = db.execute(text("SELECT COUNT(*) FROM rules")).scalar()
        if existing_count and existing_count > 0:
            logger.info("Rules table already has %d entries — skipping DML seed.", existing_count)
            return

        dml_sql = dml_path.read_text()

        # Extract INSERT INTO rules statements using semicolons as terminators
        statements = []
        current = []
        for line in dml_sql.splitlines():
            stripped = line.strip()
            if stripped.startswith("--") or stripped == "":
                if current and current[-1].rstrip().endswith(";"):
                    statements.append(" ".join(current))
                    current = []
                continue
            if stripped.startswith("INSERT INTO rules"):
                current = [line]
            elif current:
                current.append(line)
                if stripped.endswith(";"):
                    statements.append(" ".join(current))
                    current = []

        # Execute raw SQL directly on the DBAPI connection to avoid
        # SQLAlchemy interpreting :RSA as bind parameters.
        raw_conn = db.connection().connection
        cursor = raw_conn.cursor()
        for stmt in statements:
            try:
                cursor.execute(stmt)
            except Exception as exc:
                logger.warning("DML insert skipped: %s — %s", stmt[:60], exc)
        raw_conn.commit()
        cursor.close()

        db.commit()
        count = db.execute(text("SELECT COUNT(*) FROM rules")).scalar()
        logger.info("Seeded %d SDK rules from DML (%d statements).", count, len(statements))
    except Exception:
        db.rollback()
        logger.exception("Failed to seed rules from DML")
        raise
    finally:
        db.close()


def run_migrations() -> None:
    """Run all pending schema upgrades and seed master data."""
    _upgrade_to_v2(engine)
    seed_master_data()
    logger.info("Migrations complete.")
