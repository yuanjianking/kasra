"""Alembic environment configuration for Kasra.

PostgreSQL only.
"""

from __future__ import annotations

import logging
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import engine_from_config, pool

# Alembic Config object
config = context.config

# Set up Python logging from alembic.ini
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# ── Import all models so Alembic can detect schema changes ───────────────────
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.database import Base  # noqa: E402

# Import all model modules so they register on Base.metadata
from app.models.audit_log import AuditLog  # noqa: F401, E402
from app.models.audit_chain import AuditChain  # noqa: F401, E402
from app.models.rule_config import Rule  # noqa: F401, E402
from app.models.category import Category  # noqa: F401, E402
from app.models.pattern_type import PatternType  # noqa: F401, E402
from app.models.custom_rule import CustomRule  # noqa: F401, E402
from app.models.user_behavior import UserBehavior  # noqa: F401, E402
from app.models.user import User  # noqa: F401, E402

target_metadata = Base.metadata

# ── Database URL resolution ───────────────────────────────────────────────────
# Priority:
#   1. Environment variable (KASRA_APP_DATABASE_URL)
#   2. alembic.ini sqlalchemy.url

def get_database_url() -> str:
    import os
    env_url = os.environ.get("KASRA_APP_DATABASE_URL")
    if env_url:
        return env_url
    return config.get_main_option("sqlalchemy.url", "postgresql+psycopg2://kasra:kasra@localhost:5432/kasra")


# ── Migration functions ──────────────────────────────────────────────────────

def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (emit SQL without connecting).

    Useful for generating SQL scripts for production deployment review.
    """
    url = get_database_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,          # Detect column type changes
        compare_server_default=True, # Detect default value changes
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode with a live database connection."""
    cfg = config.get_section(config.config_ini_section, {})
    cfg["sqlalchemy.url"] = get_database_url()

    connectable = engine_from_config(
        cfg,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,  # Single connection for migrations
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
