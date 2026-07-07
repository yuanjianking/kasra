"""Alembic migration script template.

Usage:
    alembic revision --autogenerate -m "description of change"
    alembic upgrade head
    alembic downgrade -1
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

# Revision identifiers
revision: str = "0001"
down_revision: str | None = None
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    """Create all initial tables."""
    # ── Users table ──
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("username", sa.String(length=64), nullable=False),
        sa.Column("email", sa.String(length=128), nullable=True),
        sa.Column("role", sa.String(length=16), nullable=True, server_default="user"),
        sa.Column("is_active", sa.Boolean(), nullable=True, server_default="1"),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("username"),
    )

    # ── Rule configurations table ──
    op.create_table(
        "rule_configs",
        sa.Column("id", sa.String(length=16), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("category", sa.String(length=64), nullable=True),
        sa.Column("severity", sa.String(length=4), nullable=True),
        sa.Column("action", sa.String(length=16), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=True, server_default="1"),
        sa.Column("is_custom", sa.Boolean(), nullable=True, server_default="0"),
        sa.Column("source", sa.String(length=16), nullable=True, server_default="sdk"),
        sa.Column("priority", sa.Integer(), nullable=True, server_default="100"),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )

    # ── Audit logs table ──
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("timestamp", sa.DateTime(), nullable=False),
        sa.Column("user_id", sa.String(length=64), nullable=True),
        sa.Column("session_id", sa.String(length=64), nullable=True),
        sa.Column("request_id", sa.String(length=64), nullable=True),
        sa.Column("rule_id", sa.String(length=16), nullable=True),
        sa.Column("rule_name", sa.String(length=128), nullable=True),
        sa.Column("severity", sa.String(length=4), nullable=True),
        sa.Column("action", sa.String(length=16), nullable=True),
        sa.Column("direction", sa.String(length=16), nullable=True),
        sa.Column("content_snippet", sa.Text(), nullable=True),
        sa.Column("matched_text", sa.Text(), nullable=True),
        sa.Column("file_path", sa.Text(), nullable=True),
        sa.Column("line_number", sa.Integer(), nullable=True),
        sa.Column("match_count", sa.Integer(), nullable=True, server_default="0"),
        sa.Column("status", sa.String(length=16), nullable=True, server_default="pending"),
        sa.Column("gdpr_relevant", sa.Boolean(), nullable=True, server_default="0"),
        sa.Column("extra_metadata", sa.JSON(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_audit_logs_timestamp", "audit_logs", ["timestamp"])
    op.create_index("idx_audit_logs_user_id", "audit_logs", ["user_id"])
    op.create_index("idx_audit_logs_direction", "audit_logs", ["direction"])
    op.create_index("idx_audit_logs_severity", "audit_logs", ["severity"])
    op.create_index("idx_audit_logs_status", "audit_logs", ["status"])

    # ── Audit chain table ──
    op.create_table(
        "audit_chain",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("last_log_id", sa.BigInteger(), nullable=False),
        sa.Column("batch_hash", sa.String(length=64), nullable=False),
        sa.Column("prev_hash", sa.String(length=64), nullable=False),
        sa.Column("batch_count", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )

    # ── User behavior table ──
    op.create_table(
        "user_behavior",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.String(length=64), nullable=False),
        sa.Column("date", sa.Date(), nullable=False),
        sa.Column("total_requests", sa.Integer(), nullable=True, server_default="0"),
        sa.Column("blocked_requests", sa.Integer(), nullable=True, server_default="0"),
        sa.Column("warned_requests", sa.Integer(), nullable=True, server_default="0"),
        sa.Column("first_request", sa.Time(), nullable=True),
        sa.Column("last_request", sa.Time(), nullable=True),
        sa.Column("rule_triggers", sa.JSON(), nullable=True),
        sa.Column("anomaly_score", sa.Float(), nullable=True, server_default="0.0"),
        sa.Column("risk_score", sa.Float(), nullable=True, server_default="0.0"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", "date", name="uq_user_behavior_date"),
    )


def downgrade() -> None:
    """Drop all tables."""
    op.drop_table("user_behavior")
    op.drop_table("audit_chain")
    op.drop_table("audit_logs")
    op.drop_index("idx_audit_logs_timestamp", table_name="audit_logs")
    op.drop_index("idx_audit_logs_user_id", table_name="audit_logs")
    op.drop_index("idx_audit_logs_direction", table_name="audit_logs")
    op.drop_index("idx_audit_logs_severity", table_name="audit_logs")
    op.drop_index("idx_audit_logs_status", table_name="audit_logs")
    op.drop_table("rule_configs")
    op.drop_table("users")
