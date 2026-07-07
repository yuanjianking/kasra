"""Audit log ORM model — immutable record of every detection event."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Integer, String, Text, JSON

from app.database import Base


class AuditLog(Base):
    """Audit log table — immutable record of every detection event.

    Corresponds to the product spec §6.3 audit_logs table.
    One row per triggered rule per detection event.
    """

    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    user_id = Column(String(128), nullable=True, index=True)
    session_id = Column(String(128), nullable=True, index=True)
    request_id = Column(String(128), nullable=True)

    # Rule info
    rule_id = Column(String(32), nullable=False, index=True)
    rule_name = Column(String(256), nullable=False)
    category = Column(String(64), nullable=True)
    severity = Column(String(4), nullable=False)  # P0 / P1 / P2
    action = Column(String(16), nullable=False)  # block / warn / redact / clean / truncate

    # Detection context
    direction = Column(String(16), nullable=False)  # input / output / batch / behavior
    content_snippet = Column(Text, nullable=True)
    matched_text = Column(Text, nullable=True)
    file_path = Column(String(1024), nullable=True)
    line_number = Column(Integer, nullable=True)
    match_count = Column(Integer, default=0)

    # Status & extra_metadata
    status = Column(String(16), default="pending")  # pending / resolved / fp (false positive)
    extra_metadata = Column(JSON, nullable=True, default=dict)

    # Compliance flags
    gdpr_relevant = Column(Integer, default=0)  # 0/1 boolean

    def __repr__(self) -> str:
        return (
            f"<AuditLog(id={self.id}, rule={self.rule_id}, "
            f"sev={self.severity}, action={self.action})>"
        )
