"""Rule ORM model — built-in SDK rules synced from the SDK rule bundle.

This table stores the canonical rule definitions for all SDK-supplied rules.
Rules are initially seeded from the SDK JSON bundle, and can be updated
via the import/export mechanism or the UI.

Custom user rules are stored in the separate ``custom_rules`` table.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, JSON, String, Text, func

from app.database import Base


class Rule(Base):
    """Built-in SDK detection rule.

    Each row represents one rule from an SDK rule series (I, O, SEC, IAC, …).
    Rules are categorized via ``category_id`` → ``categories`` table.
    """

    __tablename__ = "rules"

    id = Column(String(50), primary_key=True)  # I-01, SEC-06
    name = Column(String(256), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(4), nullable=False, default="P2")  # P0 / P1 / P2
    action = Column(String(16), nullable=False, default="warn")  # block / warn / redact / clean

    # ── Classification ──
    category_id = Column(Integer, ForeignKey("categories.id"), nullable=True)
    rule_type = Column(String(20), nullable=False, default="io")  # io | code_review | behavior
    applicable_stages = Column(JSON, nullable=False, default=list)  # ["input"], ["output"], ["batch"]

    # ── Detection config (full JSON) ──
    detection_config = Column(JSON, nullable=False, default=dict)

    # ── Metadata ──
    enabled = Column(Boolean, default=True, nullable=False)
    source = Column(String(64), nullable=True)  # "sdk"
    bundle_series = Column(String(20), nullable=True)  # "I", "O", "SEC"
    sdk_version = Column(Integer, default=1)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    def __repr__(self) -> str:
        return (
            f"<Rule(id={self.id}, sev={self.severity}, "
            f"enabled={self.enabled})>"
        )
