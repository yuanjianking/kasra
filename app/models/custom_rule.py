"""Custom rule ORM model — user-defined detection rules.

Stored in a separate ``custom_rules`` table, completely independent from
the SDK built-in rules (which live in JSON files and are mirrored in
``rules`` table only for override state).
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Column, DateTime, String, Text, Boolean, JSON, func

from app.database import Base


class CustomRule(Base):
    """User-defined detection rule.

    Each custom rule has:
      - A detection type (regex / keyword)
      - A pattern value (the actual regex or keyword text)
      - Applicable stages (input / output / batch for code review)
      - Optional target files globs (for code review rules)

    Custom rules are injected into the live RuleEngine at startup
    and on create/update/delete.
    """

    __tablename__ = "custom_rules"

    id = Column(String(32), primary_key=True)  # U-01, U-02, ...
    name = Column(String(256), nullable=False)
    description = Column(Text, nullable=True)
    category = Column(String(64), nullable=True)  # custom, credential_leak, pii, ...
    severity = Column(String(4), nullable=False, default="P2")  # P0 / P1 / P2
    action = Column(String(16), nullable=False, default="warn")  # block / warn / redact / clean

    # Detection method
    pattern_type = Column(String(32), nullable=False, default="regex")  # regex / keyword
    pattern_value = Column(Text, nullable=False, default="")            # the regex or keyword text
    pattern_confidence = Column(String(10), nullable=True, default="0.8")

    # Rule classification
    applicable_stages = Column(JSON, nullable=False, default=list)  # ["input"], ["output"], ["batch"]
    target_files = Column(JSON, nullable=True)                      # ["**/*.py"] for code review rules

    enabled = Column(Boolean, default=True, nullable=False)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    def __repr__(self) -> str:
        return (
            f"<CustomRule(id={self.id}, sev={self.severity}, "
            f"type={self.pattern_type}, enabled={self.enabled})>"
        )
