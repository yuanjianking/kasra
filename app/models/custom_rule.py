"""Custom rule ORM model — user-defined detection rules.

Stored in a separate ``custom_rules`` table, independent from
the SDK built-in rules (``rules`` table). Each custom rule can be
categorized and use a specific detection pattern type.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, JSON, String, Text, func

from app.database import Base


class CustomRule(Base):
    """User-defined detection rule.

    Each custom rule has:
      - A detection type (regex / keyword) via ``pattern_type_id``
      - A pattern value (the actual regex or keyword text)
      - Applicable stages (input / output / batch)
      - A category reference
    """

    __tablename__ = "custom_rules"

    id = Column(String(32), primary_key=True)  # U-01, U-02, ...
    name = Column(String(256), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(4), nullable=False, default="P2")  # P0 / P1 / P2
    action = Column(String(16), nullable=False, default="warn")  # block / warn / redact / clean

    # ── Classification ──
    category_id = Column(Integer, ForeignKey("categories.id"), nullable=True)
    rule_type = Column(String(20), nullable=False, default="io")  # io | code_review | behavior
    applicable_stages = Column(JSON, nullable=False, default=list)  # ["input"], ["output"], ["batch"]
    target_files = Column(JSON, nullable=True)  # ["**/*.py"] for code review

    # ── Detection method ──
    pattern_type_id = Column(Integer, ForeignKey("pattern_types.id"), nullable=True)
    pattern_type = Column(String(32), nullable=False, default="regex")  # legacy: regex / keyword
    pattern_value = Column(Text, nullable=False, default="")
    pattern_confidence = Column(String(10), nullable=True, default="0.8")
    detection_config = Column(JSON, nullable=True)  # full JSON for advanced editing

    enabled = Column(Boolean, default=True, nullable=False)
    created_by = Column(String(100), nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    def __repr__(self) -> str:
        return (
            f"<CustomRule(id={self.id}, sev={self.severity}, "
            f"type={self.pattern_type}, enabled={self.enabled})>"
        )
