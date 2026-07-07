"""Rule configuration ORM model — overrides and custom rules.

Stores both:
  - Snapshots of SDK built-in rules (for UI display)
  - User-created custom rules (U-series)
"""

from __future__ import annotations

from sqlalchemy import Column, Integer, String, Text, Boolean, JSON

from app.database import Base


class RuleConfig(Base):
    """Rule configuration table — SDK rule snapshots + user custom rules.

    Corresponds to the product spec §6.3 rules table.
    """

    __tablename__ = "rules"

    id = Column(String(32), primary_key=True)  # e.g. I-01, SEC-06, U-01
    name = Column(String(256), nullable=False)
    description = Column(Text, nullable=True)
    category = Column(String(64), nullable=True)  # credential_leak, pii, injection, security, etc.
    severity = Column(String(4), nullable=False, default="P2")  # P0 / P1 / P2
    action = Column(String(16), nullable=False, default="warn")  # block / warn / redact / clean
    pattern = Column(Text, nullable=True)  # regex or JSON pattern definition
    enabled = Column(Boolean, default=True, nullable=False)
    is_custom = Column(Boolean, default=False, nullable=False)
    source = Column(String(64), nullable=True)  # "sdk", "user"
    extra_metadata = Column("metadata", JSON, nullable=True, default=dict)

    def __repr__(self) -> str:
        return (
            f"<RuleConfig(id={self.id}, sev={self.severity}, "
            f"enabled={self.enabled}, custom={self.is_custom})>"
        )
