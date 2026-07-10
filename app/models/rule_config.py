"""Rule configuration ORM model — SDK rule enabled/disabled overrides.

Stores only the override state (``enabled``) for SDK built-in rules.
Custom user rules are stored in the separate ``custom_rules`` table.
"""

from __future__ import annotations

from sqlalchemy import Column, String, Text, Boolean, JSON

from app.database import Base


class RuleConfig(Base):
    """Rule configuration table — SDK rule enabled/disabled overrides.

    This table tracks which SDK built-in rules the user has explicitly
    enabled or disabled via the UI. It is NOT used for custom rules
    (those go in ``custom_rules`` instead).
    """

    __tablename__ = "rules"

    id = Column(String(32), primary_key=True)  # e.g. I-01, SEC-06
    name = Column(String(256), nullable=False)
    description = Column(Text, nullable=True)
    category = Column(String(64), nullable=True)
    severity = Column(String(4), nullable=False, default="P2")
    action = Column(String(16), nullable=False, default="warn")
    pattern = Column(Text, nullable=True)
    enabled = Column(Boolean, default=True, nullable=False)
    is_custom = Column(Boolean, default=False, nullable=False)
    source = Column(String(64), nullable=True)  # "sdk"
    extra_metadata = Column(JSON, nullable=True, default=dict)

    def __repr__(self) -> str:
        return (
            f"<RuleConfig(id={self.id}, sev={self.severity}, "
            f"enabled={self.enabled}, custom={self.is_custom})>"
        )
