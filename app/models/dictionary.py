"""Dictionary ORM model — keyword lists referenced by rules.

Rules can reference dictionaries via ``detection_config`` patterns
with ``"type": "dictionary", "ref": "<code>"``.  The engine loads
the entry list and expands each entry into a ``keyword`` pattern.

Dictionaries are category-aware (via ``category_id``) so the UI can
filter by category, and the ``code`` field is what rules reference.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, JSON, String, Text, func

from app.database import Base


class Dictionary(Base):
    """Keyword dictionary — a named, versioned list of keywords."""

    __tablename__ = "dictionaries"

    id = Column(Integer, primary_key=True, autoincrement=True)
    code = Column(String(128), nullable=False, unique=True)
    name = Column(String(256), nullable=False)
    description = Column(Text, nullable=True)
    entries = Column(JSON, nullable=False, default=list)

    category_id = Column(Integer, ForeignKey("categories.id", ondelete="SET NULL"), nullable=True)

    is_active = Column(Boolean, default=True, nullable=False)
    version = Column(Integer, default=1, nullable=False)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    def __repr__(self) -> str:
        return f"<Dictionary(id={self.id}, code={self.code}, entries={len(self.entries)})>"
