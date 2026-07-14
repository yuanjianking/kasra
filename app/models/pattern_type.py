"""PatternType ORM model — detection method classification master table.

Stores types like regex, keyword, dictionary, yaml_path, dockerfile, keyvalue.
Both built-in and custom rules reference this.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Column, DateTime, Integer, String, Text, func

from app.database import Base


class PatternType(Base):
    """Pattern type master data.

    Examples: regex, keyword,
    yaml_path, dockerfile.
    """

    __tablename__ = "pattern_types"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(50), nullable=False, unique=True)  # regex, keyword
    label = Column(String(100), nullable=False)              # display label
    description = Column(Text, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    def __repr__(self) -> str:
        return f"<PatternType(id={self.id}, name={self.name})>"
