"""Category ORM model — rule classification master table.

Categories classify rules by purpose: input detection (I),
output detection (O), code security (SEC), infrastructure (IAC), etc.
Both built-in and custom rules reference this table.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Column, DateTime, Integer, String, Text, func

from app.database import Base


class Category(Base):
    """Rule category master data.

    Examples: I (Input Detection), O (Output Detection),
    SEC (Code Security), IAC (Infrastructure as Code).
    """

    __tablename__ = "categories"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(50), nullable=False, unique=True)  # I, O, SEC, IAC
    label = Column(String(100), nullable=False)              # Input Detection
    description = Column(Text, nullable=True)
    color = Column(String(7), default="#6366f1")

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    def __repr__(self) -> str:
        return f"<Category(id={self.id}, name={self.name})>"
