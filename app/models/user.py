"""User management ORM model."""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Integer, String, Boolean

from app.database import Base


class User(Base):
    """Users table — API user authentication and management."""

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(128), unique=True, nullable=False, index=True)
    email = Column(String(256), unique=True, nullable=True)
    api_key_hash = Column(String(256), nullable=True)  # Reserved for per-user API key auth (future)
    role = Column(String(32), default="user", nullable=False)  # admin / user / readonly
    team = Column(String(128), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    def __repr__(self) -> str:
        return f"<User(id={self.id}, username={self.username}, role={self.role})>"

    # ── API Key Management (for future per-user key auth) ──
    # Currently Kasra uses a single global API key configured via KASRA_APP_API_KEY env var.
    # The methods below enable per-user API key authentication when enabled.

    def set_api_key(self, api_key: str) -> None:
        """Hash and store an API key."""
        salt = secrets.token_hex(16)
        self.api_key_hash = hashlib.sha256(f"{salt}:{api_key}".encode()).hexdigest()
        # Store salt as first 32 chars of hash
        self.api_key_hash = salt + self.api_key_hash

    def verify_api_key(self, api_key: str) -> bool:
        """Verify an API key against the stored hash."""
        if not self.api_key_hash or len(self.api_key_hash) < 32:
            return False
        salt = self.api_key_hash[:32]
        stored_hash = self.api_key_hash[32:]
        computed = hashlib.sha256(f"{salt}:{api_key}".encode()).hexdigest()
        return computed == stored_hash
