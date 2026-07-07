"""Audit chain ORM model — tamper-proof hash chain for audit log integrity.

Implements a Merkle-chain over audit log batches. Each block stores
the SHA-256 hash of the previous block, creating an immutable chain
that can be verified at any time.

Corresponds to the product spec §6.3 audit_chain table.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Integer, String, BigInteger

from app.database import Base


class AuditChain(Base):
    """Audit chain table — hash chain ensuring audit log tamper-proof integrity.

    One row per batch of audit log entries. Forms a linked list via
    ``prev_hash → batch_hash``.
    """

    __tablename__ = "audit_chain"

    id = Column(Integer, primary_key=True, autoincrement=True)
    last_log_id = Column(BigInteger, nullable=False)
    batch_hash = Column(String(64), nullable=False)          # SHA-256 of this batch
    prev_hash = Column(String(64), nullable=False)           # SHA-256 of previous batch
    batch_count = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    def __repr__(self) -> str:
        return (
            f"<AuditChain(id={self.id}, last_log_id={self.last_log_id}, "
            f"hash={self.batch_hash[:16]}..., count={self.batch_count})>"
        )
