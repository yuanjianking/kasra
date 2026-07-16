"""Dictionary service — CRUD for keyword dictionaries."""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.orm import Session as DBSession

from app.models.dictionary import Dictionary
from app.schemas.dictionary import (
    DictionaryCreate,
    DictionaryEntryAdd,
    DictionaryEntryRemove,
    DictionaryUpdate,
)

logger = logging.getLogger("kasra.service.dictionary")


def list_dictionaries(
    db: DBSession,
    *,
    category_id: int | None = None,
    is_active: bool | None = None,
) -> list[dict[str, Any]]:
    """List all dictionaries, with optional filters."""
    query = db.query(Dictionary)
    if category_id is not None:
        query = query.filter(Dictionary.category_id == category_id)
    if is_active is not None:
        query = query.filter(Dictionary.is_active == is_active)
    items = query.order_by(Dictionary.code).all()
    return [_dict_to_dict(d) for d in items]


def get_dictionary(db: DBSession, dict_id: int) -> dict[str, Any] | None:
    """Get a single dictionary by ID."""
    d = db.query(Dictionary).filter(Dictionary.id == dict_id).first()
    return _dict_to_dict(d) if d else None


def get_dictionary_by_code(db: DBSession, code: str) -> dict[str, Any] | None:
    """Get a single dictionary by code."""
    d = db.query(Dictionary).filter(Dictionary.code == code).first()
    return _dict_to_dict(d) if d else None


def create_dictionary(db: DBSession, data: DictionaryCreate) -> dict[str, Any]:
    """Create a new dictionary."""
    existing = db.query(Dictionary).filter(Dictionary.code == data.code).first()
    if existing:
        raise ValueError(f"Dictionary '{data.code}' already exists")

    d = Dictionary(
        code=data.code,
        name=data.name,
        description=data.description,
        entries=data.entries,
        category_id=data.category_id,
    )
    db.add(d)
    db.commit()
    db.refresh(d)
    logger.info("Created dictionary: %s (%d entries)", d.code, len(d.entries))
    return _dict_to_dict(d)


def update_dictionary(
    db: DBSession, dict_id: int, data: DictionaryUpdate
) -> dict[str, Any] | None:
    """Update a dictionary."""
    d = db.query(Dictionary).filter(Dictionary.id == dict_id).first()
    if d is None:
        return None

    if data.name is not None:
        d.name = data.name
    if data.description is not None:
        d.description = data.description
    if data.entries is not None:
        d.entries = data.entries
        d.version += 1
    if data.category_id is not None:
        d.category_id = data.category_id
    if data.is_active is not None:
        d.is_active = data.is_active

    db.commit()
    db.refresh(d)
    logger.info("Updated dictionary: %s (v%d, entries=%d)", d.code, d.version, len(d.entries))
    return _dict_to_dict(d)


def delete_dictionary(db: DBSession, dict_id: int) -> bool:
    """Delete a dictionary."""
    d = db.query(Dictionary).filter(Dictionary.id == dict_id).first()
    if d is None:
        return False
    db.delete(d)
    db.commit()
    logger.info("Deleted dictionary: %s", d.code)
    return True


def add_entries(db: DBSession, dict_id: int, data: DictionaryEntryAdd) -> dict[str, Any] | None:
    """Add entries to a dictionary."""
    d = db.query(Dictionary).filter(Dictionary.id == dict_id).first()
    if d is None:
        return None

    existing = set(d.entries or [])
    new_entries = [e for e in data.entries if e not in existing]
    if new_entries:
        d.entries = d.entries + new_entries
        d.version += 1
        db.commit()
        db.refresh(d)
        logger.info("Added %d entries to dictionary %s (total: %d)", len(new_entries), d.code, len(d.entries))
    return _dict_to_dict(d)


def remove_entries(db: DBSession, dict_id: int, data: DictionaryEntryRemove) -> dict[str, Any] | None:
    """Remove entries from a dictionary."""
    d = db.query(Dictionary).filter(Dictionary.id == dict_id).first()
    if d is None:
        return None

    remove_set = set(data.entries)
    new_entries = [e for e in (d.entries or []) if e not in remove_set]
    if len(new_entries) != len(d.entries):
        d.entries = new_entries
        d.version += 1
        db.commit()
        db.refresh(d)
        logger.info("Removed %d entries from dictionary %s (total: %d)", len(data.entries), d.code, len(d.entries))
    return _dict_to_dict(d)


def load_active_dictionary_map(db: DBSession) -> dict[str, list[str]]:
    """Load all active dictionaries into a ``{code: [entries]}`` map.

    Used by ``engine_service`` when resolving ``type: dictionary`` refs.
    """
    items = db.query(Dictionary).filter(Dictionary.is_active == True).all()  # noqa: E712
    return {d.code: d.entries or [] for d in items}


def _dict_to_dict(d: Dictionary) -> dict[str, Any]:
    return {
        "id": d.id,
        "code": d.code,
        "name": d.name,
        "description": d.description,
        "entries": d.entries or [],
        "category_id": d.category_id,
        "is_active": d.is_active,
        "version": d.version,
        "created_at": d.created_at.isoformat() if d.created_at else None,
        "updated_at": d.updated_at.isoformat() if d.updated_at else None,
    }
