"""Category service — CRUD for rule classification categories."""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.orm import Session as DBSession

from app.models.category import Category
from app.schemas.category import CategoryCreate, CategoryUpdate

logger = logging.getLogger("kasra.service.category")


def list_categories(db: DBSession) -> list[dict[str, Any]]:
    """List all rule categories."""
    cats = db.query(Category).order_by(Category.id).all()
    return [_cat_to_dict(c) for c in cats]


def get_category(db: DBSession, category_id: int) -> dict[str, Any] | None:
    """Get a single category by ID."""
    cat = db.query(Category).filter(Category.id == category_id).first()
    if cat is None:
        return None
    return _cat_to_dict(cat)


def create_category(db: DBSession, data: CategoryCreate) -> dict[str, Any]:
    """Create a new rule category."""
    existing = db.query(Category).filter(Category.name == data.name).first()
    if existing:
        raise ValueError(f"Category '{data.name}' already exists")

    cat = Category(
        name=data.name,
        label=data.label,
        description=data.description,
        color=data.color,
    )
    db.add(cat)
    db.commit()
    db.refresh(cat)
    logger.info("Created category: %s (%s)", cat.name, cat.label)
    return _cat_to_dict(cat)


def update_category(db: DBSession, category_id: int, data: CategoryUpdate) -> dict[str, Any] | None:
    """Update a rule category."""
    cat = db.query(Category).filter(Category.id == category_id).first()
    if cat is None:
        return None

    if data.label is not None:
        cat.label = data.label
    if data.description is not None:
        cat.description = data.description
    if data.color is not None:
        cat.color = data.color

    db.commit()
    db.refresh(cat)
    logger.info("Updated category: %s", cat.name)
    return _cat_to_dict(cat)


def delete_category(db: DBSession, category_id: int) -> bool:
    """Delete a rule category."""
    cat = db.query(Category).filter(Category.id == category_id).first()
    if cat is None:
        return False
    db.delete(cat)
    db.commit()
    logger.info("Deleted category: %s", cat.name)
    return True


def _cat_to_dict(cat: Category) -> dict[str, Any]:
    return {
        "id": cat.id,
        "name": cat.name,
        "label": cat.label,
        "description": cat.description,
        "color": cat.color,
        "created_at": cat.created_at.isoformat() if cat.created_at else None,
    }
