"""Pattern type service — list detection pattern types."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session as DBSession

from app.models.pattern_type import PatternType


def list_pattern_types(db: DBSession) -> list[dict[str, Any]]:
    """List all detection pattern types."""
    pts = db.query(PatternType).order_by(PatternType.id).all()
    return [_pt_to_dict(p) for p in pts]


def _pt_to_dict(pt: PatternType) -> dict[str, Any]:
    return {
        "id": pt.id,
        "name": pt.name,
        "label": pt.label,
        "description": pt.description,
    }
