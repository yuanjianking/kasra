"""Category management API endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session as DBSession

from app.database import get_db
from app.schemas.category import CategoryCreate, CategoryUpdate
from app.services import category_service, pattern_type_service

router = APIRouter(prefix="/v1/categories", tags=["Categories"])


@router.get("")
def list_categories(db: DBSession = Depends(get_db)):
    """List all rule categories."""
    return category_service.list_categories(db)


@router.get("/pattern-types")
def list_pattern_types(db: DBSession = Depends(get_db)):
    """List all detection pattern types."""
    return pattern_type_service.list_pattern_types(db)


@router.get("/{category_id}")
def get_category(category_id: int, db: DBSession = Depends(get_db)):
    """Get a single category by ID."""
    cat = category_service.get_category(db, category_id)
    if cat is None:
        raise HTTPException(status_code=404, detail=f"Category not found: {category_id}")
    return cat


@router.post("", status_code=201)
def create_category(data: CategoryCreate, db: DBSession = Depends(get_db)):
    """Create a new rule category."""
    try:
        return category_service.create_category(db, data)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.put("/{category_id}")
def update_category(category_id: int, data: CategoryUpdate, db: DBSession = Depends(get_db)):
    """Update a rule category."""
    cat = category_service.update_category(db, category_id, data)
    if cat is None:
        raise HTTPException(status_code=404, detail=f"Category not found: {category_id}")
    return cat


@router.delete("/{category_id}", status_code=204)
def delete_category(category_id: int, db: DBSession = Depends(get_db)):
    """Delete a rule category."""
    deleted = category_service.delete_category(db, category_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Category not found: {category_id}")
    return None
