"""Dictionary management API endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session as DBSession

from app.database import get_db
from app.schemas.dictionary import (
    DictionaryCreate,
    DictionaryEntryAdd,
    DictionaryEntryRemove,
    DictionaryUpdate,
)
from app.services import dictionary_service

router = APIRouter(prefix="/v1/dictionaries", tags=["Dictionaries"])


@router.get("")
def list_dictionaries(
    category_id: int | None = Query(default=None),
    is_active: bool | None = Query(default=None),
    db: DBSession = Depends(get_db),
):
    """List all dictionaries with optional filters."""
    return dictionary_service.list_dictionaries(
        db, category_id=category_id, is_active=is_active,
    )


@router.get("/{dict_id}")
def get_dictionary(dict_id: int, db: DBSession = Depends(get_db)):
    """Get a single dictionary by ID."""
    d = dictionary_service.get_dictionary(db, dict_id)
    if d is None:
        raise HTTPException(status_code=404, detail=f"Dictionary not found: {dict_id}")
    return d


@router.get("/by-code/{code}")
def get_dictionary_by_code(code: str, db: DBSession = Depends(get_db)):
    """Get a single dictionary by code."""
    d = dictionary_service.get_dictionary_by_code(db, code)
    if d is None:
        raise HTTPException(status_code=404, detail=f"Dictionary not found: {code}")
    return d


@router.post("", status_code=201)
def create_dictionary(data: DictionaryCreate, db: DBSession = Depends(get_db)):
    """Create a new dictionary."""
    try:
        return dictionary_service.create_dictionary(db, data)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.put("/{dict_id}")
def update_dictionary(dict_id: int, data: DictionaryUpdate, db: DBSession = Depends(get_db)):
    """Update a dictionary."""
    d = dictionary_service.update_dictionary(db, dict_id, data)
    if d is None:
        raise HTTPException(status_code=404, detail=f"Dictionary not found: {dict_id}")
    return d


@router.delete("/{dict_id}", status_code=204)
def delete_dictionary(dict_id: int, db: DBSession = Depends(get_db)):
    """Delete a dictionary."""
    deleted = dictionary_service.delete_dictionary(db, dict_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Dictionary not found: {dict_id}")
    return None


@router.post("/{dict_id}/entries")
def add_entries(dict_id: int, data: DictionaryEntryAdd, db: DBSession = Depends(get_db)):
    """Add entries to a dictionary."""
    d = dictionary_service.add_entries(db, dict_id, data)
    if d is None:
        raise HTTPException(status_code=404, detail=f"Dictionary not found: {dict_id}")
    return d


@router.delete("/{dict_id}/entries", status_code=200)
def remove_entries(dict_id: int, data: DictionaryEntryRemove, db: DBSession = Depends(get_db)):
    """Remove entries from a dictionary."""
    d = dictionary_service.remove_entries(db, dict_id, data)
    if d is None:
        raise HTTPException(status_code=404, detail=f"Dictionary not found: {dict_id}")
    return d
