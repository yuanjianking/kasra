"""Pydantic schemas for dictionary management API endpoints."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class DictionarySchema(BaseModel):
    """Dictionary definition returned by the API."""

    id: int = Field(..., description="Dictionary ID")
    code: str = Field(..., description="Unique code referenced by rules, e.g. gdpr_health")
    name: str = Field(..., description="Human-readable name")
    description: str | None = Field(default=None)
    entries: list[str] = Field(default_factory=list, description="List of keywords")
    category_id: int | None = Field(default=None)
    is_active: bool = Field(default=True)
    version: int = Field(default=1)

    created_at: datetime | None = Field(default=None)
    updated_at: datetime | None = Field(default=None)

    model_config = {"from_attributes": True}


class DictionaryCreate(BaseModel):
    """Create a new dictionary."""

    code: str = Field(..., min_length=1, max_length=128, pattern=r"^[a-z][a-z0-9_]{0,127}$")
    name: str = Field(..., min_length=1, max_length=256)
    description: str | None = Field(default=None, max_length=1000)
    entries: list[str] = Field(default_factory=list)
    category_id: int | None = Field(default=None)


class DictionaryUpdate(BaseModel):
    """Update a dictionary."""

    name: str | None = Field(default=None, max_length=256)
    description: str | None = Field(default=None, max_length=1000)
    entries: list[str] | None = Field(default=None)
    category_id: int | None = Field(default=None)
    is_active: bool | None = Field(default=None)


class DictionaryEntryAdd(BaseModel):
    """Add entries to a dictionary."""

    entries: list[str] = Field(..., min_length=1, max_length=1000)


class DictionaryEntryRemove(BaseModel):
    """Remove entries from a dictionary."""

    entries: list[str] = Field(..., min_length=1, max_length=1000)
