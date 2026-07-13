"""Pydantic schemas for rule category API endpoints."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class CategorySchema(BaseModel):
    """Rule category definition."""

    id: int = Field(..., description="Category ID")
    name: str = Field(..., description="Category short name, e.g. I, O, SEC")
    label: str = Field(..., description="Display label, e.g. Input Detection")
    description: str | None = Field(default=None)
    color: str = Field(default="#6366f1", description="UI tag color")

    created_at: datetime | None = Field(default=None)

    model_config = {"from_attributes": True}


class CategoryCreate(BaseModel):
    """Create a new rule category."""

    name: str = Field(..., min_length=1, max_length=50, description="Short name, e.g. BEHAVIOR")
    label: str = Field(..., min_length=1, max_length=100, description="Display label")
    description: str | None = Field(default=None, max_length=500)
    color: str = Field(default="#6366f1", description="UI tag color")


class CategoryUpdate(BaseModel):
    """Update a rule category."""

    label: str | None = Field(default=None)
    description: str | None = Field(default=None)
    color: str | None = Field(default=None)
