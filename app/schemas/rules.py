"""Pydantic schemas for rule management API endpoints."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class RuleSchema(BaseModel):
    """Rule definition as exposed via the API."""

    id: str = Field(..., description="Rule ID, e.g. I-01, SEC-06, U-01")
    name: str = Field(..., description="Human-readable rule name")
    description: str | None = Field(default=None, description="Rule description")
    category: str | None = Field(default=None)
    severity: str = Field(default="P2", pattern=r"^(P0|P1|P2)$")
    action: str = Field(default="warn")
    pattern: str | None = Field(default=None, description="JSON pattern or regex")
    enabled: bool = Field(default=True)
    is_custom: bool = Field(default=False)
    source: str | None = Field(default=None)

    model_config = {"from_attributes": True}


class RuleCreate(BaseModel):
    """Create a new custom rule."""

    id: str = Field(..., pattern=r"^U-\d{2,3}$", description="Custom rule ID, e.g. U-01")
    name: str = Field(..., min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    category: str | None = Field(default=None)
    severity: str = Field(default="P2", pattern=r"^(P0|P1|P2)$")
    action: str = Field(default="warn")
    pattern: str | None = Field(default=None)
    enabled: bool = Field(default=True)


class RuleUpdate(BaseModel):
    """Update an existing rule override."""

    name: str | None = Field(default=None)
    description: str | None = Field(default=None)
    severity: str | None = Field(default=None, pattern=r"^(P0|P1|P2)$")
    action: str | None = Field(default=None)
    pattern: str | None = Field(default=None)
    enabled: bool | None = Field(default=None)


class RuleListResponse(BaseModel):
    """Paginated rule list response."""

    items: list[RuleSchema]
    total: int
    page: int
    page_size: int
