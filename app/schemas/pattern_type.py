"""Pydantic schemas for pattern type API endpoints."""

from __future__ import annotations

from pydantic import BaseModel, Field


class PatternTypeSchema(BaseModel):
    """Detection pattern type definition."""

    id: int = Field(..., description="Pattern type ID")
    name: str = Field(..., description="Type name: regex, keyword, yaml_path, ...")
    label: str = Field(..., description="Display label, e.g. Regex Match")
    description: str | None = Field(default=None)

    model_config = {"from_attributes": True}
