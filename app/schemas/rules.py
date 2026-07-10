"""Pydantic schemas for rule management API endpoints."""

from __future__ import annotations

from pydantic import BaseModel, Field


PATTERN_TYPES = ["regex", "keyword"]
PATTERN_TYPES_LITERAL = "|".join(PATTERN_TYPES)


class RuleSchema(BaseModel):
    """Unified rule definition as exposed via the API.

    Represents either an SDK built-in rule or a user-created custom rule.
    """

    id: str = Field(..., description="Rule ID, e.g. I-01, SEC-06, U-01")
    name: str = Field(..., description="Human-readable rule name")
    description: str | None = Field(default=None)
    category: str | None = Field(default=None)
    severity: str = Field(default="P2", pattern=r"^(P0|P1|P2)$")
    action: str = Field(default="warn")
    pattern: str | None = Field(default=None, description="Legacy pattern field")
    pattern_type: str | None = Field(default=None, description=f"Pattern type: {PATTERN_TYPES_LITERAL}")
    pattern_value: str | None = Field(default=None, description="Regex or keyword pattern value")
    applicable_stages: list[str] | None = Field(default=None, description="Pipeline stages: input, output, batch")
    target_files: list[str] | None = Field(default=None, description="Glob patterns for code review rules")
    enabled: bool = Field(default=True)
    is_custom: bool = Field(default=False)
    source: str | None = Field(default=None)
    group: str | None = Field(default=None, description="Rule group: input / output / code_review")

    model_config = {"from_attributes": True}


class RuleCreate(BaseModel):
    """Create a new custom rule.

    Custom rules require at minimum an ID (U-xx), name, severity, action,
    pattern_type, pattern_value, and applicable_stages.
    """

    id: str = Field(..., pattern=r"^U-\d{2,3}$", description="Custom rule ID, e.g. U-01")
    name: str = Field(..., min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    category: str | None = Field(default=None)
    severity: str = Field(default="P2", pattern=r"^(P0|P1|P2)$")
    action: str = Field(default="warn")

    # Detection method (required for active rules)
    pattern_type: str = Field(default="regex", description=f"Pattern detection type: {PATTERN_TYPES_LITERAL}")
    pattern_value: str = Field(default="", description="Pattern value: regex expression or keyword text")
    pattern_confidence: float | None = Field(default=None, ge=0.0, le=1.0, description="Confidence score (default 0.8)")

    # Rule classification
    applicable_stages: list[str] = Field(default=["input"], description="Pipeline stages: ['input'], ['output'], ['batch']")
    target_files: list[str] | None = Field(default=None, description="Glob patterns for code review (e.g. ['**/*.py', '**/*.js'])")

    enabled: bool = Field(default=True)


class RuleUpdate(BaseModel):
    """Update an existing rule — SDK override or custom rule fields."""

    name: str | None = Field(default=None)
    description: str | None = Field(default=None)
    severity: str | None = Field(default=None, pattern=r"^(P0|P1|P2)$")
    action: str | None = Field(default=None)
    pattern_type: str | None = Field(default=None)
    pattern_value: str | None = Field(default=None)
    pattern_confidence: str | None = Field(default=None)
    applicable_stages: list[str] | None = Field(default=None)
    target_files: list[str] | None = Field(default=None)
    enabled: bool | None = Field(default=None)


class RuleListResponse(BaseModel):
    """Paginated rule list response."""

    items: list[RuleSchema]
    total: int
    page: int
    page_size: int
