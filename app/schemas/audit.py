"""Pydantic schemas for audit log and report API endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class AuditLogSchema(BaseModel):
    """A single audit log entry."""

    id: int
    timestamp: datetime
    user_id: str | None
    session_id: str | None
    rule_id: str
    rule_name: str
    category: str | None
    severity: str
    action: str
    direction: str
    content_snippet: str | None
    matched_text: str | None
    file_path: str | None
    line_number: int | None
    match_count: int
    status: str
    gdpr_relevant: bool
    metadata: dict[str, Any] | None = Field(
        default=None, validation_alias="extra_metadata"
    )

    model_config = {"from_attributes": True}


class AuditLogQuery(BaseModel):
    """Query parameters for listing audit logs."""

    user_id: str | None = Field(default=None)
    rule_id: str | None = Field(default=None)
    severity: str | None = Field(default=None, pattern=r"^(P0|P1|P2)$")
    direction: str | None = Field(default=None, pattern=r"^(input|output|batch|behavior)$")
    status: str | None = Field(default=None)
    start_time: datetime | None = Field(default=None)
    end_time: datetime | None = Field(default=None)
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1, le=500)
    sort_by: str = Field(default="timestamp")
    sort_order: str = Field(default="desc", pattern=r"^(asc|desc)$")


class AuditLogPage(BaseModel):
    """Paginated audit log response."""

    items: list[AuditLogSchema]
    total: int
    page: int
    page_size: int
    total_pages: int


class ComplianceReportResponse(BaseModel):
    """Compliance report summary."""

    report_type: str = Field(default="compliance")
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    total_events: int = 0
    total_blocked: int = 0
    total_warnings: int = 0
    p0_count: int = 0
    p1_count: int = 0
    p2_count: int = 0
    unique_users: int = 0
    unique_rules: int = 0
    date_range: dict[str, str] = Field(default_factory=dict)
    top_rules: list[dict[str, Any]] = Field(default_factory=list)
