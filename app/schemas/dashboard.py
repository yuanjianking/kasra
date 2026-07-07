"""Pydantic schemas for dashboard and user behavior API endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class DashboardSummary(BaseModel):
    """Dashboard summary statistics."""

    total_requests_24h: int = 0
    blocked_count_24h: int = 0
    warning_count_24h: int = 0
    total_users_active_24h: int = 0
    total_rules_active: int = 0
    p0_triggers_24h: int = 0
    p1_triggers_24h: int = 0
    p2_triggers_24h: int = 0
    block_rate_percent: float = 0.0
    top_triggered_rules: list[dict[str, Any]] = Field(default_factory=list)
    top_users: list[dict[str, Any]] = Field(default_factory=list)
    current_time: datetime = Field(default_factory=datetime.utcnow)


class TrendDataPoint(BaseModel):
    """A single data point in a trend series."""

    date: str = Field(..., description="Date string, YYYY-MM-DD")
    total: int = 0
    blocked: int = 0
    warned: int = 0


class DashboardTrend(BaseModel):
    """Trend data response."""

    period: str = Field(default="7d", description="7d / 30d / 90d")
    data: list[TrendDataPoint] = Field(default_factory=list)


class UserBehaviorSchema(BaseModel):
    """User behavior summary for the behavior analysis page."""

    user_id: str
    date: str
    total_requests: int
    blocked_requests: int
    warned_requests: int
    anomaly_score: int
    top_triggers: list[dict[str, Any]] = Field(default_factory=list)

    model_config = {"from_attributes": True}


class UserBehaviorPage(BaseModel):
    """Paginated user behavior response."""

    items: list[UserBehaviorSchema]
    total: int
    page: int
    page_size: int
