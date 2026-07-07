"""Dashboard and user behavior API endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session as DBSession

from app.database import get_db
from app.schemas.dashboard import (
    DashboardSummary,
    DashboardTrend,
    UserBehaviorPage,
)
from app.services import dashboard_service

router = APIRouter(prefix="/v1/dashboard", tags=["Dashboard"])


@router.get("/summary", response_model=DashboardSummary)
def dashboard_summary(db: DBSession = Depends(get_db)):
    """Dashboard summary — aggregate statistics for the last 24 hours."""
    return dashboard_service.get_summary(db)


@router.get("/trend", response_model=DashboardTrend)
def dashboard_trend(
    period: str = Query(default="7d", pattern=r"^(7d|30d|90d)$"),
    db: DBSession = Depends(get_db),
):
    """Trend data — daily request/block/warn counts."""
    return dashboard_service.get_trend(db, period=period)


@router.get("/users/behavior", response_model=UserBehaviorPage)
def user_behavior(
    user_id: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=500),
    db: DBSession = Depends(get_db),
):
    """User behavior analysis — daily activity summaries."""
    return dashboard_service.get_user_behavior(
        db,
        user_id=user_id,
        page=page,
        page_size=page_size,
    )
