"""Dashboard service — aggregation queries for analytics."""

from __future__ import annotations

from datetime import date, datetime, timedelta
from typing import Any

from sqlalchemy import case, func
from sqlalchemy.orm import Session as DBSession

from app.models.audit_log import AuditLog
from app.models.user_behavior import UserBehavior
from app.schemas.dashboard import (
    DashboardSummary,
    DashboardTrend,
    TrendDataPoint,
    UserBehaviorPage,
    UserBehaviorSchema,
)


def get_summary(db: DBSession) -> DashboardSummary:
    """Compute dashboard summary for the last 24 hours using aggregated queries."""
    since = datetime.utcnow() - timedelta(hours=24)

    # 1. Single aggregation query for counts
    agg = db.query(
        func.count(AuditLog.id).label("total"),
        func.sum(case((AuditLog.action == "block", 1), else_=0)).label("blocked"),
        func.sum(case((AuditLog.action == "warn", 1), else_=0)).label("warned"),
        func.sum(case((AuditLog.severity == "P0", 1), else_=0)).label("p0"),
        func.sum(case((AuditLog.severity == "P1", 1), else_=0)).label("p1"),
        func.count(func.distinct(AuditLog.user_id)).label("active_users"),
        func.count(func.distinct(AuditLog.rule_id)).label("active_rules"),
    ).filter(AuditLog.timestamp >= since).first()

    total_24h = agg.total or 0
    blocked_24h = agg.blocked or 0
    warned_24h = agg.warned or 0
    p0_24h = agg.p0 or 0
    p1_24h = agg.p1 or 0
    p2_24h = total_24h - p0_24h - p1_24h
    active_users = agg.active_users or 0
    active_rules = agg.active_rules or 0

    # Block rate
    block_rate = round((blocked_24h / total_24h * 100) if total_24h > 0 else 0, 1)

    # 2. Top triggered rules
    top_rules_raw = (
        db.query(
            AuditLog.rule_id,
            AuditLog.rule_name,
            func.count(AuditLog.id).label("count"),
        )
        .filter(AuditLog.timestamp >= since)
        .group_by(AuditLog.rule_id, AuditLog.rule_name)
        .order_by(func.count(AuditLog.id).desc())
        .limit(10)
        .all()
    )
    top_triggered_rules = [
        {"rule_id": r.rule_id, "rule_name": r.rule_name, "count": r.count}
        for r in top_rules_raw
    ]

    # 3. Top users
    top_users_raw = (
        db.query(
            AuditLog.user_id,
            func.count(AuditLog.id).label("count"),
            func.sum(
                case((AuditLog.action == "block", 1), else_=0)
            ).label("blocks"),
        )
        .filter(AuditLog.timestamp >= since, AuditLog.user_id.isnot(None))
        .group_by(AuditLog.user_id)
        .order_by(func.count(AuditLog.id).desc())
        .limit(10)
        .all()
    )
    top_users = [
        {"user_id": r.user_id, "requests": r.count, "blocks": r.blocks or 0}
        for r in top_users_raw
    ]

    return DashboardSummary(
        total_requests_24h=total_24h,
        blocked_count_24h=blocked_24h,
        warning_count_24h=warned_24h,
        total_users_active_24h=active_users,
        total_rules_active=active_rules,
        p0_triggers_24h=p0_24h,
        p1_triggers_24h=p1_24h,
        p2_triggers_24h=p2_24h,
        block_rate_percent=block_rate,
        top_triggered_rules=top_triggered_rules,
        top_users=top_users,
    )


def get_trend(db: DBSession, period: str = "7d") -> DashboardTrend:
    """Compute daily trend data."""
    days = {"7d": 7, "30d": 30, "90d": 90}.get(period, 7)
    since = datetime.utcnow() - timedelta(days=days)

    # Group by date
    rows = (
        db.query(
            func.date(AuditLog.timestamp).label("day"),
            func.count(AuditLog.id).label("total"),
            func.sum(
                case((AuditLog.action == "block", 1), else_=0)
            ).label("blocked"),
            func.sum(
                case((AuditLog.action == "warn", 1), else_=0)
            ).label("warned"),
        )
        .filter(AuditLog.timestamp >= since)
        .group_by(func.date(AuditLog.timestamp))
        .order_by(func.date(AuditLog.timestamp))
        .all()
    )

    data = [
        TrendDataPoint(
            date=str(r.day),
            total=r.total or 0,
            blocked=r.blocked or 0,
            warned=r.warned or 0,
        )
        for r in rows
    ]

    return DashboardTrend(period=period, data=data)


def get_user_behavior(
    db: DBSession,
    *,
    user_id: str | None = None,
    page: int = 1,
    page_size: int = 50,
) -> UserBehaviorPage:
    """Query user behavior summaries."""
    query = db.query(UserBehavior)

    if user_id:
        query = query.filter(UserBehavior.user_id == user_id)

    query = query.order_by(UserBehavior.date.desc(), UserBehavior.user_id)

    total = query.count()
    offset = (page - 1) * page_size
    items = query.offset(offset).limit(page_size).all()

    return UserBehaviorPage(
        items=[
            UserBehaviorSchema(
                user_id=item.user_id,
                date=str(item.date),
                total_requests=item.total_requests,
                blocked_requests=item.blocked_requests,
                warned_requests=item.warned_requests,
                anomaly_score=item.anomaly_score,
                top_triggers=sorted(
                    (item.rule_triggers or {}).items(),
                    key=lambda x: -x[1],
                )[:5] if item.rule_triggers else [],
            )
            for item in items
        ],
        total=total,
        page=page,
        page_size=page_size,
    )
