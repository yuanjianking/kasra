"""Audit service — query and export audit logs."""

from __future__ import annotations

import csv
import io
import logging
from datetime import datetime
from typing import Any

from sqlalchemy import desc, asc
from sqlalchemy.orm import Session as DBSession

from app.models.audit_log import AuditLog
from app.schemas.audit import (
    AuditLogPage,
    AuditLogSchema,
    ComplianceReportResponse,
)

logger = logging.getLogger("kasra.service.audit")


def query_logs(
    db: DBSession,
    *,
    user_id: str | None = None,
    rule_id: str | None = None,
    severity: str | None = None,
    direction: str | None = None,
    status: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    page: int = 1,
    page_size: int = 50,
    sort_by: str = "timestamp",
    sort_order: str = "desc",
) -> AuditLogPage:
    """Query audit logs with filters and pagination."""
    query = db.query(AuditLog)

    if user_id:
        query = query.filter(AuditLog.user_id == user_id)
    if rule_id:
        query = query.filter(AuditLog.rule_id == rule_id)
    if severity:
        query = query.filter(AuditLog.severity == severity)
    if direction:
        query = query.filter(AuditLog.direction == direction)
    if status:
        query = query.filter(AuditLog.status == status)
    if start_time:
        query = query.filter(AuditLog.timestamp >= start_time)
    if end_time:
        query = query.filter(AuditLog.timestamp <= end_time)

    # Count total
    total = query.count()

    # Security: whitelist sort fields to prevent column enumeration
    ALLOWED_SORT_COLUMNS = {"timestamp", "severity", "user_id", "rule_id", "action", "direction", "status"}
    if sort_by not in ALLOWED_SORT_COLUMNS:
        sort_by = "timestamp"

    # Sorting
    sort_col = getattr(AuditLog, sort_by, AuditLog.timestamp)
    order_fn = desc if sort_order == "desc" else asc
    query = query.order_by(order_fn(sort_col))

    # Pagination
    offset = (page - 1) * page_size
    items = query.offset(offset).limit(page_size).all()

    return AuditLogPage(
        items=[AuditLogSchema.model_validate(item) for item in items],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=max(1, (total + page_size - 1) // page_size),
    )


def generate_report(
    db: DBSession,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
) -> ComplianceReportResponse:
    """Generate a compliance report with summary statistics using SQL aggregation."""
    from sqlalchemy import func, case

    base_query = db.query(AuditLog)
    if start_time:
        base_query = base_query.filter(AuditLog.timestamp >= start_time)
    if end_time:
        base_query = base_query.filter(AuditLog.timestamp <= end_time)

    # Aggregate counts in a single query
    agg = db.query(
        func.count(AuditLog.id).label("total"),
        func.sum(case((AuditLog.action == "block", 1), else_=0)).label("blocked"),
        func.sum(case((AuditLog.action == "warn", 1), else_=0)).label("warned"),
        func.sum(case((AuditLog.severity == "P0", 1), else_=0)).label("p0"),
        func.sum(case((AuditLog.severity == "P1", 1), else_=0)).label("p1"),
        func.sum(case((AuditLog.severity == "P2", 1), else_=0)).label("p2"),
        func.count(func.distinct(AuditLog.user_id)).label("unique_users"),
        func.count(func.distinct(AuditLog.rule_id)).label("unique_rules"),
    ).filter(
        AuditLog.timestamp >= (start_time or datetime.min),
        AuditLog.timestamp <= (end_time or datetime.max),
    ).first()

    total = agg.total or 0
    blocked = agg.blocked or 0
    warned = agg.warned or 0
    p0 = agg.p0 or 0
    p1 = agg.p1 or 0
    p2 = agg.p2 or 0
    unique_users = agg.unique_users or 0
    unique_rules = agg.unique_rules or 0

    # Top triggered rules (via GROUP BY)
    top_rules_query = base_query.with_entities(
        AuditLog.rule_id,
        AuditLog.rule_name,
        func.count(AuditLog.id).label("count"),
    ).group_by(AuditLog.rule_id, AuditLog.rule_name).order_by(
        func.count(AuditLog.id).desc()
    ).limit(10).all()

    top_rules_list = [
        {"rule_id": r.rule_id, "count": r.count, "rule_name": r.rule_name}
        for r in top_rules_query
    ]

    # Date range
    date_query = db.query(
        func.min(AuditLog.timestamp).label("start"),
        func.max(AuditLog.timestamp).label("end"),
    ).select_from(AuditLog).first()

    date_range = {}
    if date_query and date_query.start:
        date_range = {
            "start": date_query.start.isoformat(),
            "end": date_query.end.isoformat(),
        }

    return ComplianceReportResponse(
        total_events=total,
        total_blocked=blocked,
        total_warnings=warned,
        p0_count=p0,
        p1_count=p1,
        p2_count=p2,
        unique_users=unique_users,
        unique_rules=unique_rules,
        date_range=date_range,
        top_rules=top_rules_list,
    )


def export_csv(
    db: DBSession,
    **filters: Any,
) -> str:
    """Export audit logs as CSV string."""
    logs = query_logs(db, page_size=10000, **filters)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "id", "timestamp", "user_id", "session_id", "rule_id", "rule_name",
        "severity", "action", "direction", "matched_text", "file_path",
        "match_count", "status", "gdpr_relevant",
    ])
    for item in logs.items:
        writer.writerow([
            item.id,
            item.timestamp.isoformat() if item.timestamp else "",
            item.user_id or "",
            item.session_id or "",
            item.rule_id,
            item.rule_name,
            item.severity,
            item.action,
            item.direction,
            item.matched_text or "",
            item.file_path or "",
            item.match_count,
            item.status,
            item.gdpr_relevant,
        ])

    return output.getvalue()


def update_log(db: DBSession, log_id: int, status: str | None = None) -> AuditLogSchema | None:
    """Update a single audit log entry (e.g. mark as resolved / fp)."""
    log = db.query(AuditLog).filter(AuditLog.id == log_id).first()
    if not log:
        return None
    if status is not None:
        log.status = status
    db.commit()
    db.refresh(log)
    return AuditLogSchema.model_validate(log)


def batch_update_logs(db: DBSession, ids: list[int], status: str | None = None) -> int:
    """Batch update audit log entries."""
    count = db.query(AuditLog).filter(AuditLog.id.in_(ids)).update(
        {"status": status}, synchronize_session=False
    )
    db.commit()
    return count
