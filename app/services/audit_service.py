"""Audit service — query and export audit logs."""

from __future__ import annotations

import csv
import io
import json
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
    """Generate a compliance report with summary statistics."""
    query = db.query(AuditLog)

    if start_time:
        query = query.filter(AuditLog.timestamp >= start_time)
    if end_time:
        query = query.filter(AuditLog.timestamp <= end_time)

    all_logs = query.all()
    total = len(all_logs)

    blocked = sum(1 for l in all_logs if l.action == "block")
    warned = sum(1 for l in all_logs if l.action == "warn")
    p0 = sum(1 for l in all_logs if l.severity == "P0")
    p1 = sum(1 for l in all_logs if l.severity == "P1")
    p2 = sum(1 for l in all_logs if l.severity == "P2")
    unique_users = len(set(l.user_id for l in all_logs if l.user_id))
    unique_rules = len(set(l.rule_id for l in all_logs))

    # Top triggered rules
    rule_counts: dict[str, int] = {}
    for l in all_logs:
        rule_counts[l.rule_id] = rule_counts.get(l.rule_id, 0) + 1
    top_rules = sorted(rule_counts.items(), key=lambda x: -x[1])[:10]
    top_rules_list = [
        {"rule_id": rid, "count": cnt, "rule_name": next(
            (l.rule_name for l in all_logs if l.rule_id == rid), ""
        )}
        for rid, cnt in top_rules
    ]

    # Date range
    timestamps = [l.timestamp for l in all_logs if l.timestamp]
    date_range = {}
    if timestamps:
        date_range = {
            "start": min(timestamps).isoformat(),
            "end": max(timestamps).isoformat(),
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
