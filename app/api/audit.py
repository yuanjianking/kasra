"""Audit log and compliance report API endpoints."""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, Query
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session as DBSession

from app.database import get_db
from app.schemas.audit import (
    AuditLogPage,
    ComplianceReportResponse,
)
from app.services import audit_service

router = APIRouter(prefix="/v1/audit", tags=["Audit"])


@router.get("/logs", response_model=AuditLogPage)
def list_audit_logs(
    user_id: str | None = Query(default=None),
    rule_id: str | None = Query(default=None),
    severity: str | None = Query(default=None, pattern=r"^(P0|P1|P2)$"),
    direction: str | None = Query(default=None, pattern=r"^(input|output|batch|behavior)$"),
    status: str | None = Query(default=None),
    start_time: datetime | None = Query(default=None),
    end_time: datetime | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=500),
    sort_by: str = Query(default="timestamp"),
    sort_order: str = Query(default="desc", pattern=r"^(asc|desc)$"),
    db: DBSession = Depends(get_db),
):
    """Query audit logs with filters and pagination."""
    return audit_service.query_logs(
        db,
        user_id=user_id,
        rule_id=rule_id,
        severity=severity,
        direction=direction,
        status=status,
        start_time=start_time,
        end_time=end_time,
        page=page,
        page_size=page_size,
        sort_by=sort_by,
        sort_order=sort_order,
    )


@router.get("/report", response_model=ComplianceReportResponse)
def compliance_report(
    start_time: datetime | None = Query(default=None),
    end_time: datetime | None = Query(default=None),
    db: DBSession = Depends(get_db),
):
    """Generate compliance report summary."""
    return audit_service.generate_report(
        db,
        start_time=start_time,
        end_time=end_time,
    )


@router.get("/export")
def export_logs(
    format: str = Query(default="csv", pattern=r"^(csv)$"),
    start_time: datetime | None = Query(default=None),
    end_time: datetime | None = Query(default=None),
    db: DBSession = Depends(get_db),
):
    """Export audit logs as CSV."""
    csv_content = audit_service.export_csv(
        db,
        start_time=start_time,
        end_time=end_time,
    )
    return PlainTextResponse(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=kasra-audit-export.csv"},
    )
