"""Audit log and compliance report API endpoints."""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session as DBSession

from app.database import get_db
from app.schemas.audit import (
    AuditLogPage,
    ComplianceReportResponse,
)
from app.services import audit_service

router = APIRouter(prefix="/v1/audit", tags=["Audit"])


VALID_STATUSES = {"pending", "resolved", "fp"}


class AuditLogUpdate(BaseModel):
    """Update a single audit log entry."""
    status: str | None = None  # pending / resolved / fp

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: str | None) -> str | None:
        if v is not None and v not in {"pending", "resolved", "fp"}:
            raise ValueError(f"Invalid status: {v}. Must be pending, resolved, or fp")
        return v

    class Config:
        json_schema_extra = {"enum": list(VALID_STATUSES)}


class BatchUpdateRequest(BaseModel):
    """Batch update request."""
    ids: list[int]
    status: str


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
    ALLOWED_SORT_COLUMNS = {"timestamp", "severity", "user_id", "rule_id", "action", "direction", "status"}
    if sort_by not in ALLOWED_SORT_COLUMNS:
        raise HTTPException(status_code=400, detail=f"Invalid sort field: {sort_by}")

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


@router.patch("/logs/{log_id}")
def update_audit_log(log_id: int, update: AuditLogUpdate, db: DBSession = Depends(get_db)):
    """Update an audit log entry (mark as resolved / false positive)."""
    log = audit_service.update_log(db, log_id, status=update.status)
    if log is None:
        raise HTTPException(status_code=404, detail=f"Audit log not found: {log_id}")
    return log


@router.post("/logs/batch-update")
def batch_update_audit_logs(req: BatchUpdateRequest, db: DBSession = Depends(get_db)):
    """Batch update audit log entries."""
    count = audit_service.batch_update_logs(db, req.ids, status=req.status)
    return {"updated": count}


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
