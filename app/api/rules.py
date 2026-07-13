"""Rule management API endpoints — CRUD + import/export."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session as DBSession

from app.database import get_db
from app.schemas.rules import RuleCreate, RuleSchema, RuleUpdate
from app.services import rules_service

router = APIRouter(prefix="/v1/rules", tags=["Rules"])


@router.get("")
def list_rules(
    category: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    enabled_only: bool | None = Query(default=None),
    custom_only: bool | None = Query(default=None),
    group: str | None = Query(default=None, description="Filter by group: input, output, code_review"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=100, ge=1, le=500),
    db: DBSession = Depends(get_db),
):
    """List all rules (SDK built-in + custom)."""
    return rules_service.list_rules(
        db,
        category=category,
        severity=severity,
        enabled_only=enabled_only,
        custom_only=custom_only,
        group=group,
        page=page,
        page_size=page_size,
    )


@router.get("/export")
def export_rules(
    series: str | None = Query(default=None, description="Filter by bundle series: I, O, SEC, IAC"),
    category: str | None = Query(default=None, description="Filter by category name"),
    db: DBSession = Depends(get_db),
):
    """Export rules as a JSON bundle."""
    bundle = rules_service.export_rules_to_bundle(
        db,
        series=series,
        category=category,
    )
    return JSONResponse(
        content=bundle,
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=kasra-rules-export.json"},
    )


@router.post("/import", status_code=201)
async def import_rules(
    file: UploadFile,
    db: DBSession = Depends(get_db),
):
    """Import rules from an uploaded JSON bundle file."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")
    if not file.filename.endswith(".json"):
        raise HTTPException(status_code=400, detail="Only .json files are supported")

    try:
        stats = await rules_service.import_rules_from_file(db, file)
        return stats
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Import failed: {e}")


@router.get("/{rule_id}", response_model=RuleSchema)
def get_rule(rule_id: str, db: DBSession = Depends(get_db)):
    """Get a single rule by ID."""
    rule = rules_service.get_rule(db, rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail=f"Rule not found: {rule_id}")
    return rule


@router.post("", response_model=RuleSchema, status_code=201)
def create_rule(rule: RuleCreate, db: DBSession = Depends(get_db)):
    """Create a new custom rule (U-series)."""
    try:
        return rules_service.create_rule(db, rule)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.put("/{rule_id}", response_model=RuleSchema)
def update_rule(rule_id: str, update: RuleUpdate, db: DBSession = Depends(get_db)):
    """Update a rule (override SDK rule settings or modify custom rule)."""
    rule = rules_service.update_rule(db, rule_id, update)
    if rule is None:
        raise HTTPException(status_code=404, detail=f"Rule not found: {rule_id}")
    return rule


@router.delete("/{rule_id}", status_code=204)
def delete_rule(rule_id: str, db: DBSession = Depends(get_db)):
    """Delete a custom rule or reset an SDK rule override."""
    deleted = rules_service.delete_rule(db, rule_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Rule not found: {rule_id}")
    return None
