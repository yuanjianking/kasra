"""Scan API endpoints — input/output/batch detection."""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session as DBSession

from app.database import get_db
from app.schemas.scan import (
    BatchScanRequest,
    BatchScanResponse,
    ScanInputRequest,
    ScanOutputRequest,
    ScanResponse,
)
from app.services import scan_service

logger = logging.getLogger("kasra.api.scan")
router = APIRouter(prefix="/v1/scan", tags=["Scan"])


@router.post("/input", response_model=ScanResponse)
def scan_input(
    req: ScanInputRequest,
    db: DBSession = Depends(get_db),
):
    """Input detection — scan content before it reaches the AI model.

    Evaluates all input-stage rules (I-series) against the content.
    Returns whether the content was blocked, along with any triggered rules.
    """
    result = scan_service.scan_input(
        content=req.content,
        db=db,
        user_id=req.user_id,
        session_id=req.session_id,
        request_id=req.request_id,
    )
    return result


@router.post("/output", response_model=ScanResponse)
def scan_output(
    req: ScanOutputRequest,
    db: DBSession = Depends(get_db),
):
    """Output detection — scan AI-generated content before returning to user.

    Evaluates all output-stage rules (O-series) against the content.
    """
    result = scan_service.scan_output(
        content=req.content,
        db=db,
        user_id=req.user_id,
        session_id=req.session_id,
        request_id=req.request_id,
    )
    return result


@router.post("/batch", response_model=BatchScanResponse)
def scan_batch(
    req: BatchScanRequest,
    db: DBSession = Depends(get_db),
):
    """Batch scan — scan a file or directory for security issues.

    Runs code review rules (SEC-series, IAC-series, ARCH-series)
    against the specified path.
    """
    path = Path(req.path)
    if not path.exists():
        raise HTTPException(
            status_code=404,
            detail=f"Path not found: {req.path}",
        )

    try:
        result = scan_service.scan_batch(
            path=str(path.resolve()),
            db=db,
            user_id=req.user_id,
        )
        return result
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.exception("Batch scan failed")
        raise HTTPException(status_code=500, detail=str(e))
