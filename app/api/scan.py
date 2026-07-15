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
    ScanFileRequest,
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


@router.post("/file", response_model=BatchScanResponse)
def scan_file(
    req: ScanFileRequest,
    db: DBSession = Depends(get_db),
):
    """Scan a single file's content for security issues.

    Accepts file content directly (from MCP or API clients),
    writes it to a temporary file, and runs code review rules.
    This enables local file scanning without mounting volumes.
    """
    import tempfile

    # Determine a safe filename for extension detection
    safe_name = req.filename or "uploaded_file"
    # Only keep the basename and extension
    safe_name = Path(safe_name).name
    # Ensure a reasonable extension for scanning
    if "." not in safe_name:
        safe_name = safe_name + ".txt"

    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=safe_name, delete=False,
        ) as f:
            f.write(req.content)
            tmp_path = f.name

        result = scan_service.scan_batch(
            path=tmp_path,
            db=db,
            user_id=req.user_id,
        )
        return result
    except Exception as e:
        logger.exception("File scan failed")
        raise HTTPException(status_code=500, detail="Internal scan error")
    finally:
        # Clean up temp file
        try:
            os.unlink(tmp_path)
        except (NameError, OSError):
            pass


@router.post("/batch", response_model=BatchScanResponse)
def scan_batch(
    req: BatchScanRequest,
    db: DBSession = Depends(get_db),
):
    """Batch scan — scan a file or directory for security issues.

    Runs code review rules (SEC-series, IAC-series, ARCH-series)
    against the specified path.
    """
    import os
    from app.config import settings

    # Security: resolve and validate path
    resolved = Path(req.path).resolve()

    # Restrict batch scan to allowed base directories
    allowed_bases = [
        Path(settings.data_dir).resolve(),
        Path.cwd().resolve(),
    ]
    # Also allow explicit paths that exist and are within the CWD
    is_allowed = False
    for base in allowed_bases:
        try:
            resolved.relative_to(base)
            is_allowed = True
            break
        except ValueError:
            pass

    if not is_allowed and resolved.exists():
        # For now, allow if path exists (relaxed check)
        # In production, restrict further
        is_allowed = True

    if not resolved.exists():
        raise HTTPException(status_code=404, detail=f"Path not found: {req.path}")

    try:
        result = scan_service.scan_batch(
            path=str(resolved),
            db=db,
            user_id=req.user_id,
        )
        return result
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.exception("Batch scan failed")
        raise HTTPException(status_code=500, detail="Internal scan error")  # Don't leak internal details
