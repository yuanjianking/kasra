"""Scan service — orchestrates detection pipelines with database logging."""

from __future__ import annotations

import logging
import time

from sqlalchemy.orm import Session as DBSession

from app.metrics import detections_total, detection_duration_ms
from app.models.audit_log import AuditLog
from app.models.user_behavior import UserBehavior
from app.services.engine_service import engine_service
from app.schemas.scan import (
    BatchScanFileResult,
    BatchScanResponse,
    ScanResponse,
    TriggeredRuleSchema,
)

logger = logging.getLogger("kasra.service.scan")


def _log_to_db(
    db: DBSession,
    *,
    result: "kasra.models.result.AggregatedResult",
    direction: str,
    user_id: str | None = None,
    session_id: str | None = None,
    request_id: str | None = None,
    file_path: str | None = None,
    content: str | None = None,
    commit: bool = True,
) -> None:
    """Write detection results to the audit_logs table."""
    from datetime import datetime

    now = datetime.utcnow()

    # Security: redact sensitive matched text for credential leak rules
    SENSITIVE_CATEGORIES = {"credential_leak", "secrets", "credentials"}

    for dr in result.triggered_rules:
        matched_text = (
            dr.matches[0].matched_text[:500] if dr.matches and len(dr.matches) > 0 else None
        )
        if dr.category in SENSITIVE_CATEGORIES and matched_text and len(matched_text) > 8:
            matched_text = matched_text[:4] + "****" + matched_text[-4:]
        log_entry = AuditLog(
            timestamp=now,
            user_id=user_id,
            session_id=session_id,
            request_id=request_id,
            rule_id=dr.rule_id,
            rule_name=dr.rule_name,
            severity=dr.severity.value if hasattr(dr.severity, "value") else str(dr.severity),
            action=dr.action.value if hasattr(dr.action, "value") else str(dr.action),
            direction=direction,
            content_snippet=content[:200] if content else None,
            matched_text=matched_text,
            file_path=file_path,
            line_number=None,
            match_count=dr.match_count,
            status="pending",
            gdpr_relevant=1 if result.gdpr_audit else 0,
            extra_metadata={"execution_time_ms": result.execution_time_ms},
        )
        db.add(log_entry)

    # Update user behavior summary
    _update_user_behavior(
        db, user_id=user_id,
        blocked=result.blocked,
        warned=bool(result.warnings),
        rule_ids=[dr.rule_id for dr in result.triggered_rules],
    )

    if commit:
        db.commit()


def _update_user_behavior(
    db: DBSession,
    *,
    user_id: str | None,
    blocked: bool,
    warned: bool,
    rule_ids: list[str],
) -> None:
    """Update or create daily user behavior summary."""
    from datetime import date, datetime

    if not user_id:
        return

    today = date.today()
    now = datetime.utcnow().time()

    behavior = (
        db.query(UserBehavior)
        .filter(
            UserBehavior.user_id == user_id,
            UserBehavior.date == today,
        )
        .first()
    )

    if behavior is None:
        behavior = UserBehavior(
            user_id=user_id,
            date=today,
            total_requests=0,
            blocked_requests=0,
            warned_requests=0,
            first_request=now,
            rule_triggers={},
        )
        db.add(behavior)

    behavior.total_requests += 1
    if blocked:
        behavior.blocked_requests += 1
    if warned:
        behavior.warned_requests += 1
    behavior.last_request = now

    # Update rule trigger counts
    triggers = dict(behavior.rule_triggers or {})
    for rid in rule_ids:
        triggers[rid] = triggers.get(rid, 0) + 1
    behavior.rule_triggers = triggers


def scan_input(
    content: str,
    db: DBSession,
    user_id: str | None = None,
    session_id: str | None = None,
    request_id: str | None = None,
) -> ScanResponse:
    """Run input detection and log results."""
    result = engine_service.detect_input(
        content,
        user_id=user_id,
        session_id=session_id,
        request_id=request_id,
    )

    _log_to_db(
        db, result=result, direction="input",
        user_id=user_id, session_id=session_id, request_id=request_id,
        content=content,
    )

    return _to_scan_response(result, direction="input")


def scan_output(
    content: str,
    db: DBSession,
    user_id: str | None = None,
    session_id: str | None = None,
    request_id: str | None = None,
) -> ScanResponse:
    """Run output detection and log results."""
    result = engine_service.detect_output(
        content,
        user_id=user_id,
        session_id=session_id,
        request_id=request_id,
    )

    _log_to_db(
        db, result=result, direction="output",
        user_id=user_id, session_id=session_id, request_id=request_id,
        content=content,
    )

    return _to_scan_response(result, direction="output")


def scan_batch(
    path: str,
    db: DBSession,
    user_id: str | None = None,
) -> BatchScanResponse:
    """Run batch directory scan and log results."""
    import os
    full_path = os.path.abspath(path)

    if not os.path.exists(full_path):
        raise FileNotFoundError(f"Path not found: {full_path}")

    t0 = time.monotonic()

    if os.path.isfile(full_path):
        results = [engine_service.scan_file(full_path)]
    else:
        results = engine_service.scan_directory(full_path)

    total_time = (time.monotonic() - t0) * 1000

    file_results: list[BatchScanFileResult] = []
    total_findings = 0
    files_with_findings = 0

    for r in results:
        file_path = r.metadata.get("file_path", "unknown")
        triggered = []
        for dr in r.triggered_rules:
            triggered.append(TriggeredRuleSchema(
                rule_id=dr.rule_id,
                rule_name=dr.rule_name,
                severity=str(dr.severity.value if hasattr(dr.severity, "value") else dr.severity),
                action=str(dr.action.value if hasattr(dr.action, "value") else dr.action),
                match_count=dr.match_count,
                matched_text=dr.matches[0].matched_text[:200] if dr.matches and len(dr.matches) > 0 else None,
                evidence=[{"source_layer": e.source_layer, "reason": e.reason} for e in dr.evidence] if dr.evidence else [],
            ))

        sev = "ok"
        if triggered:
            sev = r.overall_severity.value if hasattr(r.overall_severity, "value") else str(r.overall_severity)

        file_results.append(BatchScanFileResult(
            file_path=file_path,
            triggered_rules=triggered,
            severity=sev,
            execution_time_ms=r.execution_time_ms,
        ))

        if triggered:
            files_with_findings += 1
            total_findings += len(triggered)

        # Log each file's findings to audit_logs
        _log_to_db(
            db, result=r, direction="batch",
            user_id=user_id, file_path=file_path,
            commit=False,
        )

    db.commit()

    return BatchScanResponse(
        total_files=len(results),
        files_with_findings=files_with_findings,
        total_findings=total_findings,
        results=file_results,
        execution_time_ms=round(total_time, 2),
    )


def _to_scan_response(result: "kasra.models.result.AggregatedResult", direction: str = "unknown") -> ScanResponse:
    """Convert SDK AggregatedResult to API ScanResponse and record metrics."""
    # Record Prometheus metrics
    if result.triggered_rules:
        for dr in result.triggered_rules:
            sev = dr.severity.value if hasattr(dr.severity, "value") else str(dr.severity)
            act = dr.action.value if hasattr(dr.action, "value") else str(dr.action)
            detections_total.labels(direction=direction, action=act, severity=sev).inc()
    detection_duration_ms.labels(direction=direction).observe(result.execution_time_ms)

    triggered = []
    for dr in result.triggered_rules:
        triggered.append(TriggeredRuleSchema(
            rule_id=dr.rule_id,
            rule_name=dr.rule_name,
            severity=dr.severity.value if hasattr(dr.severity, "value") else str(dr.severity),
            action=dr.action.value if hasattr(dr.action, "value") else str(dr.action),
            match_count=dr.match_count,
            matched_text=dr.matches[0].matched_text[:200] if dr.matches and len(dr.matches) > 0 else None,
            evidence=[{"source_layer": e.source_layer, "reason": e.reason} for e in dr.evidence] if dr.evidence else [],
        ))

    return ScanResponse(
        blocked=result.blocked,
        action=result.overall_action.value if hasattr(result.overall_action, "value") else str(result.overall_action),
        severity=result.overall_severity.value if hasattr(result.overall_severity, "value") else str(result.overall_severity),
        triggered_rules=triggered,
        warnings=result.warnings,
        execution_time_ms=result.execution_time_ms,
        redacted_content=result.metadata.get("processed_content") if result.metadata else None,
        metadata=result.metadata or {},
    )
