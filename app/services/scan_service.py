"""Scan service — orchestrates detection pipelines with database logging."""

from __future__ import annotations

import logging
import time

from sqlalchemy.orm import Session as DBSession

from app.metrics import detections_total, detection_duration_ms
from app.models.audit_log import AuditLog
from app.models.user_behavior import UserBehavior
from app.services.engine_service import engine_service
from app.services.audit_chain import seal_chain_batch
from app.schemas.scan import (
    BatchScanFileResult,
    BatchScanResponse,
    ScanResponse,
    TriggeredRuleSchema,
)

logger = logging.getLogger("kasra.service.scan")


# ── Enum conversion helpers ────────────────────────────────────────────────
# SDK models use Pydantic enums (Severity, ActionType) that may or may not
# have .value. These helpers handle both cases cleanly.

def _sev(val: object) -> str:
    """Convert a severity value to its string representation."""
    return str(val.value if hasattr(val, "value") else val)


def _act(val: object) -> str:
    """Convert an action value to its string representation."""
    return str(val.value if hasattr(val, "value") else val)


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
    # Note: DetectionResult doesn't carry `category` directly;
    # look it up from the engine's rule definition when available.
    SENSITIVE_CATEGORIES = {"credential_leak", "secrets", "credentials"}

    for dr in result.triggered_rules:
        matched_text = (
            dr.matches[0].matched_text[:500] if dr.matches and len(dr.matches) > 0 else None
        )
        # Attempt to determine category (DetectionResult lacks it; try engine lookup)
        dr_category = getattr(dr, "category", None)
        if dr_category is None:
            try:
                rule_obj = engine_service.engine.get_rule(dr.rule_id)
                dr_category = getattr(rule_obj, "category", None)
            except (KeyError, RuntimeError, AttributeError):
                pass
        if dr_category in SENSITIVE_CATEGORIES and matched_text and len(matched_text) > 8:
            matched_text = matched_text[:4] + "****" + matched_text[-4:]
        log_entry = AuditLog(
            timestamp=now,
            user_id=user_id,
            session_id=session_id,
            request_id=request_id,
            rule_id=dr.rule_id,
            rule_name=dr.rule_name,
            severity=_sev(dr.severity),
            action=_act(dr.action),
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
        # Seal audit chain after each batch commit
        try:
            from app.database import SessionLocal
            chain_db = SessionLocal()
            last_id = db.query(AuditLog.id).order_by(AuditLog.id.desc()).first()
            if last_id:
                seal_chain_batch(chain_db, last_log_id=last_id[0],
                                 batch_count=len(result.triggered_rules))
            chain_db.close()
        except Exception:
            pass  # Best-effort: chain sealing failure does not block detection


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

    # Auto-create user record if first time seeing this user_id
    from app.models.user import User
    existing_user = db.query(User).filter(User.username == user_id).first()
    if existing_user is None:
        db.add(User(username=user_id, role="user", is_active=True))
        db.flush()

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
        # Flush so subsequent calls in the same transaction (e.g. batch scan
        # across multiple files without per-file commit) can see this row.
        db.flush()

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


def _log_code_review_findings(
    db: DBSession,
    *,
    result: "kasra.scanner.models.CodeReviewResult",
    user_id: str | None = None,
    commit: bool = True,
) -> None:
    """Write code review findings to the audit_logs table."""
    from datetime import datetime

    now = datetime.utcnow()

    for f in result.findings:
        log_entry = AuditLog(
            timestamp=now,
            user_id=user_id,
            rule_id=f.rule_id,
            rule_name=f.rule_name,
            severity=f.severity,
            action="warn",
            direction="batch",
            matched_text=f.matched_text[:500] if f.matched_text else None,
            file_path=f.file_path,
            line_number=f.line_number,
            match_count=1,
            status="pending",
            extra_metadata={"confidence": f.confidence, "message": f.message},
        )
        db.add(log_entry)

    if commit:
        db.commit()


def scan_batch(
    path: str,
    db: DBSession,
    user_id: str | None = None,
) -> BatchScanResponse:
    """Run batch code review scan and log results."""
    import os
    from collections import defaultdict

    full_path = os.path.abspath(path)

    if not os.path.exists(full_path):
        raise FileNotFoundError(f"Path not found: {full_path}")

    t0 = time.monotonic()

    # review_code() handles both files and directories internally
    result = engine_service.review_code(full_path)

    total_time = (time.monotonic() - t0) * 1000

    # Group findings by file path
    findings_by_file: dict[str, list] = defaultdict(list)
    for finding in result.findings:
        findings_by_file[finding.file_path].append(finding)

    file_results: list[BatchScanFileResult] = []
    worst_severity_rank = {"P0": 0, "P1": 1, "P2": 2}

    for file_path, findings in sorted(findings_by_file.items()):
        triggered = []
        worst_rank = 99
        for finding in findings:
            triggered.append(TriggeredRuleSchema(
                rule_id=finding.rule_id,
                rule_name=finding.rule_name,
                severity=finding.severity,
                action="warn",
                match_count=1,
                matched_text=finding.matched_text[:200] if finding.matched_text else None,
            ))
            rank = worst_severity_rank.get(finding.severity, 99)
            if rank < worst_rank:
                worst_rank = rank

        sev = {0: "P0", 1: "P1", 2: "P2"}.get(worst_rank, "ok")

        file_results.append(BatchScanFileResult(
            file_path=file_path,
            triggered_rules=triggered,
            severity=sev,
            execution_time_ms=0.0,  # per-file timing not available from CodeReviewResult
        ))

    # Log all findings to audit_logs
    _log_code_review_findings(
        db, result=result, user_id=user_id, commit=True,
    )

    # Update user behavior summary
    all_rule_ids = [f.rule_id for f in result.findings]
    _update_user_behavior(
        db, user_id=user_id,
        blocked=False,
        warned=bool(result.findings),
        rule_ids=all_rule_ids,
    )

    return BatchScanResponse(
        total_files=result.files_scanned,
        files_with_findings=len(findings_by_file),
        total_findings=len(result.findings),
        results=file_results,
        execution_time_ms=round(total_time, 2),
    )


def _to_scan_response(result: "kasra.models.result.AggregatedResult", direction: str = "unknown") -> ScanResponse:
    """Convert SDK AggregatedResult to API ScanResponse and record metrics."""
    # Record Prometheus metrics
    if result.triggered_rules:
        for dr in result.triggered_rules:
            sev = _sev(dr.severity)
            act = _act(dr.action)
            detections_total.labels(direction=direction, action=act, severity=sev).inc()
    detection_duration_ms.labels(direction=direction).observe(result.execution_time_ms)

    triggered = []
    for dr in result.triggered_rules:
        triggered.append(TriggeredRuleSchema(
            rule_id=dr.rule_id,
            rule_name=dr.rule_name,
            severity=_sev(dr.severity),
            action=_act(dr.action),
            match_count=dr.match_count,
            matched_text=dr.matches[0].matched_text[:200] if dr.matches and len(dr.matches) > 0 else None,
            evidence=[{"source_layer": e.source_layer, "reason": e.reason} for e in dr.evidence] if dr.evidence else [],
        ))

    return ScanResponse(
        blocked=result.blocked,
        action=_act(result.overall_action),
        severity=_sev(result.overall_severity),
        triggered_rules=triggered,
        warnings=result.warnings,
        execution_time_ms=result.execution_time_ms,
        redacted_content=result.metadata.get("processed_content") if result.metadata else None,
        metadata=result.metadata or {},
    )
