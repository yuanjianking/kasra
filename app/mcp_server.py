"""Kasra MCP Server - Model Context Protocol implementation.

Exposes Kasra's security detection capabilities as MCP tools,
compatible with Claude Desktop, Cursor, and any MCP client.

All detection events are automatically logged to the audit database,
same as the REST API — Dashboard and Audit pages reflect MCP activity too.
"""
from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from app.database import SessionLocal
from app.services.engine_service import engine_service
from app.services.scan_service import _log_to_db


# ── Enum conversion helpers ────────────────────────────────────────────────

def _sev(val: object) -> str:
    return str(val.value if hasattr(val, "value") else val)

def _act(val: object) -> str:
    return str(val.value if hasattr(val, "value") else val)


# ---------------------------------------------------------------------------
# FastMCP Server instance
# ---------------------------------------------------------------------------

_mcp_host = os.environ.get("KASRA_MCP_HOST", "127.0.0.1")
_mcp_port = int(os.environ.get("KASRA_MCP_PORT", "8090"))

kasra_server = FastMCP(
    name="Kasra Security Scanner",
    instructions=(
        "Kasra is an AI Development Security Governance Platform. "
        "It scans content for security risks including credential leaks, "
        "PII exposure, prompt injection attacks, dangerous code patterns, "
        "and compliance violations. "
        "Use these tools BEFORE sending content to an AI model, and AFTER "
        "receiving AI-generated content."
    ),
    host=_mcp_host,
    port=_mcp_port,
    sse_path="/sse",
    message_path="/messages/",
)


# ── Audit logging helper ──────────────────────────────────────────────────

def _audit_log(result: Any, direction: str, **kwargs: Any) -> None:
    """Write detection results to the audit database (best-effort)."""
    if not result.triggered_rules:
        return
    try:
        db = SessionLocal()
        _log_to_db(db, result=result, direction=direction, commit=True, **kwargs)
        db.close()
    except Exception:
        pass  # Non-blocking: audit failure does not break detection


# ===========================================================================
# MCP Tools
# ===========================================================================


@kasra_server.tool(
    name="kasra_scan_input",
    description=(
        "SECURITY: Scan developer input BEFORE it reaches the AI model. "
        "Detects credential leaks (API keys, passwords, tokens), PII (phone numbers, "
        "ID numbers, emails), prompt injection attacks, jailbreak attempts, and other "
        "security risks. Returns blocked status and triggered rules."
    ),
)
def scan_input(content: str, user_id: str | None = None) -> str:
    _ensure_engine()
    result = engine_service.detect_input(content, user_id=user_id)
    _audit_log(result, direction="input", user_id=user_id, content=content)
    return _format_result(result, "input")


@kasra_server.tool(
    name="kasra_scan_output",
    description=(
        "SECURITY: Scan AI-generated content BEFORE returning it to the user. "
        "Detects dangerous function calls (eval/exec), dangerous shell commands "
        "(rm -rf /, curl | bash), credential leaks in output, SQL injection, "
        "XSS, and other code security issues."
    ),
)
def scan_output(content: str, user_id: str | None = None) -> str:
    _ensure_engine()
    result = engine_service.detect_output(content, user_id=user_id)
    _audit_log(result, direction="output", user_id=user_id, content=content)
    return _format_result(result, "output")


@kasra_server.tool(
    name="kasra_scan_file",
    description=(
        "SECURITY: Scan a file or directory for security vulnerabilities. "
        "Runs code review rules (SQL injection, XSS, hardcoded secrets, "
        "Docker/K8s misconfigurations, etc.) against the specified path. "
        "Supports all major programming languages and config formats."
    ),
)
def scan_file(path: str) -> str:
    _ensure_engine()

    normalized = os.path.normpath(path)
    if ".." in normalized.split(os.sep):
        return json.dumps({"error": "Path traversal is not allowed", "findings": []}, ensure_ascii=False)

    full_path = os.path.abspath(path)
    if not os.path.exists(full_path):
        return json.dumps({"error": f"Path not found: {full_path}"}, ensure_ascii=False)

    if os.path.isfile(full_path):
        results = [engine_service.scan_file(full_path)]
    else:
        results = engine_service.scan_directory(full_path)

    findings = []
    for r in results:
        file_path = r.metadata.get("file_path", str(full_path))
        for dr in r.triggered_rules:
            findings.append({
                "file": file_path,
                "rule_id": dr.rule_id,
                "rule_name": dr.rule_name,
                "severity": _sev(dr.severity),
                "action": _act(dr.action),
                "match_count": dr.match_count,
                "matched_text": dr.matches[0].matched_text if dr.matches else None,
            })
        # Log each file result to audit database
        _audit_log(r, direction="batch", file_path=file_path)

    return json.dumps({
        "scan_path": full_path,
        "files_scanned": len(results),
        "total_findings": len(findings),
        "findings": findings,
    }, ensure_ascii=False, indent=2)


@kasra_server.tool(
    name="kasra_get_rules",
    description=(
        "List all available security rules loaded in the Kasra engine. "
        "Returns rule ID, name, category, severity, and action for each rule. "
        "Use this to understand what detections are active."
    ),
)
def get_rules(
    category: str | None = None,
    severity: str | None = None,
    enabled_only: bool = True,
) -> str:
    _ensure_engine()
    all_rules = engine_service.engine.get_rules()

    filtered = []
    for rule in all_rules:
        if enabled_only and not rule.enabled:
            continue
        if category and rule.category != category:
            continue
        sev = _sev(rule.severity)
        if severity and sev != severity:
            continue
        filtered.append({
            "id": rule.id,
            "name": rule.name,
            "description": rule.description,
            "category": rule.category,
            "severity": sev,
            "action": _act(rule.action),
            "enabled": rule.enabled,
        })

    # Also include scanner rules (SEC/IAC)
    try:
        from kasra.scanner import CodeReviewScanner
        _s = CodeReviewScanner()
        _s.load_rules()
        for _r in _s.rules:
            _rid = _r.get("id", "")
            if enabled_only and not _r.get("enabled", True):
                continue
            if category and _r.get("category") != category:
                continue
            if severity and _r.get("severity") != severity:
                continue
            # Skip if already added from engine rules
            if any(r["id"] == _rid for r in filtered):
                continue
            filtered.append({
                "id": _rid,
                "name": _r.get("name", _rid),
                "description": _r.get("description", ""),
                "category": _r.get("category", "code_security"),
                "severity": _r.get("severity", "P1"),
                "action": _r.get("action", "warn"),
                "enabled": True,
            })
    except ImportError:
        pass

    return json.dumps({
        "total": len(filtered),
        "rules": filtered,
    }, ensure_ascii=False, indent=2)


@kasra_server.tool(
    name="kasra_health",
    description=(
        "Check if the Kasra security engine is running and healthy. "
        "Returns engine status, number of loaded rules, and audit status."
    ),
)
def health() -> str:
    if not engine_service.is_initialized:
        return json.dumps({
            "status": "unhealthy",
            "message": "RuleEngine not initialized",
        })

    engine = engine_service.engine
    return json.dumps({
        "status": "healthy",
        "rules_loaded": engine.rule_count,
        "audit_enabled": engine.config.audit.enabled,
        "timestamp": datetime.utcnow().isoformat(),
    }, ensure_ascii=False)


@kasra_server.tool(
    name="kasra_scan_prompt",
    description=(
        "COMPREHENSIVE: Scan both the developer prompt AND the AI response in one call. "
        "This is the recommended tool for MCP-based AI tools. It runs input detection "
        "on the prompt, then output detection on the response, and combines results. "
        "Use this when you control both sides of the conversation."
    ),
)
def scan_prompt(prompt: str, response: str = "", user_id: str | None = None) -> str:
    _ensure_engine()

    input_result = engine_service.detect_input(prompt, user_id=user_id)
    _audit_log(input_result, direction="input", user_id=user_id, content=prompt)

    output_result = None
    if response.strip():
        output_result = engine_service.detect_output(response, user_id=user_id)
        _audit_log(output_result, direction="output", user_id=user_id, content=response)

    return json.dumps({
        "input": {
            "blocked": input_result.blocked,
            "action": str(input_result.overall_action.value if hasattr(input_result.overall_action, "value") else input_result.overall_action),
            "severity": str(input_result.overall_severity.value if hasattr(input_result.overall_severity, "value") else input_result.overall_severity),
            "triggered_rules": [
                {"rule_id": dr.rule_id, "rule_name": dr.rule_name, "severity": _sev(dr.severity)}
                for dr in input_result.triggered_rules
            ],
            "warnings": input_result.warnings,
        },
        "output": {
            "blocked": output_result.blocked if output_result else False,
            "triggered_rules": [
                {"rule_id": dr.rule_id, "rule_name": dr.rule_name, "severity": _sev(dr.severity)}
                for dr in (output_result.triggered_rules if output_result else [])
            ],
        } if output_result else None,
    }, ensure_ascii=False, indent=2)


# ===========================================================================
# Internal helpers
# ===========================================================================


def _ensure_engine() -> None:
    """Ensure the RuleEngine is initialized."""
    if not engine_service.is_initialized:
        engine_service.initialize()


def _format_result(result: Any, direction: str) -> str:
    """Format an AggregatedResult as a JSON string."""
    return json.dumps({
        "direction": direction,
        "blocked": result.blocked,
        "action": str(result.overall_action.value if hasattr(result.overall_action, "value") else result.overall_action),
        "severity": str(result.overall_severity.value if hasattr(result.overall_severity, "value") else result.overall_severity),
        "triggered_rules": [
            {
                "rule_id": dr.rule_id,
                "rule_name": dr.rule_name,
                "severity": _sev(dr.severity),
                "action": _act(dr.action),
                "match_count": dr.match_count,
                "matched_text": dr.matches[0].matched_text if dr.matches else None,
                "evidence": [
                    {"source_layer": e.source_layer, "reason": e.reason}
                    for e in dr.evidence
                ] if dr.evidence else [],
            }
            for dr in result.triggered_rules
        ],
        "warnings": result.warnings,
        "execution_time_ms": result.execution_time_ms,
    }, ensure_ascii=False, indent=2)


# ===========================================================================
# CLI entry point
# ===========================================================================

if __name__ == "__main__":
    import sys

    port = int(os.environ.get("KASRA_MCP_PORT", "8090"))
    host = os.environ.get("KASRA_MCP_HOST", "0.0.0.0")

    from app.database import init_db
    from app.models.audit_log import AuditLog  # noqa: F401
    from app.models.rule_config import RuleConfig  # noqa: F401
    from app.models.user_behavior import UserBehavior  # noqa: F401
    from app.models.user import User  # noqa: F401

    init_db()
    _ensure_engine()

    print(f"Kasra MCP Server starting on {host}:{port} (SSE)...", file=sys.stderr)
    kasra_server.run(transport="sse")
