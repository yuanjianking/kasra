"""Kasra MCP Server — Code Review + Detection tools.

Exposes MCP tools for:
  - ``kasra_scan_file``     — file/directory code review (SEC/IAC rules)
  - ``kasra_scan_input``    — input content detection (I-series rules)
  - ``kasra_scan_output``   — output content detection (O-series rules)
  - ``kasra_get_rules``     — list loaded rules
  - ``kasra_scan_prompt``   — combined input + output scan
  - ``health``              — engine health status
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from mcp.server.fastmcp import FastMCP

from app.services.engine_service import engine_service


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
    name="Kasra Code Reviewer",
    instructions=(
        "Kasra security tools. Use kasra_scan_file for code review of "
        "files and directories (SEC/IAC rules). Use kasra_scan_input / "
        "kasra_scan_output for content detection (I/O rules). "
        "Use kasra_get_rules to list all loaded rules."
    ),
    host=_mcp_host,
    port=_mcp_port,
    sse_path="/sse",
    message_path="/messages/",
)


# ===========================================================================
# Internal helpers (exported for testing)
# ===========================================================================


def _ensure_engine() -> None:
    """Ensure the RuleEngine is initialized."""
    if not engine_service.is_initialized:
        engine_service.initialize()


# ===========================================================================
# Health
# ===========================================================================


def health() -> str:
    """Return engine health status as JSON.

    Returns:
        JSON string with status, rules_loaded, and timestamp.
    """
    _ensure_engine()
    engine = engine_service.engine
    return json.dumps({
        "status": "healthy" if engine.is_loaded else "unhealthy",
        "rules_loaded": engine.rule_count,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }, ensure_ascii=False)


# ===========================================================================
# Input detection
# ===========================================================================


def scan_input(content: str, user_id: str | None = None) -> str:
    """Scan input content against I-series rules.

    Args:
        content: The text content to scan.
        user_id: Optional user identifier.

    Returns:
        JSON string with scan results.
    """
    _ensure_engine()
    kwargs = {}
    if user_id is not None:
        kwargs["user_id"] = user_id
    result = engine_service.detect_input(content, **kwargs)
    return json.dumps(_agg_result_to_dict(result, direction="input"), ensure_ascii=False)


def scan_output(content: str, user_id: str | None = None) -> str:
    """Scan output content against O-series rules.

    Args:
        content: The text content to scan.
        user_id: Optional user identifier.

    Returns:
        JSON string with scan results.
    """
    _ensure_engine()
    kwargs = {}
    if user_id is not None:
        kwargs["user_id"] = user_id
    result = engine_service.detect_output(content, **kwargs)
    return json.dumps(_agg_result_to_dict(result, direction="output"), ensure_ascii=False)


# ===========================================================================
# Code review
# ===========================================================================


def scan_file(path: str) -> str:
    """Scan a file or directory for security vulnerabilities.

    Uses the SDK's ``review_code()`` which runs SEC/IAC code security rules.

    Args:
        path: Absolute path to a file or directory to scan.

    Returns:
        JSON string with scan findings.
    """
    _ensure_engine()

    normalized = os.path.normpath(path)
    if ".." in normalized.split(os.sep):
        return json.dumps({"error": "Path traversal is not allowed", "findings": []}, ensure_ascii=False)

    full_path = os.path.abspath(path)
    if not os.path.exists(full_path):
        return json.dumps({"error": f"Path not found: {full_path}"}, ensure_ascii=False)

    result = engine_service.review_code(full_path)

    findings = []
    for f in result.findings:
        findings.append({
            "file": f.file_path,
            "rule_id": f.rule_id,
            "rule_name": f.rule_name,
            "severity": f.severity,
            "action": "warn",
            "match_count": 1,
            "matched_text": f.matched_text,
            "line_number": f.line_number,
            "column": f.column,
            "confidence": f.confidence,
            "message": f.message,
        })

    return json.dumps({
        "scan_path": result.scan_path,
        "files_scanned": result.files_scanned,
        "files_skipped": result.files_skipped,
        "total_findings": len(findings),
        "findings": findings,
        "duration_ms": round(result.duration_ms, 2),
    }, ensure_ascii=False, indent=2)


# ===========================================================================
# Rules listing
# ===========================================================================


def get_rules(severity: str | None = None, enabled_only: bool | None = None) -> str:
    """Return all loaded rules.

    Args:
        severity: Optional filter by severity (P0, P1, P2).
        enabled_only: If true, only return enabled rules.

    Returns:
        JSON string with total and rules list.
    """
    _ensure_engine()
    engine = engine_service.engine

    rules = engine.get_rules()

    # Include code review rules too
    try:
        cr_rules = engine.get_code_review_rules()
    except Exception:
        cr_rules = []

    all_rules = []
    for r in rules:
        all_rules.append({
            "id": r.id,
            "name": r.name,
            "severity": _sev(r.severity),
            "action": _act(r.action),
            "category": r.category,
            "enabled": r.enabled,
            "description": r.description,
        })
    for r in cr_rules:
        all_rules.append({
            "id": r.get("id", ""),
            "name": r.get("name", ""),
            "severity": r.get("severity", "P2"),
            "action": r.get("action", "warn"),
            "category": r.get("category", "code_security"),
            "enabled": r.get("id", "") not in engine.disabled_code_review_rule_ids,
            "description": r.get("description", ""),
        })

    # Apply filters
    if severity:
        all_rules = [r for r in all_rules if r["severity"] == severity]
    if enabled_only is not None:
        all_rules = [r for r in all_rules if r["enabled"] == enabled_only]

    return json.dumps({
        "total": len(all_rules),
        "rules": all_rules,
    }, ensure_ascii=False)


# ===========================================================================
# Combined input + output scan
# ===========================================================================


def scan_prompt(prompt: str, response: str | None = None, user_id: str | None = None) -> str:
    """Scan both input prompt and optional AI response.

    Args:
        prompt: The user input prompt.
        response: Optional AI response text.
        user_id: Optional user identifier.

    Returns:
        JSON string with input and (if provided) output scan results.
    """
    _ensure_engine()

    kwargs = {}
    if user_id is not None:
        kwargs["user_id"] = user_id

    input_result = engine_service.detect_input(prompt, **kwargs)
    output_result = None
    if response is not None:
        output_result = engine_service.detect_output(response, **kwargs)

    result = {
        "input": _agg_result_to_dict(input_result, direction="input"),
        "output": _agg_result_to_dict(output_result, direction="output") if output_result else None,
    }
    return json.dumps(result, ensure_ascii=False)


# ===========================================================================
# MCP Tool registration
# ===========================================================================


@kasra_server.tool(
    name="kasra_scan_file",
    description=(
        "SECURITY: Scan a file or directory for security vulnerabilities. "
        "Runs code review rules (SQL injection, XSS, hardcoded secrets, "
        "Docker/K8s misconfigurations, etc.) against the specified path. "
        "Supports all major programming languages and config formats."
    ),
)
def mcp_scan_file(path: str) -> str:
    """MCP tool: scan a file or directory for code security vulnerabilities."""
    return scan_file(path)


@kasra_server.tool(
    name="kasra_scan_input",
    description=(
        "Scan user input content for security risks (credential leaks, "
        "prompt injection, PII exposure, etc.). Runs I-series rules."
    ),
)
def mcp_scan_input(content: str, user_id: str | None = None) -> str:
    """MCP tool: scan input content."""
    return scan_input(content, user_id=user_id)


@kasra_server.tool(
    name="kasra_scan_output",
    description=(
        "Scan AI-generated output for security risks (dangerous function "
        "calls, shell commands, code execution, etc.). Runs O-series rules."
    ),
)
def mcp_scan_output(content: str, user_id: str | None = None) -> str:
    """MCP tool: scan output content."""
    return scan_output(content, user_id=user_id)


@kasra_server.tool(
    name="kasra_get_rules",
    description="List all loaded security rules with their severity, action, and status.",
)
def mcp_get_rules(severity: str | None = None, enabled_only: bool | None = None) -> str:
    """MCP tool: return all loaded rules."""
    return get_rules(severity=severity, enabled_only=enabled_only)


@kasra_server.tool(
    name="kasra_scan_prompt",
    description="Scan both input prompt and optional AI response in one call.",
)
def mcp_scan_prompt(prompt: str, response: str | None = None, user_id: str | None = None) -> str:
    """MCP tool: scan prompt + optional response."""
    return scan_prompt(prompt, response=response, user_id=user_id)


@kasra_server.tool(
    name="health",
    description="Check the Kasra RuleEngine health status.",
)
def mcp_health() -> str:
    """MCP tool: return engine health."""
    return health()


# ===========================================================================
# Internal helpers
# ===========================================================================


def _agg_result_to_dict(result, direction: str) -> dict:
    """Convert an AggregatedResult to a plain dict for JSON serialization."""
    triggered = []
    for dr in result.triggered_rules:
        triggered.append({
            "rule_id": dr.rule_id,
            "rule_name": dr.rule_name,
            "severity": _sev(dr.severity),
            "action": _act(dr.action),
            "match_count": dr.match_count,
            "matched_text": dr.matches[0].matched_text[:200] if dr.matches else None,
        })
    return {
        "direction": direction,
        "blocked": result.blocked,
        "action": _act(result.overall_action),
        "severity": _sev(result.overall_severity),
        "triggered_rules": triggered,
        "warnings": result.warnings,
        "execution_time_ms": result.execution_time_ms,
    }


# ===========================================================================
# CLI entry point
# ===========================================================================

if __name__ == "__main__":
    import sys

    transport = os.environ.get("KASRA_MCP_TRANSPORT", "sse")
    port = int(os.environ.get("KASRA_MCP_PORT", "8090"))
    host = os.environ.get("KASRA_MCP_HOST", "0.0.0.0")

    _ensure_engine()

    print(f"Kasra MCP Server starting (transport={transport})...", file=sys.stderr)
    kasra_server.run(transport=transport)
