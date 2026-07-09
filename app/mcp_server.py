"""Kasra MCP Server — Code Review tools only.

Exposes MCP tools for:
  - ``kasra_scan_file``     — file/directory code review (SEC/IAC rules)
  - ``kasra_get_rules``     — list loaded rules
  - ``health``              — engine health status

Input/output detection is handled by hooks (kasra-hook.sh) at the harness level.
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
        "Kasra Code Review tool. Scans files and directories for security "
        "vulnerabilities: SQL injection, XSS, hardcoded secrets, "
        "Docker/K8s misconfigurations, and 160+ other code security rules. "
        "Use kasra_scan_file to review code before committing."
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
    name="kasra_get_rules",
    description="List all loaded security rules with their severity, action, and status.",
)
def mcp_get_rules(severity: str | None = None, enabled_only: bool | None = None) -> str:
    """MCP tool: return all loaded rules."""
    return get_rules(severity=severity, enabled_only=enabled_only)


@kasra_server.tool(
    name="health",
    description="Check the Kasra RuleEngine health status.",
)
def mcp_health() -> str:
    """MCP tool: return engine health."""
    return health()


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
