"""Kasra MCP Server — Code Review only.

Exposes only ``kasra_scan_file`` for security code review.
Input/output detection is handled by hooks (kasra-hook.sh) at the harness level.
"""
from __future__ import annotations

import json
import os

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
# MCP Tools — only code review
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
def scan_file(path: str) -> str:
    """Scan a file or directory for code security vulnerabilities.

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

    return json.dumps({
        "scan_path": full_path,
        "files_scanned": len(results),
        "total_findings": len(findings),
        "findings": findings,
    }, ensure_ascii=False, indent=2)


# ===========================================================================
# Internal helpers
# ===========================================================================


def _ensure_engine() -> None:
    """Ensure the RuleEngine is initialized."""
    if not engine_service.is_initialized:
        engine_service.initialize()


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
