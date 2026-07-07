"""Kasra MCP Server — Model Context Protocol implementation.

Exposes Kasra's security detection capabilities as MCP tools,
compatible with Claude Desktop, Cursor, and any MCP client.

## Usage

### Claude Desktop integration (stdio):
\`\`\`json
{
  "mcpServers": {
    "kasra": {
      "command": "python",
      "args": ["-m", "app.mcp_server"]
    }
  }
}
\`\`\`

### Web SSE access (via FastAPI):
    http://localhost:8080/v1/mcp/sse

### Direct Python:
    from app.mcp_server import kasra_server
    async with kasra_server.run_stdio_async():
        ...
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from app.services.engine_service import engine_service

# ---------------------------------------------------------------------------
# FastMCP Server instance
# ---------------------------------------------------------------------------

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
    host="0.0.0.0",
    port=8931,
    sse_path="/sse",
    message_path="/messages/",
)


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
    """Scan user/AI input for security risks.

    Args:
        content: The text content to scan (e.g. a developer's prompt).
        user_id: Optional developer identifier for audit logging.

    Returns:
        JSON string with scan results.
    """
    _ensure_engine()
    result = engine_service.detect_input(content, user_id=user_id)
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
    """Scan AI-generated output for security risks.

    Args:
        content: The AI-generated text content to scan.
        user_id: Optional developer identifier for audit logging.

    Returns:
        JSON string with scan results.
    """
    _ensure_engine()
    result = engine_service.detect_output(content, user_id=user_id)
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
    """Scan a file or directory for code security vulnerabilities.

    Args:
        path: Absolute path to a file or directory to scan.

    Returns:
        JSON string with scan findings.
    """
    _ensure_engine()

    # Security: prevent path traversal (check before abspath normalization
    # so sneaky paths like "safe_dir/../../etc/passwd" are caught)
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
                "severity": str(dr.severity.value if hasattr(dr.severity, "value") else dr.severity),
                "action": str(dr.action.value if hasattr(dr.action, "value") else dr.action),
                "match_count": dr.match_count,
                "matched_text": dr.matches[0].matched_text if dr.matches else None,
            })

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
    """List Kasra security rules.

    Args:
        category: Filter by category (credential_leak, pii, injection, code_security, etc.).
        severity: Filter by severity (P0, P1, P2).
        enabled_only: Only return enabled rules (default: True).

    Returns:
        JSON string with rule definitions.
    """
    _ensure_engine()
    all_rules = engine_service.engine.get_rules()

    filtered = []
    for rule in all_rules:
        if enabled_only and not rule.enabled:
            continue
        if category and rule.category != category:
            continue
        sev = str(rule.severity.value if hasattr(rule.severity, "value") else rule.severity)
        if severity and sev != severity:
            continue

        filtered.append({
            "id": rule.id,
            "name": rule.name,
            "description": rule.description,
            "category": rule.category,
            "severity": sev,
            "action": str(rule.action.value if hasattr(rule.action, "value") else rule.action),
            "enabled": rule.enabled,
        })

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
    """Check Kasra engine health.

    Returns:
        JSON string with health status info.
    """
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
    """Scan both prompt (input) and AI response (output) together.

    Args:
        prompt: The user/developer input text to scan.
        response: The AI-generated response text to scan (optional).
        user_id: Optional developer identifier.

    Returns:
        JSON string with combined scan results.
    """
    _ensure_engine()

    input_result = engine_service.detect_input(prompt, user_id=user_id)
    output_result = None
    if response.strip():
        output_result = engine_service.detect_output(response, user_id=user_id)

    return json.dumps({
        "input": {
            "blocked": input_result.blocked,
            "action": str(input_result.overall_action.value if hasattr(input_result.overall_action, "value") else input_result.overall_action),
            "severity": str(input_result.overall_severity.value if hasattr(input_result.overall_severity, "value") else input_result.overall_severity),
            "triggered_rules": [
                {"rule_id": dr.rule_id, "rule_name": dr.rule_name, "severity": str(dr.severity.value if hasattr(dr.severity, "value") else dr.severity)}
                for dr in input_result.triggered_rules
            ],
            "warnings": input_result.warnings,
        },
        "output": {
            "blocked": output_result.blocked if output_result else False,
            "triggered_rules": [
                {"rule_id": dr.rule_id, "rule_name": dr.rule_name, "severity": str(dr.severity.value if hasattr(dr.severity, "value") else dr.severity)}
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
                "severity": str(dr.severity.value if hasattr(dr.severity, "value") else dr.severity),
                "action": str(dr.action.value if hasattr(dr.action, "value") else dr.action),
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
# CLI entry point (for Claude Desktop stdio transport)
# ===========================================================================

if __name__ == "__main__":
    # Ensure engine is initialized before accepting MCP connections
    _ensure_engine()
    print("Kasra MCP Server starting (stdio transport)...", file=__import__("sys").stderr)
    kasra_server.run()
