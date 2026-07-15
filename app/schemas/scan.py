"""Pydantic schemas for scan (input/output/batch) API endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


# ── Requests ──


class ScanInputRequest(BaseModel):
    """Input detection request — content to scan before reaching AI."""

    content: str = Field(..., min_length=1, description="User input content to scan")
    user_id: str | None = Field(default=None, description="Developer identifier")
    session_id: str | None = Field(default=None, description="AI conversation session ID")
    request_id: str | None = Field(default=None, description="Request identifier")


class ScanOutputRequest(BaseModel):
    """Output detection request — AI-generated content to scan."""

    content: str = Field(..., min_length=1, description="AI output content to scan")
    user_id: str | None = Field(default=None, description="Developer identifier")
    session_id: str | None = Field(default=None, description="AI conversation session ID")
    request_id: str | None = Field(default=None, description="Request identifier")


class BatchScanRequest(BaseModel):
    """Batch scan request — scan a code directory or file."""

    path: str = Field(..., description="Path to file or directory on the server")
    user_id: str | None = Field(default=None, description="Requesting user")


class ScanFileRequest(BaseModel):
    """Single file scan request — send file content for code review."""

    content: str = Field(..., min_length=1, description="File content to scan")
    filename: str | None = Field(default=None, description="Original filename (for extension detection)")
    user_id: str | None = Field(default=None, description="Requesting user")


# ── Responses ──


class MatchSpanSchema(BaseModel):
    """A specific matched span within content."""

    start: int = Field(..., description="Start position in content")
    end: int = Field(..., description="End position in content (exclusive)")
    matched: str = Field(..., description="The matched text snippet")
    redacted: str | None = Field(default=None, description="Redacted replacement, if any")


class TriggeredRuleSchema(BaseModel):
    """A rule that triggered during detection."""

    rule_id: str = Field(..., description="Rule ID, e.g. I-01, SEC-06")
    rule_name: str = Field(..., description="Human-readable rule name")
    severity: str = Field(..., description="P0 / P1 / P2")
    action: str = Field(..., description="Action taken: block / warn / redact / clean / truncate")
    match_count: int = Field(default=0, description="Number of matches")
    matched_text: str | None = Field(default=None, description="Matched text snippet")
    evidence: list[dict[str, Any]] = Field(default_factory=list, description="Evidence chain items")


class ScanResponse(BaseModel):
    """Unified scan response for input and output detection."""

    blocked: bool = Field(default=False, description="Whether content was blocked")
    action: str = Field(default="warn", description="Overall action taken")
    severity: str = Field(default="P2", description="Highest severity triggered")
    triggered_rules: list[TriggeredRuleSchema] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    execution_time_ms: float = Field(default=0.0)
    redacted_content: str | None = Field(default=None, description="Content with redactions applied")
    metadata: dict[str, Any] = Field(default_factory=dict)


class BatchScanFileResult(BaseModel):
    """Result for a single file in batch scan."""

    file_path: str = Field(..., description="Relative file path")
    triggered_rules: list[TriggeredRuleSchema] = Field(default_factory=list)
    severity: str = Field(default="ok", description="ok / P2 / P1 / P0")
    execution_time_ms: float = Field(default=0.0)


class BatchScanResponse(BaseModel):
    """Batch scan response — results for all scanned files."""

    total_files: int = Field(default=0)
    files_with_findings: int = Field(default=0)
    total_findings: int = Field(default=0)
    results: list[BatchScanFileResult] = Field(default_factory=list)
    execution_time_ms: float = Field(default=0.0)
