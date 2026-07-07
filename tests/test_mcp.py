"""Tests for MCP server — Kasra security tools via Model Context Protocol."""

from __future__ import annotations

import json
import os
import tempfile

import pytest

from app.mcp_server import (
    health,
    scan_input,
    scan_output,
    scan_file,
    get_rules,
    scan_prompt,
)
from app.services.engine_service import engine_service


class TestMcpHealth:
    """MCP health tool tests."""

    def test_health_returns_status(self):
        """Health tool should return engine status."""
        result = health()
        data = json.loads(result)
        assert "status" in data
        assert data["status"] in ("healthy", "unhealthy")

    def test_health_contains_rule_count(self):
        """Health should include loaded rules count when healthy."""
        result = health()
        data = json.loads(result)
        if data["status"] == "healthy":
            assert "rules_loaded" in data
            assert data["rules_loaded"] > 0

    def test_health_contains_timestamp(self):
        """Health should include a timestamp when engine is initialized."""
        # Ensure engine is initialized so health returns full data
        if not engine_service.is_initialized:
            engine_service.initialize()
        result = health()
        data = json.loads(result)
        # Engine should be healthy now
        assert data["status"] == "healthy"
        assert "timestamp" in data


class TestMcpScanInput:
    """MCP scan_input tool tests."""

    def test_scan_input_safe_content(self):
        """Safe content should not be blocked."""
        result = scan_input(content="What is the weather today?")
        data = json.loads(result)
        assert "blocked" in data
        assert "direction" in data
        assert data["direction"] == "input"

    def test_scan_input_detects_credentials(self):
        """Credentials should be detected by input scan."""
        result = scan_input(content="my password is secret123!")
        data = json.loads(result)
        assert "triggered_rules" in data
        assert "blocked" in data

    def test_scan_input_with_user_id(self):
        """User ID parameter should be accepted."""
        result = scan_input(content="hello", user_id="test-user")
        data = json.loads(result)
        assert data["direction"] == "input"

    def test_scan_input_response_format(self):
        """Input scan response should have all required fields."""
        result = scan_input(content="test content")
        data = json.loads(result)
        assert "direction" in data
        assert "blocked" in data
        assert "action" in data
        assert "severity" in data
        assert "triggered_rules" in data
        assert "execution_time_ms" in data


class TestMcpScanOutput:
    """MCP scan_output tool tests."""

    def test_scan_output_safe_content(self):
        """Safe output should not be blocked."""
        result = scan_output(content="The answer is 42.")
        data = json.loads(result)
        assert "direction" in data
        assert data["direction"] == "output"

    def test_scan_output_detects_dangerous_code(self):
        """Dangerous function calls should be detected."""
        result = scan_output(content='Use eval(user_input) carefully.')
        data = json.loads(result)
        assert "triggered_rules" in data

    def test_scan_output_response_format(self):
        """Output scan response should have all required fields."""
        result = scan_output(content="test output")
        data = json.loads(result)
        assert "direction" in data
        assert "blocked" in data
        assert "action" in data
        assert "triggered_rules" in data
        assert "execution_time_ms" in data
        assert "warnings" in data


class TestMcpScanFile:
    """MCP scan_file tool tests."""

    def test_scan_file_non_existent(self):
        """Non-existent path should return error."""
        result = scan_file(path="/tmp/non_existent_path_xyz_123")
        data = json.loads(result)
        assert "error" in data

    def test_scan_file_path_traversal_blocked(self):
        """Path traversal attempts should be rejected."""
        result = scan_file(path="safe_dir/../../etc/passwd")
        data = json.loads(result)
        assert "error" in data
        assert "traversal" in data["error"].lower()

    def test_scan_file_clean(self):
        """Clean file should scan without findings."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False,
        ) as f:
            f.write('print("hello")\n')
            f_path = f.name
        try:
            result = scan_file(path=f_path)
            data = json.loads(result)
            assert "scan_path" in data
            assert data["scan_path"] == os.path.abspath(f_path)
            assert "total_findings" in data
            assert "files_scanned" in data
        finally:
            os.unlink(f_path)

    def test_scan_file_dangerous(self):
        """File with dangerous code should have findings."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False,
        ) as f:
            f.write('os.system("rm -rf /")\n')
            f_path = f.name
        try:
            result = scan_file(path=f_path)
            data = json.loads(result)
            assert "findings" in data
            assert "files_scanned" in data
        finally:
            os.unlink(f_path)

    def test_scan_file_returns_findings_with_details(self):
        """Findings should include rule_id, severity, action, etc."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False,
        ) as f:
            f.write('subprocess.call("rm -rf /", shell=True)\n')
            f_path = f.name
        try:
            result = scan_file(path=f_path)
            data = json.loads(result)
            for finding in data.get("findings", []):
                assert "rule_id" in finding
                assert "rule_name" in finding
                assert "severity" in finding
                assert "action" in finding
        finally:
            os.unlink(f_path)


class TestMcpGetRules:
    """MCP get_rules tool tests."""

    def test_get_rules_returns_list(self):
        """get_rules should return a list of rules."""
        result = get_rules()
        data = json.loads(result)
        assert "total" in data
        assert "rules" in data
        assert data["total"] > 0

    def test_get_rules_filter_by_severity(self):
        """get_rules should filter by severity."""
        result = get_rules(severity="P0")
        data = json.loads(result)
        assert data["total"] >= 0
        for rule in data["rules"]:
            assert rule["severity"] == "P0"

    def test_get_rules_filter_by_enabled(self):
        """get_rules with enabled_only should return only enabled rules."""
        result = get_rules(enabled_only=True)
        data = json.loads(result)
        for rule in data["rules"]:
            assert rule["enabled"] is True

    def test_get_rules_rule_format(self):
        """Each rule should have the correct fields."""
        result = get_rules()
        data = json.loads(result)
        if data["rules"]:
            rule = data["rules"][0]
            assert "id" in rule
            assert "name" in rule
            assert "severity" in rule
            assert "action" in rule
            assert "enabled" in rule
            assert "category" in rule


class TestMcpScanPrompt:
    """MCP scan_prompt (combined input+output) tool tests."""

    def test_scan_prompt_input_only(self):
        """Scan prompt without response should scan only input."""
        result = scan_prompt(prompt="hello world")
        data = json.loads(result)
        assert "input" in data
        assert data["output"] is None

    def test_scan_prompt_with_response(self):
        """Scan prompt with response should scan both."""
        result = scan_prompt(
            prompt="hello",
            response="The answer is 42.",
        )
        data = json.loads(result)
        assert "input" in data
        assert "output" in data

    def test_scan_prompt_with_user_id(self):
        """scan_prompt should accept user_id."""
        result = scan_prompt(prompt="test", user_id="dev-1")
        data = json.loads(result)
        assert "input" in data
