---
name: code-review
description: 🔒 Perform deep security review of the current code repository using the Kasra security engine (supports AI-driven MCP tool invocation and CLI mode)
metadata:
  type: skill
---

# Kasra Code Review

When a user types `/code-review [path]`, use the Kasra security detection engine to perform a security review of the code repository.

## Execution Methods

### Method 1: MCP Tool (Recommended, AI auto-executes)

If the Kasra MCP Server is registered, call the MCP tool directly:

1. Invoke `kasra_scan_file` to scan the project root directory (or the user-specified path)
   - Parameter `path` is the user-specified directory, defaults to `.`
2. Analyze returned findings, sorted by severity: 🔴 P0 → 🟡 P1 → 🟢 P2
3. For each finding, provide:
   - Risk description (why this is a security issue)
   - Problem location (file:line)
   - Fix recommendation + safe code example
4. Output summary: files scanned, findings found, severity distribution

### Method 2: CLI Scan (fallback when MCP is unavailable)

If the MCP tool is unavailable, execute directly:

```bash
kasra-scan review <path> --json
```

Parse the JSON output and perform the same analysis and reporting.

## Output Format

```
🔒 Kasra Security Review Report
━━━━━━━━━━━━━━━━━━━
📁 Scan path: ./src
📄 Files scanned: 45
🔍 Findings: 3 (P0: 1, P1: 1, P2: 1)

🔴 P0 - [SEC-05] SQL Injection Risk
   File: src/api/routes.py:42
   Risk: Using string concatenation to build SQL queries, vulnerable to injection
   Fix: Use parameterized queries
   ───
   ❌ Unsafe: cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
   ✅ Safe: cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

🟡 P1 - [SEC-12] XSS Risk
   ...

🟢 P2 - [IAC-01] Dockerfile image tag not pinned
   ...

📊 Overall Assessment: ⚠️ High-risk issues found, fix before committing
```

## Suggested Commands

| Command | Description |
|---------|-------------|
| `/code-review` | Scan current project |
| `/code-review ./src` | Scan specified directory |
| `/code-review --severity P0` | View P0 issues only |
