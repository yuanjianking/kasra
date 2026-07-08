---
name: code-review
description: 🔒 Perform deep security review of the current code repository using the Kasra security engine (direct SDK or MCP)
metadata:
  type: skill
---

# Kasra Code Review

When a user types `/code-review [path]`, use the Kasra security detection engine to perform a security review of the code repository.

## Execution Methods (priority order)

### Method 1: Direct Python SDK (Recommended — fastest, no server needed)

Run detection by calling the `kasra` SDK RuleEngine directly:

```python
from kasra import RuleEngine

eng = RuleEngine()
eng.load_rules()
result = eng.scan_file("<path>")       # Single file
# or
results = eng.scan_directory("<path>")  # Directory
```

Then parse `result.triggered_rules` and format as the report below.

### Method 2: MCP Tool (Kasra MCP configured in settings.json)

If the Kasra MCP server is configured (SSE at localhost:8091), call `kasra_scan_file`:
- Parameter `path`: the user-specified directory, defaults to `.`

### Method 3: CLI (fallback)

```bash
kasra-scan review <path> --json
```

## Output Format

```
🔒 Kasra Security Review Report
━━━━━━━━━━━━━━━━━━━
📁 Scan path: <path>
📄 Files scanned: <N>
🔍 Findings: <N> (P0: <N>, P1: <N>, P2: <N>)

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

## Analysis Rules

When reporting findings, always include for each item:
1. **Risk description** — why this is a security issue
2. **Location** — file:line
3. **Fix recommendation** — with before/after code examples
4. **Severity** — color-coded (🔴 P0 / 🟡 P1 / 🟢 P2)

Severity priority:
- **P0** → Blocked. Must fix before merging.
- **P1** → Warning. Should fix, high risk.
- **P2** → Advisory. Best practice improvement.

## Suggested Commands

| Command | Description |
|---------|-------------|
| `/code-review` | Scan current project |
| `/code-review ./src` | Scan specified directory |
| `/code-review --severity P0` | View P0 issues only |
