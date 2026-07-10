# Kasra

**AI Development Security Governance Platform** — a security gateway between development teams and AI coding tools.

Making the AI-assisted coding process fully **visible, controllable, and auditable**.

---

## Integration Methods

Kasra provides three integration methods for different use cases:

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Integration Methods                                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─── Method 1: Claude Code Hooks ───────────────────────────────┐  │
│  │  .claude/settings.json → kasra-hook.sh                        │  │
│  │  Covers: Claude Code (UserPrompt / PreTool / PostTool)        │  │
│  │  Feature: Full input/output interception at the harness level  │  │
│  └─────────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  ┌─── Method 2: MCP Protocol ────────────────────────────────────┐  │
│  │  kasra-mcp SSE on :8091 → kasra_scan_file                     │  │
│  │  Covers: Code review (SEC/IAC rules) via AI tools              │  │
│  │  Feature: Scan files/directories for security vulnerabilities  │  │
│  └─────────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  ┌─── Method 3: REST API ────────────────────────────────────────┐  │
│  │  curl POST http://localhost:8090/v1/scan/...                   │  │
│  │  Covers: Direct integration, CI/CD, custom tooling              │  │
│  │  Feature: Full programmatic access to all features              │  │
│  └─────────────────────────────────────────────────────────────────┘  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

### Method 1: Claude Code Hooks (Automatic Interception)

The recommended way for Claude Code users. Register `kasra-hook.sh` in your Claude Code settings so every user prompt, tool invocation, and AI response is automatically scanned.

**Configure in `.claude/settings.json.local` or `~/.claude/settings.json`:**

```json
{
  "hooks": {
    "UserPromptSubmit": "bash /path/to/kasra/hooks/kasra-hook.sh input",
    "PreToolUse": "bash /path/to/kasra/hooks/kasra-hook.sh input",
    "PostToolUse": "bash /path/to/kasra/hooks/kasra-hook.sh output"
  }
}
```

**Detection flow per event:**

| Hook Event | Timing | Detection | On Violation |
|---|---|---|---|
| `UserPromptSubmit` | Developer types a message | Input scan (I-series) | Blocked with dialog, message not sent |
| `PreToolUse` | AI is about to run a tool | Input scan (I-series) | Tool denied, AI notified |
| `PostToolUse` | AI returns a response | Output scan (O-series) | Warning shown to developer |

```bash
# Environment variables for the hook (optional)
export KASRA_API_URL=http://localhost:8090
export KASRA_HOOK_API_KEY=your-api-key
```

---

### Method 2: MCP Protocol (Code Review)

Kasra exposes a dedicated MCP SSE server on port `8091` for code security review.

#### MCP Tools

| Tool | Description | Parameters |
|------|-------------|-----------|
| `kasra_scan_file` | Scan a file or directory for security vulnerabilities | `path` |
| `kasra_get_rules` | List all security rules with severity, action, and status | `severity?`, `enabled_only?` |
| `health` | Check the RuleEngine health status | None |

#### Claude Desktop / Cursor Integration

```json
{
  "mcpServers": {
    "kasra": {
      "type": "sse",
      "url": "http://localhost:8091/sse"
    }
  }
}
```

Or via command:

```json
{
  "mcpServers": {
    "kasra": {
      "command": "python",
      "args": ["-m", "app.mcp_server"]
    }
  }
}
```

---

### Method 3: REST API (Direct Integration)

Full programmatic access to all Kasra features.

#### Content Detection

```bash
# Input detection — scan developer input before it reaches the AI
curl -X POST http://localhost:8090/v1/scan/input \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{"content": "my password is admin123", "user_id": "dev1"}'

# Output detection — scan AI-generated responses
curl -X POST http://localhost:8090/v1/scan/output \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{"content": "eval(user_input)", "user_id": "dev1"}'
```

#### Code Review

```bash
# Scan a file or directory for security vulnerabilities
curl -X POST http://localhost:8090/v1/scan/batch \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{"path": "./src", "user_id": "dev1"}'
```

#### Rule Management

```bash
# List all rules (with optional filters)
curl "http://localhost:8090/v1/rules?group=input&severity=P0&page_size=20" \
  -H "X-API-Key: your-api-key"

# Get a single rule
curl "http://localhost:8090/v1/rules/I-01" -H "X-API-Key: your-api-key"

# Create a custom rule
curl -X POST http://localhost:8090/v1/rules \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{"id": "U-01", "name": "Custom Rule", "severity": "P1", "action": "warn"}'

# Enable or disable a rule
curl -X PUT http://localhost:8090/v1/rules/I-01 \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{"enabled": false}'

# Delete a custom rule or reset an SDK rule override
curl -X DELETE http://localhost:8090/v1/rules/I-01 -H "X-API-Key: your-api-key"
```

#### Audit & Reports

```bash
# Query audit logs
curl "http://localhost:8090/v1/audit/logs?page_size=10&severity=P0&direction=input" \
  -H "X-API-Key: your-api-key"

# Compliance report
curl "http://localhost:8090/v1/audit/report" -H "X-API-Key: your-api-key"

# CSV export
curl "http://localhost:8090/v1/audit/export" -H "X-API-Key: your-api-key"
```

#### Dashboard

```bash
# Summary statistics
curl "http://localhost:8090/v1/dashboard/summary" -H "X-API-Key: your-api-key"

# Trend data (7d, 30d, 90d)
curl "http://localhost:8090/v1/dashboard/trend?period=7d" -H "X-API-Key: your-api-key"

# User behavior analysis
curl "http://localhost:8090/v1/dashboard/users/behavior?user_id=dev1" \
  -H "X-API-Key: your-api-key"
```

---

## API Reference

### REST Endpoints

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| `GET` | `/health` | Health check (includes DB, engine, proxy status) | No |
| `GET` | `/metrics` | Prometheus metrics | No |
| | | | |
| `POST` | `/v1/scan/input` | Input content detection (I-series rules) | API Key |
| `POST` | `/v1/scan/output` | Output content detection (O-series rules) | API Key |
| `POST` | `/v1/scan/batch` | Code review — scan file or directory (SEC/IAC rules) | API Key |
| | | | |
| `GET` | `/v1/rules` | List all rules (supports `group`, `severity`, `enabled_only`, `custom_only`, pagination) | API Key |
| `GET` | `/v1/rules/{rule_id}` | Get a single rule by ID | API Key |
| `POST` | `/v1/rules` | Create a custom rule (U-series only) | API Key |
| `PUT` | `/v1/rules/{rule_id}` | Update a rule (enable/disable, change severity, etc.) | API Key |
| `DELETE` | `/v1/rules/{rule_id}` | Delete a custom rule or reset an SDK override | API Key |
| | | | |
| `GET` | `/v1/audit/logs` | Query audit logs (supports `user_id`, `severity`, `direction`, pagination) | API Key |
| `GET` | `/v1/audit/report` | Compliance report summary | API Key |
| `GET` | `/v1/audit/export` | CSV export of audit logs | API Key |
| | | | |
| `GET` | `/v1/dashboard/summary` | 24-hour summary statistics | API Key |
| `GET` | `/v1/dashboard/trend` | Trend data by period (7d/30d/90d) | API Key |
| `GET` | `/v1/dashboard/users/behavior` | User behavior analysis | API Key |
| | | | |
| `ALL` | `/v1/proxy/{path}` | HTTP proxy forwarding to upstream AI APIs | API Key |

### MCP Tools

| Tool | Description | Parameters |
|------|-------------|-----------|
| `kasra_scan_file` | Scan a file or directory for security vulnerabilities (SEC/IAC rules) | `path` |
| `kasra_get_rules` | List all loaded rules | `severity?`, `enabled_only?` |
| `health` | Engine health check | None |

Full interactive API documentation: `http://localhost:8090/docs`

---

## Quick Start

```bash
# Start service (development mode with SQLite)
docker compose up -d

# Verify
curl http://localhost:8090/health

# Test input detection
curl -X POST http://localhost:8090/v1/scan/input \
  -H "Content-Type: application/json" \
  -H "X-API-Key: dev-api-key-change-in-production" \
  -d '{"content": "export GITHUB_TOKEN=ghp_abc123def456", "user_id": "test"}'
# → {"blocked": true, ...}

# Open web dashboard
open http://localhost:8080
```

## Services

| Service | Port | Description |
|---------|------|-------------|
| **kasra-api** | `:8090` | FastAPI REST API + HTTPS CONNECT proxy (`:8443`) |
| **kasra-frontend** | `:8080` | React SPA web dashboard |
| **kasra-mcp** | `:8091` | MCP SSE server (code review tools) |
| **postgres** | `:5432` | PostgreSQL database |
| **adminer** | `:8083` | Database administration UI |

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                      Kasra Platform                                  │
│                                                                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │
│  │  REST API    │  │  MCP Server  │  │  CONNECT     │              │
│  │  (:8090)     │  │  (:8091)     │  │  Proxy       │              │
│  └──────┬───────┘  └──────┬───────┘  │  (:8443)     │              │
│         │                │           └──────┬───────┘              │
│         ▼                ▼                  ▼                      │
│  ┌─────────────────────────────────────────────────────┐          │
│  │              Rule Engine (kasra-sdk)                  │          │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────────────┐     │          │
│  │  │ Input    │ │ Output   │ │ Code Review      │     │          │
│  │  │ Pipeline │ │ Pipeline │ │ (SEC/IAC rules)  │     │          │
│  │  └──────────┘ └──────────┘ └──────────────────┘     │          │
│  │  110+ security rules across 10 series               │          │
│  └─────────────────────────────────────────────────────┘          │
│                                                                     │
│  ┌─────────────────────────────────────────────────────┐          │
│  │  PostgreSQL (audit_logs, rules_config, users, ...)  │          │
│  └─────────────────────────────────────────────────────┘          │
└─────────────────────────────────────────────────────────────────────┘
```

## Development

```bash
# Install SDK in development mode
pip install -e ../kasra-sdk

# Install app in development mode
pip install -e .

# Run with hot reload
uvicorn app.main:app --reload --port 8090

# Run tests
python -m pytest tests/ -v
```
