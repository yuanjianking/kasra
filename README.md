# Kasra

**AI Development Security Governance Platform** — a security gateway between development teams and AI coding tools.

Making the AI-assisted coding process fully **visible, controllable, and auditable**.

---

## Three Integration Methods

Kasra provides three integration methods for different use cases:

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Developer / System Access Methods                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─── Method 1: HTTP Proxy ──────────────────────────────────────┐  │
│  │  export HTTP_PROXY=http://kasra:8080/v1/proxy                  │  │
│  │  Covers: Claude Code / Copilot / Cursor / all HTTP traffic     │  │
│  │  Feature: Full interception, zero dev effort, once configured  │  │
│  └─────────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  ┌─── Method 2: MCP Protocol ────────────────────────────────────┐  │
│  │  Claude Desktop/IDE → MCP Server → Kasra Detection Engine     │  │
│  │  Covers: Claude Desktop / Cursor / MCP-compatible AI tools    │  │
│  │  Feature: Standardized protocol, unified AI tool interface     │  │
│  └─────────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  ┌─── Method 3: CLI Scanner ──────────────────────────────────────┐  │
│  │  kasra-scan review ./src --format json                         │  │
│  │  Covers: Code repos / CI/CD pipelines / pre-release checks     │  │
│  │  Feature: No proxy needed, scans filesystem directly            │  │
│  └─────────────────────────────────────────────────────────────────┘  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

### Method 1: HTTP Proxy (Zero-Friction Developer Integration)

Developers only need to set environment variables — all AI tool traffic automatically passes through Kasra detection.

```bash
# Developer terminal configuration
export HTTP_PROXY=http://kasra.company.com:8080/v1/proxy
export HTTPS_PROXY=http://kasra.company.com:8080/v1/proxy

# After configuration, all Claude Code / Copilot / Cursor requests are intercepted by Kasra
# Detection flow:
#   Developer → Claude Code
#       → HTTP request enters Kasra proxy
#       → Input detection (prevent leaks, prevent injection)
#       → Safe → Forward to AI API
#       → AI response received → Output detection (prevent dangerous code)
#       → Log to audit trail
#       → Return to developer
```

#### Direct REST API Calls

```bash
# Input detection (before sending to AI)
curl -X POST http://localhost:8080/v1/scan/input \
  -H "Content-Type: application/json" \
  -d '{"content": "my password is admin123", "user_id": "dev1"}'

# Output detection (after AI response)
curl -X POST http://localhost:8080/v1/scan/output \
  -H "Content-Type: application/json" \
  -d '{"content": "eval(user_input)", "user_id": "dev1"}'

# Batch code repository scan
curl -X POST http://localhost:8080/v1/scan/batch \
  -H "Content-Type: application/json" \
  -d '{"path": "./src"}'

# View audit logs
curl "http://localhost:8080/v1/audit/logs?page_size=10&severity=P0"

# Dashboard data
curl http://localhost:8080/v1/dashboard/summary
```

---

### Method 2: MCP Protocol (Native AI Tool Integration)

Kasra implements an MCP (Model Context Protocol) Server, allowing AI development tools to call Kasra's security detection capabilities directly.

#### Claude Desktop Integration

Register the Kasra MCP Server in Claude Desktop configuration:

```json
{
  "mcpServers": {
    "kasra": {
      "command": "python",
      "args": ["-m", "app.mcp_server"],
      "env": {
        "KASRA_ENGINE__MAX_CONCURRENT_RULES": "50"
      }
    }
  }
}
```

#### SSE (Server-Sent Events) Integration

Kasra's MCP SSE endpoint starts automatically with the main service:

```
http://localhost:8080/v1/mcp/sse
```

Compatible with Cursor, Continue.dev, and other MCP SSE-aware tools.

#### Kasra MCP Tools

| Tool | Description | Parameters |
|------|-------------|-----------|
| `kasra_scan_input` | Scan developer input (before sending to AI) | `content`, `user_id?` |
| `kasra_scan_output` | Scan AI output (before returning to developer) | `content`, `user_id?` |
| `kasra_scan_prompt` | Simultaneous scan of input+output | `prompt`, `response?`, `user_id?` |
| `kasra_scan_file` | Scan file/directory for security vulnerabilities | `path` |
| `kasra_get_rules` | List all security rules | `category?`, `severity?`, `enabled_only?` |
| `kasra_health` | Check engine health status | None |

#### Direct Usage via stdio

```bash
# Start MCP stdio server
python -m app.mcp_server

# Invoke from CI/CD
echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"kasra_scan_file","arguments":{"path":"./src"}}}' | python -m app.mcp_server
```

---

### Method 3: CLI Scanner (Code Repository / CI Integration)

The Kasra SDK includes a full-featured CLI tool `kasra-scan`, suitable for local development or CI/CD pipeline code scanning.

```bash
# Scan entire project
kasra-scan review ./src

# JSON format output (suitable for CI integration)
kasra-scan review ./src --json

# View only P0 severity issues
kasra-scan review ./src --severity P0

# Input detection
kasra-scan input "my password is secret123"

# View engine status
kasra-scan info
kasra-scan health
kasra-scan metrics
```

CI/CD usage (GitHub Actions example):

```yaml
- name: Security Scan
  run: |
    pip install kasra-sdk
    kasra-scan review ./src --json --severity P0 > report.json
    if [ $(jq '.findings | length' report.json) -gt 0 ]; then
      echo "Security risks found!"
      cat report.json
      exit 1
    fi
```

---

## Core Features

### Input Detection (I-Series Rules)

| Rule | Detection Target | Action | Severity |
|------|-----------------|--------|----------|
| I-01 | GitHub Token (ghp_) | Block | P0 |
| I-02 | OpenAI API Key (sk-) | Block | P0 |
| I-03 | Anthropic API Key | Block | P0 |
| I-04 | AWS Access Key (AKIA) | Block | P0 |
| I-05 | Generic Password/Secret | Block | P0 |
| I-08 | Phone Number | Redact | P1 |
| I-09 | National ID Number | Redact | P1 |
| I-11 | Prompt Injection Attack | Block | P0 |
| I-12 | Jailbreak/Role-Play Attack | Block | P0 |

### Output Detection (O-Series Rules)

| Rule | Detection Target | Action | Severity |
|------|-----------------|--------|----------|
| O-01 | Dangerous Function Call (eval/exec) | Warn | P0 |
| O-02 | Dangerous Shell Command (rm -rf /) | Block | P0 |
| O-03 | Credential Leak in Output | Block | P0 |
| O-04 | SQL Concatenation (non-parameterized) | Warn | P2 |

### Code Batch Scan (SEC/IAC/ARCH Rules)

Covers SQL injection, XSS, SSRF, path traversal, hardcoded secrets, Dockerfile security, K8s configuration, and **110+ rules** total.

### Audit & Compliance

- All detection events automatically logged to audit trail
- Compliance report export (CSV/JSON) with one click
- Hash chain ensures audit log tamper-proof integrity

---

## Web Dashboard

Open `http://localhost:8080` to access the Web console:

| Page | Features |
|------|----------|
| 📊 **Dashboard** | 24h statistics, block rate, trend chart, top rules/users |
| 📋 **Audit Logs** | Paginated queries, severity/direction filtering |
| 🛡️ **Rule Management** | 110+ rule list, enable/disable, custom rules |
| 👤 **User Behavior** | User behavior analysis, anomaly scores |

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check (includes DB status) |
| `POST` | `/v1/scan/input` | Input detection |
| `POST` | `/v1/scan/output` | Output detection |
| `POST` | `/v1/scan/batch` | Batch code scan |
| `GET` | `/v1/audit/logs` | Audit log query |
| `GET` | `/v1/audit/report` | Compliance report |
| `GET/POST/PUT/DELETE` | `/v1/rules` | Rule CRUD |
| `GET` | `/v1/dashboard/summary` | Dashboard summary |
| `GET` | `/v1/dashboard/trend` | Trend data |
| `GET` | `/v1/dashboard/users/behavior` | User behavior analysis |
| `ALL` | `/v1/proxy/{path}` | HTTP proxy forwarding |
| `SSE` | `/v1/mcp/sse` | MCP Server (SSE protocol) |

Full API documentation: `http://localhost:8080/docs`

---

## Quick Start

```bash
# Install
pip install -e .

# Start service (development mode)
uvicorn app.main:app --reload --port 8080

# Verify
curl http://localhost:8080/health

# Test detection
curl -X POST http://localhost:8080/v1/scan/input \
  -H "Content-Type: application/json" \
  -d '{"content": "export GITHUB_TOKEN=ghp_abc123def456", "user_id": "test"}'
# → {"blocked": true, ...}
```

## Docker Deployment

```bash
# Development mode (SQLite)
docker compose up -d

# Production mode (PostgreSQL)
export POSTGRES_PASSWORD=your-strong-password
docker compose --profile production up -d
```
