# Kasra Claude Code Integration Configuration

This directory contains pre-built configuration files for integrating Kasra with Claude Code.

---

## Directory Structure

```
configs/
├── README.md                  # This file — installation guide
├── skills/
│   └── code-review.md         # /code-review — code security review skill
└── hooks/
    ├── claude-hooks.json      # hooks configuration template
    └── kasra-hook.sh          # hook helper script
```

---

## 1. Install Skill (Code Review)

The skill enables `/code-review` command in Claude Code for security review of code repositories.

### Installation

Copy the skill file to Claude Code's global skills directory:

```bash
# Copy to global skills directory
cp configs/skills/code-review.md ~/.claude/skills/

# Or copy to project-level skills directory
mkdir -p .claude/skills/
cp configs/skills/code-review.md .claude/skills/
```

### Usage

```bash
# In Claude Code, type:
/code-review           # Scan current project
/code-review ./src     # Scan specified directory
```

Claude Code will automatically call the Kasra MCP tool (or fall back to `kasra-scan` CLI) for security review, and output results sorted by severity.

---

## 2. Install Hooks (Automatic Input/Output Detection)

Hooks allow Claude Code to **automatically** call the Kasra detection engine at key lifecycle events:

| Hook Event | Trigger Point | Detection Scope | Can Block |
|-----------|--------------|----------------|:---------:|
| `UserPromptSubmit` | Before sending user prompt | Credential leaks, PII, prompt injection | ✅ Yes |
| `PreToolUse (Bash)` | Before shell command execution | Dangerous commands, credential leaks | ✅ Yes |
| `PreToolUse (Write/Edit)` | Before file write | Dangerous code writing | ✅ Yes |
| `PostToolUse (Write/Edit)` | After AI generates code | Dangerous function calls, SQL injection, XSS | ❌ No |
| `PostToolUse (Bash)` | After command execution | Sensitive info disclosure in output | ❌ No |
| `PostToolUse (Read)` | After file read | File content security risks | ❌ No |

### Installation

#### Method 1: Project-level config (recommended, per-project only)

Merge the hooks config into the project root's `.claude/settings.local.json`:

```bash
# Ensure kasra-hook.sh is accessible from the project root
cp configs/hooks/kasra-hook.sh .claude/kasra-hook.sh
chmod +x .claude/kasra-hook.sh

# Edit .claude/settings.local.json, add the hooks section
# Refer to configs/hooks/claude-hooks.json for the hooks structure
```

Example `.claude/settings.local.json`:

```json
{
  "permissions": {
    "allow": [
      "bash configs/hooks/kasra-hook.sh *"
    ]
  },
  "hooks": {
    "UserPromptSubmit": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "bash configs/hooks/kasra-hook.sh input",
            "timeout": 10000,
            "description": "🔒 Kasra Input Scan"
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Write|Edit",
        "hooks": [
          {
            "type": "command",
            "command": "bash configs/hooks/kasra-hook.sh output",
            "timeout": 15000,
            "description": "🛡️ Kasra Output Scan"
          }
        ]
      },
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "bash configs/hooks/kasra-hook.sh output",
            "timeout": 10000,
            "description": "🛡️ Kasra Output Scan"
          }
        ]
      }
    ]
  }
}
```

> ⚠️ **Note**: Hooks depend on the `kasra-hook.sh` script, which will first try the Kasra REST API (`localhost:8080`),
> then fall back to the `kasra-scan` CLI. Ensure the Kasra service is running, or the SDK is installed.

---

## 3. Prerequisites

### Must have (at least one)

- **Kasra service running** (recommended): `http://localhost:8080/v1/scan/input`
- **SDK installed**: `pip install kasra-sdk`

### Verification

```bash
# Verify service is reachable
curl -s http://localhost:8080/health

# Or verify CLI is available
kasra-scan health
```

---

## 4. Complete Integration Example

Full flow to integrate Kasra into a Claude Code project:

```bash
# 1. Copy skill
cp -r kasra/configs/skills ~/.claude/

# 2. Copy hook script to project
cp kasra/configs/hooks/kasra-hook.sh your-project/.claude/
chmod +x your-project/.claude/kasra-hook.sh

# 3. Configure hooks
# Edit your-project/.claude/settings.local.json, add hooks config from above

# 4. Start Kasra service
cd kasra && uvicorn app.main:app --port 8080 &

# 5. Start Claude Code
cd your-project && claude

# 6. Use in Claude Code
/code-review
```
