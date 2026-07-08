#!/usr/bin/env bash
# ===========================================================================
# Kasra Hook — Security detection for Claude Code Hooks
# Uses Kasra MCP Server HTTP API
# NOTE: Set KASRA_SKIP_HOOK=1 to bypass (for internal Kasra dev work)
# ===========================================================================

# Allow internal development bypass
if [ "${KASRA_SKIP_HOOK:-0}" = "1" ]; then
    exit 0
fi
#
# Events:
#   UserPromptSubmit → exit 2 (stderr shown in dialog)
#   PreToolUse       → exit 0 + JSON {permissionDecision: "deny"}
#   PostToolUse      → exit 0 + JSON {additionalContext} for warnings
# ===========================================================================
set -o pipefail

INPUT_JSON=$(cat)
[ -z "$INPUT_JSON" ] && exit 0

# ── Extract event info ──────────────────────────────────────────────────────
HOOK_EVENT=$(python3 -c "import sys, json; d=json.load(sys.stdin); print(d.get('hook_event_name','') or d.get('_mode',''))" <<< "$INPUT_JSON" 2>/dev/null)
[ -z "$HOOK_EVENT" ] && exit 0

# ── Extract content to scan based on event type ─────────────────────────────
SCAN_CONTENT=$(python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    ev = d.get('hook_event_name', '')
    if ev == 'UserPromptSubmit':
        print(d.get('prompt', ''))
    elif ev == 'PreToolUse':
        ti = d.get('tool_input', {}) or {}
        print(ti.get('command', '') or ti.get('content', '') or ti.get('new_string', '') or ti.get('file_path', '') or ti.get('pattern', '') or str(ti))
    elif ev == 'PostToolUse':
        ti = d.get('tool_input', {}) or {}
        tr = d.get('tool_response', '') or ''
        print(ti.get('command', '') or ti.get('content', '') or ti.get('new_string', '') or str(tr))
    else:
        print(d.get('content', '') or str(d))
except: pass
" <<< "$INPUT_JSON" 2>/dev/null)

[ -z "$SCAN_CONTENT" ] || [ "$SCAN_CONTENT" = "None" ] && exit 0

# ── Logging ─────────────────────────────────────────────────────────────────
LOG="$HOME/.kasra/hooks.log"
mkdir -p "$(dirname "$LOG")"
log_event() {
    local level="$1" rule_info="$2"
    local snippet
    snippet=$(echo "$SCAN_CONTENT" | head -c 80 | tr '\n' ' ')
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $rule_info | event=$HOOK_EVENT snippet=\"$snippet\"" >> "$LOG"
}

# ═════════════════════════════════════════════════════════════════════════════
# Kasra API scan
# ═════════════════════════════════════════════════════════════════════════════
KASRA_API="${KASRA_API_URL:-http://localhost:8090}"
KASRA_API_KEY="${KASRA_HOOK_API_KEY:-}"
HOOK_USER="${KASRA_USER_ID:-$USER}"
HOOK_USER="${HOOK_USER:-unknown}"

api_scan() {
    local mode="$1"
    local payload response blocked auth_arg

    payload=$(python3 -c "import sys, json; print(json.dumps({'content': sys.stdin.read(), 'user_id': sys.argv[1]}))" "$HOOK_USER" <<< "$SCAN_CONTENT" 2>/dev/null) || return 0

    auth_arg=()
    [ -n "$KASRA_API_KEY" ] && auth_arg=(-H "X-API-Key: $KASRA_API_KEY")

    response=$(curl -s --max-time 3 \
        -X POST "$KASRA_API/v1/scan/$mode" \
        -H "Content-Type: application/json" \
        "${auth_arg[@]}" \
        -d "$payload" 2>/dev/null) || return 0

    blocked=$(python3 -c "import sys, json; d=json.load(sys.stdin); print('true' if d.get('blocked') else 'false')" <<< "$response" 2>/dev/null)

    if [ "$blocked" = "true" ]; then
        echo "$response"
        return 1
    fi

    local has_warn
    has_warn=$(python3 -c "import sys, json; d=json.load(sys.stdin); rules = d.get('triggered_rules', []) or []; print('true' if len(rules) > 0 else 'false')" <<< "$response" 2>/dev/null)

    if [ "$has_warn" = "true" ]; then
        echo "$response"
        return 3
    fi

    return 0
}

format_rules() {
    python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    parts = []
    for r in d.get('triggered_rules', []) or []:
        s = r.get('severity', '')
        i = r.get('rule_id', '?')
        n = r.get('rule_name', '')
        parts.append('[' + s + '] ' + i + ': ' + n)
    print('; '.join(parts))
except: print('unknown')
" 2>/dev/null
}

# ═════════════════════════════════════════════════════════════════════════════
# Event handlers
# ═════════════════════════════════════════════════════════════════════════════

# UserPromptSubmit: block via exit 2 (stderr shown in dialog)
handle_blocked_user_prompt() {
    local rule_info="$1"
    log_event "BLOCKED" "$rule_info"
    echo "🔒 Kasra Security — Your message was blocked. Reason: $rule_info" >&2
    exit 2
}

# PreToolUse: deny via JSON
handle_blocked_pre_tool() {
    local rule_info="$1"
    log_event "BLOCKED" "$rule_info"
    python3 - "$rule_info" << 'PYEOF'
import sys, json
reason = f"🔒 Kasra Security blocked this action: {sys.argv[1]}"
print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": reason}}))
PYEOF
    exit 0
}

# PostToolUse: warn via additionalContext
handle_warning() {
    local warn_info="$1"
    log_event "WARN" "$warn_info"
    python3 - "$warn_info" << 'PYEOF'
import sys, json
msg = f"⚠️ Kasra Security warning: {sys.argv[1]}"
print(json.dumps({"hookSpecificOutput": {"hookEventName": "PostToolUse", "additionalContext": msg}}))
PYEOF
    exit 0
}

# ═════════════════════════════════════════════════════════════════════════════
# Main dispatch
# ═════════════════════════════════════════════════════════════════════════════
INPUT_MODE="${1:-input}"

case "$HOOK_EVENT" in
    UserPromptSubmit)
        result=$(api_scan "input")
        rc=$?
        [ $rc -eq 1 ] && handle_blocked_user_prompt "$(echo "$result" | format_rules)"
        [ $rc -eq 3 ] && log_event "WARN" "$(echo "$result" | format_rules)"
        exit 0
        ;;
    PreToolUse)
        result=$(api_scan "input")
        rc=$?
        [ $rc -eq 1 ] && handle_blocked_pre_tool "$(echo "$result" | format_rules)"
        exit 0
        ;;
    PostToolUse)
        result=$(api_scan "output")
        rc=$?
        [ $rc -eq 1 ] || [ $rc -eq 3 ] && handle_warning "$(echo "$result" | format_rules)"
        exit 0
        ;;
    *)
        exit 0
        ;;
esac
