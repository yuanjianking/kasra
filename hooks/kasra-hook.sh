#!/usr/bin/env bash
# ===========================================================================
# Kasra Hook Helper — Security detection for Claude Code Hooks
# Uses ONLY Kasra MCP Server HTTP API (NO Python SDK)
#
# Per official Claude Code hooks documentation:
#   PreToolUse       → exit 0 + JSON {permissionDecision: "deny"}
#   UserPromptSubmit → exit 2  → blocks prompt, stderr shown
#   PostToolUse      → exit 0 + JSON {systemMessage: "..."}
# ===========================================================================
set -o pipefail

INPUT_JSON=$(cat)
[ -z "$INPUT_JSON" ] && exit 0

# ── Extract event info ──────────────────────────────────────────────────────
HOOK_EVENT=$(echo "$INPUT_JSON" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print(d.get('hook_event_name', '') or d.get('_mode', ''))
except: print('')
" 2>/dev/null)

TOOL_NAME=$(echo "$INPUT_JSON" | python3 -c "
import sys, json
try:
    print(json.load(sys.stdin).get('tool_name', ''))
except: print('')
" 2>/dev/null)

# ── Extract content to scan ─────────────────────────────────────────────────
SCAN_CONTENT=$(echo "$INPUT_JSON" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    ev = d.get('hook_event_name', '')
    if ev == 'UserPromptSubmit':
        print(d.get('user_prompt', ''))
    elif ev in ('PreToolUse', 'PostToolUse'):
        ti = d.get('tool_input', {}) or {}
        tr = d.get('tool_result', '') or ''
        print(ti.get('command', '') or ti.get('content', '') or ti.get('new_string', '') or str(tr))
    else:
        print(d.get('content', '') or str(d))
except: pass
" 2>/dev/null)

[ -z "$SCAN_CONTENT" ] || [ "$SCAN_CONTENT" = "None" ] && exit 0

# ── Logging ─────────────────────────────────────────────────────────────────
KASRA_HOOK_LOG="${KASRA_HOOK_LOG:-$HOME/.kasra/hooks.log}"
mkdir -p "$(dirname "$KASRA_HOOK_LOG")"

log_event() {
    local level="$1" rule_info="$2"
    local ts snippet
    ts=$(date '+%Y-%m-%d %H:%M:%S')
    snippet=$(echo "$SCAN_CONTENT" | head -c 80 | tr '\n' ' ')
    echo "[$ts] [$level] $rule_info | event=$HOOK_EVENT tool=$TOOL_NAME snippet=\"$snippet\"" >> "$KASRA_HOOK_LOG"
}

# ═══════════════════════════════════════════════════════════════════════════════
# Kasra MCP Server HTTP API — ONLY detection method (no Python SDK)
# ═══════════════════════════════════════════════════════════════════════════════
KASRA_API="${KASRA_API_URL:-http://localhost:8090}"
KASRA_API_TIMEOUT=3
KASRA_API_KEY="${KASRA_HOOK_API_KEY:-}"

api_scan() {
    local mode="$1"
    local payload response rc blocked auth_arg

    # Build JSON payload
    payload=$(python3 -c "
import sys, json
print(json.dumps({'content': sys.stdin.read(), 'user_id': 'claude-code'}))
" <<< "$SCAN_CONTENT" 2>/dev/null) || return 2

    # Add API key if available (Kasra MCP Server requires X-API-Key)
    auth_arg=()
    [ -n "$KASRA_API_KEY" ] && auth_arg=(-H "X-API-Key: $KASRA_API_KEY")

    # POST to Kasra API
    response=$(curl -s --max-time "$KASRA_API_TIMEOUT" \
        -X POST "$KASRA_API/v1/scan/$mode" \
        -H "Content-Type: application/json" \
        "${auth_arg[@]}" \
        -d "$payload" 2>/dev/null) || return 2

    # Parse response
    blocked=$(echo "$response" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print('true' if d.get('blocked') else 'false')
except: print('false')
" 2>/dev/null)

    if [ "$blocked" = "true" ]; then
        # Return rule info for the event handler
        echo "$response"
        return 1
    fi

    # Check for warnings (non-blocking detections)
    local has_warn
    has_warn=$(echo "$response" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    rules = d.get('triggered_rules', []) or []
    print('true' if len(rules) > 0 else 'false')
except: print('false')
" 2>/dev/null)

    if [ "$has_warn" = "true" ]; then
        echo "$response"
        return 3  # warnings but not blocked
    fi

    return 0
}

# ── Format triggered rules ──────────────────────────────────────────────────
format_rules() {
    python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    parts = []
    for r in d.get('triggered_rules', []) or []:
        parts.append(f\"[{r.get('severity','')}] {r.get('rule_id','?')}: {r.get('rule_name','')}\")
    print('; '.join(parts))
except: print('unknown')
" 2>/dev/null
}

# ═══════════════════════════════════════════════════════════════════════════════
#  Event handlers
# ═══════════════════════════════════════════════════════════════════════════════

# PreToolUse: deny via JSON response
handle_blocked_pre_tool_use() {
    local rule_info="$1"
    local json_out
    json_out=$(python3 -c "
import sys, json
reason = f'🔒 Kasra Security blocked this action: {sys.argv[1]}'
print(json.dumps({'hookSpecificOutput': {'hookEventName': 'PreToolUse', 'permissionDecision': 'deny', 'permissionDecisionReason': reason}}))
" "$rule_info" 2>/dev/null)
    log_event "BLOCKED" "$rule_info"
    echo "$json_out"
    exit 0
}

# UserPromptSubmit: block via exit 2
handle_blocked_user_prompt() {
    local rule_info="$1"
    log_event "BLOCKED" "$rule_info"
    echo "🔒 Kasra Security — Your message was blocked. Reason: $rule_info" >&2
    exit 2
}

# PostToolUse: warn via systemMessage
handle_warning() {
    local warn_info="$1"
    log_event "WARN" "$warn_info"
    echo "{\"systemMessage\":\"⚠️ Kasra detected: $warn_info\"}"
    exit 0
}

# ═══════════════════════════════════════════════════════════════════════════════
#  Main dispatch
# ═══════════════════════════════════════════════════════════════════════════════

INPUT_MODE="${1:-input}"

# Always try API — if it's unreachable, allow through (exit 0)
# Only block/warn when API explicitly returns violations
case "$HOOK_EVENT" in
    PreToolUse)
        result=$(api_scan "$INPUT_MODE")
        rc=$?
        [ $rc -eq 1 ] && handle_blocked_pre_tool_use "$(echo "$result" | format_rules)"
        exit 0
        ;;
    UserPromptSubmit)
        result=$(api_scan "$INPUT_MODE")
        rc=$?
        [ $rc -eq 1 ] && handle_blocked_user_prompt "$(echo "$result" | format_rules)"
        [ $rc -eq 3 ] && log_event "WARN" "$(echo "$result" | format_rules)"
        exit 0
        ;;
    PostToolUse)
        result=$(api_scan "$INPUT_MODE")
        rc=$?
        [ $rc -eq 1 ] || [ $rc -eq 3 ] && handle_warning "$(echo "$result" | format_rules)"
        exit 0
        ;;
    *)
        # Direct/fallback mode
        result=$(api_scan "$INPUT_MODE")
        rc=$?
        if [ $rc -eq 1 ]; then
            log_event "BLOCKED" "$(echo "$result" | format_rules)"
            echo "🔒 Blocked:" >&2
            echo "$(echo "$result" | format_rules)" >&2
            exit 2
        fi
        exit 0
        ;;
esac
