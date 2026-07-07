#!/usr/bin/env bash
# ===========================================================================
# Kasra Hook Helper — Security detection script for Claude Code Hooks
# ===========================================================================
# Usage:
#   echo "some text" | kasra-hook input     # Input detection (can block)
#   echo "some code" | kasra-hook output    # Output detection (warn only)
#   echo "some code" | kasra-hook scan      # Code review (warn only)
#
# Return codes:
#   0 = safe / warnings only
#   1 = blocked (P0 risk detected)
# ===========================================================================

set -o pipefail

KASRA_API="${KASRA_API_URL:-http://localhost:8080}"
KASRA_API_TIMEOUT=5

# ── Read stdin ──────────────────────────────────────────────────────────────
CONTENT=$(cat)
if [ -z "$CONTENT" ]; then
    exit 0
fi

# ── Detection functions ─────────────────────────────────────────────────────

detect_input() {
    local payload
    payload=$(echo "$CONTENT" | python3 -c "
import sys, json
text = sys.stdin.read()
print(json.dumps({'content': text, 'user_id': 'claude-code'}))
" 2>/dev/null) || return 2

    # Prefer REST API, fall back to CLI
    local response
    response=$(curl -s --max-time $KASRA_API_TIMEOUT \
        -X POST "$KASRA_API/v1/scan/input" \
        -H "Content-Type: application/json" \
        -d "$payload" 2>/dev/null)

    if [ -z "$response" ]; then
        # Fallback: CLI
        response=$(echo "$CONTENT" | kasra-scan input --stdin 2>/dev/null) || true
        if echo "$response" | grep -qi "blocked\|❌ BLOCKED"; then
            echo "⚠️  Kasra (CLI) detected risk, blocked"
            return 1
        fi
        return 0
    fi

    local blocked
    blocked=$(echo "$response" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print('true' if d.get('blocked') else 'false')
except: print('false')
" 2>/dev/null)

    if [ "$blocked" = "true" ]; then
        echo ""
        echo "╔══════════════════════════════════════════════════════════════╗"
        echo "║  🔒 Kasra Security — Risky content blocked                ║"
        echo "╚══════════════════════════════════════════════════════════════╝"
        echo "$response" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    for r in d.get('triggered_rules', []):
        sev = r.get('severity', '')
        rid = r.get('rule_id', '')
        name = r.get('rule_name', '')
        print(f'  [{sev}] {rid}: {name}')
except: pass
" 2>/dev/null
        echo ""
        return 1
    fi

    # Warnings but not blocked
    local warnings
    warnings=$(echo "$response" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    ws = d.get('warnings', [])
    if ws:
        print('\\n'.join(f'  ⚠ {w}' for w in ws))
except: pass
" 2>/dev/null)
    if [ -n "$warnings" ]; then
        echo "⚠️  Kasra warnings:"
        echo "$warnings"
    fi
    return 0
}

detect_output() {
    local payload
    payload=$(echo "$CONTENT" | python3 -c "
import sys, json
text = sys.stdin.read()
print(json.dumps({'content': text, 'user_id': 'claude-code'}))
" 2>/dev/null) || return 2

    local response
    response=$(curl -s --max-time $KASRA_API_TIMEOUT \
        -X POST "$KASRA_API/v1/scan/output" \
        -H "Content-Type: application/json" \
        -d "$payload" 2>/dev/null)

    if [ -z "$response" ]; then
        # Fallback: CLI — use input detection as an approximation since
        # there is no dedicated output detection CLI command.
        # This may give approximate results.
        response=$(echo "$CONTENT" | kasra-scan input --stdin 2>/dev/null) || true
        if echo "$response" | grep -qi "blocked\|❌ BLOCKED"; then
            echo "⚠️  Kasra (CLI) detected output risk"
        fi
        return 0
    fi

    local blocked
    blocked=$(echo "$response" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print('true' if d.get('blocked') else 'false')
except: print('false')
" 2>/dev/null)

    if [ "$blocked" = "true" ]; then
        echo ""
        echo "╔══════════════════════════════════════════════════════════════╗"
        echo "║  🔒 Kasra Output — Risky content detected                 ║"
        echo "╚══════════════════════════════════════════════════════════════╝"
        echo "$response" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    for r in d.get('triggered_rules', []):
        sev = r.get('severity', '')
        rid = r.get('rule_id', '')
        name = r.get('rule_name', '')
        print(f'  [{sev}] {rid}: {name}')
except: pass
" 2>/dev/null
        echo ""
    fi
    return 0
}

detect_scan() {
    # Write content to a temp file, then scan
    local tmpfile
    tmpfile=$(mktemp /tmp/kasra-hook-XXXXXX 2>/dev/null)
    echo "$CONTENT" > "$tmpfile"

    kasra-scan scan "$tmpfile" --quiet 2>/dev/null || true
    rm -f "$tmpfile"
    return 0
}

# ── Main ────────────────────────────────────────────────────────────────────

case "${1:-input}" in
    input)
        detect_input
        exit $?
        ;;
    output)
        detect_output
        exit $?
        ;;
    scan)
        detect_scan
        exit $?
        ;;
    *)
        echo "Usage: kasra-hook {input|output|scan}" >&2
        exit 2
        ;;
esac
