#!/usr/bin/env bash
# ===========================================================================
# Kasra Hook Helper — Security detection for Claude Code Hooks
# ===========================================================================
# Architecture:
#   ┌─ Primary: HTTP API → localhost:8090 (Docker Kasra API service)
#   │  The hooks call the REST API directly (fast, real-time detection).
#   │  Docker runs 24/7, so this is always available.
#   │
#   └─ Fallback: Direct Python SDK (no server needed)
#      Uses kasra-sdk RuleEngine inline.
# ===========================================================================
#
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

CONTENT=$(cat)
if [ -z "$CONTENT" ]; then
    exit 0
fi

# Kasra server endpoint (Docker)
KASRA_API="${KASRA_API_URL:-http://localhost:8090}"
KASRA_API_TIMEOUT=5
KASRA_API_KEY="${KASRA_HOOK_API_KEY:-}"
HAS_CURL=1
command -v curl &>/dev/null || HAS_CURL=0

# ── Detection via HTTP API (primary) ────────────────────────────────────────
# The Docker container runs 24/7 at localhost:8090.
# This is the same detection engine that powers MCP.

api_detect() {
    local mode="$1"  # "input" or "output"
    local payload
    payload=$(python3 -c "
import sys, json
text = sys.stdin.read()
print(json.dumps({'content': text, 'user_id': 'claude-code'}))
" <<< "$CONTENT" 2>/dev/null) || return 2

    # Auth header if configured
    local auth_arg=()
    if [ -n "$KASRA_API_KEY" ]; then
        auth_arg=(-H "X-API-Key: $KASRA_API_KEY")
    fi

    local response
    response=$(curl -s --max-time "$KASRA_API_TIMEOUT" \
        -X POST "$KASRA_API/v1/scan/$mode" \
        -H "Content-Type: application/json" \
        "${auth_arg[@]}" \
        -d "$payload" 2>/dev/null) || return 2

    # Parse and display results
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
        print(f\"  [{r.get('severity','')}] {r.get('rule_id','')}: {r.get('rule_name','')}\")
except: pass
" 2>/dev/null
        echo ""
        return 1
    fi

    # Warnings
    local warnings
    warnings=$(echo "$response" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    for w in d.get('warnings', []) or []:
        print(w)
except: pass
" 2>/dev/null)
    if [ -n "$warnings" ]; then
        echo "⚠️  Kasra warnings:" >&2
        echo "$warnings" | while IFS= read -r w; do echo "  ⚠ $w" >&2; done
    fi
    return 0
}

api_detect_output() {
    local auth_arg=()
    if [ -n "$KASRA_API_KEY" ]; then
        auth_arg=(-H "X-API-Key: $KASRA_API_KEY")
    fi

    local payload
    payload=$(python3 -c "
import sys, json
text = sys.stdin.read()
print(json.dumps({'content': text, 'user_id': 'claude-code'}))
" <<< "$CONTENT" 2>/dev/null) || return 2

    local response
    response=$(curl -s --max-time "$KASRA_API_TIMEOUT" \
        -X POST "$KASRA_API/v1/scan/output" \
        -H "Content-Type: application/json" \
        "${auth_arg[@]}" \
        -d "$payload" 2>/dev/null) || return 2

    echo "$response" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    rules = d.get('triggered_rules', [])
    if rules:
        print('⚠️  Kasra output detection:')
        for r in rules:
            print(f\"  [{r.get('severity','')}] {r.get('rule_id','')}: {r.get('rule_name','')}\")
except: pass
" 2>/dev/null
    return 0
}


# ── Direct SDK Fallback (no server needed) ──────────────────────────────────
# Used when the Docker container is not running or curl isn't available.

SDK_DETECT=$(cat << 'PYEOF'
import sys, json, os
# Suppress startup logs
os.environ.setdefault('KASRA_AUDIT__JSONL_PATH', '/dev/null')
os.environ.setdefault('KASRA_AUDIT__ENABLED', 'false')
try:
    from kasra import RuleEngine
    eng = RuleEngine()
    eng.load_rules()
    text = sys.stdin.read()
    if not text.strip():
        print(json.dumps({"blocked": False, "triggered_rules": []}))
        sys.exit(0)
    mode = sys.argv[1]
    if mode == "input":
        result = eng.detect_input(text)
    else:
        result = eng.detect_output(text)
    rules = []
    for r in getattr(result, "triggered_rules", []) or []:
        sev = str(r.severity.value) if hasattr(r.severity, "value") else str(r.severity)
        act = str(r.action.value) if hasattr(r.action, "value") else str(r.action)
        rules.append({
            "rule_id": r.rule_id, "rule_name": r.rule_name,
            "severity": sev, "action": act, "match_count": r.match_count,
        })
    print(json.dumps({
        "blocked": bool(getattr(result, "blocked", False)),
        "triggered_rules": rules,
        "warnings": list(getattr(result, "warnings", []) or []),
    }))
except ImportError:
    print("FALLBACK_FAILED")
    sys.exit(2)
except Exception as e:
    print(f"SDK ERROR: {e}")
    sys.exit(2)
PYEOF
)

sdk_detect() {
    local mode="$1"
    local result
    result=$("$KASRA_PYTHON" -c "$SDK_DETECT" "$mode" 2>/dev/null <<< "$CONTENT") || true

    if [ "$result" = "FALLBACK_FAILED" ] || [ -z "$result" ]; then
        return 2
    fi
    if echo "$result" | grep -q "^SDK ERROR"; then
        return 2
    fi

    local blocked
    blocked=$(echo "$result" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print('true' if d.get('blocked') else 'false')
except: print('false')
" 2>/dev/null)

    if [ "$blocked" = "true" ]; then
        echo "⚠️  Kasra detected risk, blocked" >&2
        return 1
    fi

    local warnings
    warnings=$(echo "$result" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    for w in d.get('warnings', []) or []:
        print(w)
except: pass
" 2>/dev/null)
    if [ -n "$warnings" ]; then
        echo "⚠️  Kasra warnings:" >&2
        echo "$warnings" | while IFS= read -r w; do echo "  ⚠ $w" >&2; done
    fi
    return 0
}


# ── Main ────────────────────────────────────────────────────────────────────

KASRA_PYTHON="${KASRA_PYTHON:-python3}"

case "${1:-input}" in
    input)
        # Primary: HTTP API → Docker
        if [ "$HAS_CURL" -eq 1 ]; then
            api_detect "input" && exit 0 || true
            # Fallback: maybe API unreachable → fall through to SDK
        fi
        # Fallback: Direct Python SDK
        sdk_detect "input" && exit 0 || true
        exit 0
        ;;
    output)
        if [ "$HAS_CURL" -eq 1 ]; then
            api_detect_output && exit 0 || true
        fi
        sdk_detect "output" && exit 0 || true
        exit 0
        ;;
    scan)
        # Direct SDK scan (keep existing code for scan)
        "$KASRA_PYTHON" -c "
import sys, json, os
os.environ.setdefault('KASRA_AUDIT__JSONL_PATH', '/dev/null')
os.environ.setdefault('KASRA_AUDIT__ENABLED', 'false')
try:
    from kasra import RuleEngine
    eng = RuleEngine()
    eng.load_rules()
    path = sys.argv[1]
    result = eng.scan_file(path)
    findings = getattr(result, 'triggered_rules', []) or []
    if findings:
        for r in findings:
            sev = str(r.severity.value) if hasattr(r.severity, 'value') else str(r.severity)
            rid = getattr(r, 'rule_id', '?')
            name = getattr(r, 'rule_name', '')
            print(f'  [{sev}] {rid}: {name}')
except Exception as e:
    print(f'ERROR: {e}')
    sys.exit(1)
" "$CONTENT" 2>/dev/null || true
        exit 0
        ;;
    *)
        echo "Usage: kasra-hook {input|output|scan}" >&2
        exit 2
        ;;
esac
