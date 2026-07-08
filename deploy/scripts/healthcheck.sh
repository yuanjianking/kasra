#!/usr/bin/env bash
# =============================================================================
# Kasra — Enterprise Health Check Script
# =============================================================================
# Used by: Docker HEALTHCHECK, systemd, Kubernetes probes, monitoring
# Checks: HTTP health, database connectivity, engine status, recent events
# =============================================================================
set -euo pipefail

KASRA_URL="${KASRA_HEALTHCHECK_URL:-http://localhost:8090}"
TIMEOUT="${KASRA_HEALTHCHECK_TIMEOUT:-10}"
API_KEY="${KASRA_API_KEY:-}"

log()  { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
error(){ echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $*" >&2; exit 1; }

# ── Step 1: Basic health endpoint ────────────────────────────────────────────

log "Checking health endpoint: ${KASRA_URL}/health ..."
HEALTH=$(curl -sf --max-time "$TIMEOUT" "${KASRA_URL}/health" 2>/dev/null) || error "Health endpoint unreachable"

echo "$HEALTH" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d.get('status') == 'healthy', f'Status: {d.get(\"status\")}'" 2>/dev/null || {
    error "Health check failed: $HEALTH"
}

log "✓ Health endpoint OK"

# ── Step 2: Engine status ────────────────────────────────────────────────────

ENGINE_STATUS=$(echo "$HEALTH" | python3 -c "import sys,json; print(json.load(sys.stdin).get('engine','unknown'))" 2>/dev/null || echo "unknown")
if [ "$ENGINE_STATUS" = "unknown" ]; then
    log "⚠ Engine status not reported in health endpoint"
else
    log "✓ Engine status: $ENGINE_STATUS"
fi

# ── Step 3: API metric check (authenticated) ─────────────────────────────────

if [ -n "$API_KEY" ]; then
    log "Checking rules endpoint: ${KASRA_URL}/v1/rules?page_size=1 ..."
    RULES=$(curl -sf --max-time "$TIMEOUT" \
        -H "X-API-Key: $API_KEY" \
        "${KASRA_URL}/v1/rules?page_size=1" 2>/dev/null) || log "⚠ Rules endpoint unreachable (non-fatal)"

    if [ -n "$RULES" ]; then
        TOTAL=$(echo "$RULES" | python3 -c "import sys,json; print(json.load(sys.stdin).get('total',0))" 2>/dev/null || echo "unknown")
        log "✓ Rules loaded: $TOTAL"
    fi
fi

# ── Step 4: Database connectivity ────────────────────────────────────────────

DB_STATUS=$(echo "$HEALTH" | python3 -c "import sys,json; print(json.load(sys.stdin).get('database',{}).get('status','unknown'))" 2>/dev/null || echo "unknown")
if [ "$DB_STATUS" != "healthy" ]; then
    error "Database status: $DB_STATUS"
fi
log "✓ Database OK"

# ── All checks passed ────────────────────────────────────────────────────────

log "✅ All health checks passed"
exit 0
