#!/bin/bash
# =============================================================================
# Kasra — PostgreSQL database initialization script
# =============================================================================
# Runs automatically on first startup of the PostgreSQL container.
# Docker entrypoint executes .sql and .sh files under /docker-entrypoint-initdb.d/
# in filename order.
# =============================================================================

set -e

echo "=== Kasra: Starting database initialization ==="

# ── 1. Execute DDL ─────────────────────────────────────────────────────────
echo ">>> Creating table structure (DDL)..."
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -f /docker-entrypoint-initdb.d/01-ddl.sql
echo "    DDL complete ✓"

# ── 2. Execute DML ─────────────────────────────────────────────────────────
echo ">>> Inserting seed data (DML)..."
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -f /docker-entrypoint-initdb.d/02-master-data.sql
echo "    DML complete ✓"

# ── 3. Verification ─────────────────────────────────────────────────────────
echo ">>> Verifying database..."
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    SELECT 'Tables created:' AS info, count(*)::text FROM information_schema.tables WHERE table_schema = 'public';
    SELECT 'Rules loaded:' AS info, count(*)::text FROM rules;
    SELECT 'Users created:' AS info, count(*)::text FROM users;
    SELECT 'Audit logs seeded:' AS info, count(*)::text FROM audit_logs;
EOSQL

echo "=== Kasra: Database initialization complete ==="
