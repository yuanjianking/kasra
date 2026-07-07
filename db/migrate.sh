#!/bin/bash
# =============================================================================
# Kasra — Database migration tool
# =============================================================================
# Manually execute SQL migration scripts, supports both SQLite and PostgreSQL.
#
# Usage:
#   ./db/migrate.sh                    # Show status
#   ./db/migrate.sh up                 # Run all pending migrations
#   ./db/migrate.sh up <version>       # Run up to a specific version
#   ./db/migrate.sh down               # Roll back the last migration
#   ./db/migrate.sh reset              # Reset the database (recreate all tables)
#   ./db/migrate.sh seed               # Re-insert seed data
#
# Environment variables:
#   DATABASE_URL   — Database connection string (default: sqlite:///data/kasra.db)
# =============================================================================

set -euo pipefail

MIGRATIONS_DIR="$(cd "$(dirname "$0")" && pwd)/migrations"
INIT_DIR="$(cd "$(dirname "$0")" && pwd)/init"
DATABASE_URL="${DATABASE_URL:-sqlite:///data/kasra.db}"

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# ── Detect database type ────────────────────────────────────────────────────
detect_db_type() {
    if [[ "$DATABASE_URL" == sqlite* ]]; then
        echo "sqlite"
    elif [[ "$DATABASE_URL" == postgresql* ]]; then
        echo "postgres"
    else
        echo "unknown"
    fi
}

# ── Initialize schema (DDL) ────────────────────────────────────────────────
run_ddl() {
    local db_type
    db_type=$(detect_db_type)
    log_info "Initializing database schema (${db_type})..."

    if [[ "$db_type" == "sqlite" ]]; then
        # SQLite: use Python and SQLAlchemy to create tables
        python3 -c "
from app.database import engine, Base
from app.models.audit_log import AuditLog
from app.models.rule_config import RuleConfig
from app.models.user_behavior import UserBehavior
from app.models.user import User
Base.metadata.create_all(bind=engine)
print('SQLite tables created successfully')
"
    elif [[ "$db_type" == "postgres" ]]; then
        # PostgreSQL: execute SQL directly
        local conn_str="${DATABASE_URL/postgresql:\/\//}"
        conn_str="${conn_str/postgresql+psycopg2:\/\//}"
        PGPASSWORD="${PGPASSWORD:-}" psql "$conn_str" -f "$INIT_DIR/01-ddl.sql"
    fi

    log_info "Schema initialization complete ✓"
}

# ── Insert seed data (DML) ─────────────────────────────────────────────────
run_dml() {
    local db_type
    db_type=$(detect_db_type)
    log_info "Inserting seed data (${db_type})..."

    if [[ "$db_type" == "sqlite" ]]; then
        # SQLite: use Python script
        python3 "$INIT_DIR/seed_sqlite.py"
    elif [[ "$db_type" == "postgres" ]]; then
        local conn_str="${DATABASE_URL/postgresql:\/\//}"
        conn_str="${conn_str/postgresql+psycopg2:\/\//}"
        PGPASSWORD="${PGPASSWORD:-}" psql "$conn_str" -f "$INIT_DIR/02-dml.sql"
    fi

    log_info "Seed data insertion complete ✓"
}

# ── Run migrations ──────────────────────────────────────────────────────────
run_migrations() {
    local db_type
    db_type=$(detect_db_type)
    log_info "Running migration scripts (${db_type})..."

    mkdir -p "$MIGRATIONS_DIR"

    local migrated=0
    for f in $(ls "$MIGRATIONS_DIR"/*.sql 2>/dev/null | sort); do
        local version
        version=$(basename "$f" | cut -d- -f1)

        # Check if already executed
        if [[ "$db_type" == "sqlite" ]]; then
            local done_flag="$MIGRATIONS_DIR/.done_${version}"
            if [[ -f "$done_flag" ]]; then
                log_info "  Skipping ${version} (already executed)"
                continue
            fi
        fi

        log_info "  Executing ${version}: $(basename "$f")..."
        if [[ "$db_type" == "sqlite" ]]; then
            sqlite3 "$(echo "$DATABASE_URL" | sed 's/sqlite:\/\///')" < "$f"
            touch "$done_flag"
        elif [[ "$db_type" == "postgres" ]]; then
            local conn_str="${DATABASE_URL/postgresql:\/\//}"
            conn_str="${conn_str/postgresql+psycopg2:\/\//}"
            PGPASSWORD="${PGPASSWORD:-}" psql "$conn_str" -f "$f"
        fi
        migrated=$((migrated + 1))
    done

    log_info "Migration complete: $migrated scripts executed"
}

# ── Main logic ──────────────────────────────────────────────────────────────
main() {
    local cmd="${1:-status}"

    case "$cmd" in
        up)
            run_ddl
            run_migrations
            echo ""
            log_info "Database is up to date ✓"
            ;;
        down)
            log_warn "Rollback requires manually writing down migration scripts. Edit $MIGRATIONS_DIR directly."
            ;;
        reset)
            log_warn "Resetting database... All data will be lost!"
            run_ddl
            run_dml
            log_info "Database reset complete ✓"
            ;;
        seed)
            run_dml
            ;;
        status)
            local db_type
            db_type=$(detect_db_type)
            echo "════════════════════════════════════════"
            echo "  Kasra Database Status"
            echo "════════════════════════════════════════"
            echo "  Database type: ${db_type}"
            echo "  Connection:    ${DATABASE_URL}"
            echo "  Migrations:    ${MIGRATIONS_DIR}"
            echo ""
            echo "  DDL:      ${INIT_DIR}/01-ddl.sql"
            echo "  DML:      ${INIT_DIR}/02-dml.sql"
            echo ""
            echo "  Executed migrations:"
            for f in "$MIGRATIONS_DIR"/.done_* 2>/dev/null; do
                if [[ -f "$f" ]]; then
                    echo "    ✓ $(basename "$f" | sed 's/.done_//')"
                fi
            done
            echo ""
            echo "  Pending migrations:"
            for f in "$MIGRATIONS_DIR"/*.sql 2>/dev/null; do
                local version
                version=$(basename "$f" | cut -d- -f1)
                if [[ ! -f "$MIGRATIONS_DIR/.done_${version}" ]]; then
                    echo "    · $(basename "$f")"
                fi
            done
            echo ""
            log_info "Run ./db/migrate.sh up to execute pending migrations"
            echo ""
            ;;
        *)
            echo "Usage: $0 {up|down|reset|seed|status}"
            exit 1
            ;;
    esac
}

main "$@"
