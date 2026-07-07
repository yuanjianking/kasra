#!/usr/bin/env bash
# =============================================================================
# Kasra — Enterprise Database Restore Script
# =============================================================================
# Usage:
#   sudo ./restore.sh <backup_file>
#   sudo ./restore.sh /var/backups/kasra/daily/kasra_daily_20240101_120000.sqlite
#   sudo ./restore.sh /var/backups/kasra/daily/kasra_daily_20240101_120000.dump
#   sudo ./restore.sh /var/backups/kasra/daily/kasra_daily_20240101_120000.dump.age  # decrypts automatically
# =============================================================================
set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <backup_file>"
    echo ""
    echo "Supports: .sqlite, .dump (pg_dump), .age (age-encrypted), .gpg (gpg-encrypted)"
    exit 1
fi

BACKUP_FILE="$1"
KASRA_HOME="${KASRA_HOME:-/opt/kasra}"
DATABASE_URL="${KASRA_DATABASE_URL:-sqlite:////data/kasra.db}"
ENCRYPTION_KEY="${KASRA_BACKUP_ENCRYPTION_KEY:-}"

log()   { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
error() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $*" >&2; exit 1; }

# ── Decryption ───────────────────────────────────────────────────────────────

decrypt_if_needed() {
    local file="$1"

    case "$file" in
        *.age)
            if [ -z "$ENCRYPTION_KEY" ]; then
                error "Encrypted backup (.age) but KASRA_BACKUP_ENCRYPTION_KEY is not set"
            fi
            local decrypted="${file%.age}"
            log "Decrypting with age..."
            echo "$ENCRYPTION_KEY" | age --decrypt --passphrase --output "$decrypted" "$file"
            echo "$decrypted"
            ;;
        *.gpg)
            local decrypted="${file%.gpg}"
            log "Decrypting with GPG..."
            gpg --decrypt --output "$decrypted" "$file"
            echo "$decrypted"
            ;;
        *)
            echo "$file"
            ;;
    esac
}

# ── Restore Functions ────────────────────────────────────────────────────────

restore_postgres() {
    local backup="$1"
    log "Restoring PostgreSQL from $backup ..."

    # Extract connection info
    local db_url="$DATABASE_URL"

    # Drop and recreate database
    PGPASSWORD="${KASRA_DB_PASSWORD:-}" dropdb --if-exists "$db_url" 2>/dev/null || true
    PGPASSWORD="${KASRA_DB_PASSWORD:-}" createdb "$db_url" || error "Failed to create database"

    # Restore using pg_restore
    PGPASSWORD="${KASRA_DB_PASSWORD:-}" pg_restore \
        --no-owner \
        --no-acl \
        --clean \
        --if-exists \
        --jobs=4 \
        --dbname="$db_url" \
        "$backup" || error "pg_restore failed"

    log "PostgreSQL restore complete"
}

restore_sqlite() {
    local backup="$1"
    local db_path="${DATABASE_URL#sqlite:///}"

    # Make path absolute if relative
    if [[ "$db_path" != /* ]]; then
        db_path="${KASRA_HOME}/${db_path}"
    fi

    log "Restoring SQLite to $db_path from $backup ..."

    # Stop Kasra service first
    log "Ensure Kasra is stopped: sudo systemctl stop kasra"

    # Verify backup integrity
    if command -v sqlite3 &>/dev/null; then
        sqlite3 "$backup" "PRAGMA integrity_check;" | grep -q "ok" || error "Backup integrity check FAILED"
    fi

    # Create backup of current database before overwriting
    if [ -f "$db_path" ]; then
        local pre_restore_backup="${db_path}.pre-restore-$(date +%Y%m%d_%H%M%S)"
        cp "$db_path" "$pre_restore_backup"
        log "Current database backed up to: $pre_restore_backup"
    fi

    # Ensure target directory exists
    mkdir -p "$(dirname "$db_path")"

    # Restore
    if command -v sqlite3 &>/dev/null; then
        sqlite3 "$db_path" ".restore '$backup'" || {
            # Fallback: direct file copy
            cp "$backup" "$db_path"
        }
    else
        cp "$backup" "$db_path"
    fi

    # Fix permissions
    chown kasra:kasra "$db_path" 2>/dev/null || true
    chmod 640 "$db_path" 2>/dev/null || true

    log "SQLite restore complete"
}

# ── Main ─────────────────────────────────────────────────────────────────────

main() {
    if [ ! -f "$BACKUP_FILE" ]; then
        error "Backup file not found: $BACKUP_FILE"
    fi

    log "Starting restore from: $BACKUP_FILE ($(du -h "$BACKUP_FILE" | cut -f1))"

    # Decrypt if needed
    local restore_source
    restore_source=$(decrypt_if_needed "$BACKUP_FILE")

    # Determine type and restore
    case "$restore_source" in
        *.dump) restore_postgres "$restore_source" ;;
        *.sqlite) restore_sqlite "$restore_source" ;;
        *.db) restore_sqlite "$restore_source" ;;
        *)
            # Auto-detect
            local file_type
            file_type=$(file "$restore_source")
            if echo "$file_type" | grep -qi "sqlite"; then
                restore_sqlite "$restore_source"
            elif echo "$file_type" | grep -qi "postgreSQL"; then
                restore_postgres "$restore_source"
            else
                error "Cannot determine database type from file: $restore_source"
            fi
            ;;
    esac

    log "✅ Restore completed successfully from: $BACKUP_FILE"
    log "Start Kasra: sudo systemctl start kasra"
    exit 0
}

main
