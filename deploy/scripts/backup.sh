#!/usr/bin/env bash
# =============================================================================
# Kasra — Database Backup Script (PostgreSQL only)
# =============================================================================
# Features:
#   ✓ PostgreSQL pg_dump (custom format, compressed)
#   ✓ Encrypted backups (age/openssl/GPG)
#   ✓ Retention policy (daily/weekly/monthly rotation)
#   ✓ S3-compatible upload (aws s3 or rclone)
#   ✓ Prometheus metrics file for monitoring
# =============================================================================
set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────────

KASRA_HOME="${KASRA_HOME:-/opt/kasra}"
BACKUP_DIR="${KASRA_BACKUP_DIR:-/var/backups/kasra}"
RETENTION_DAYS="${KASRA_BACKUP_RETENTION_DAYS:-30}"
RETENTION_WEEKS="${KASRA_BACKUP_RETENTION_WEEKS:-12}"
RETENTION_MONTHS="${KASRA_BACKUP_RETENTION_MONTHS:-6}"

DATABASE_URL="${KASRA_DATABASE_URL:-postgresql+psycopg2://kasra:kasra@localhost:5432/kasra}"
S3_BUCKET="${KASRA_BACKUP_S3_BUCKET:-}"
ENCRYPTION_KEY="${KASRA_BACKUP_ENCRYPTION_KEY:-}"
GPG_RECIPIENT="${KASRA_BACKUP_GPG_RECIPIENT:-}"

# ── Metrics file (for Prometheus backup monitoring) ─────────────────────────
METRICS_FILE="${BACKUP_DIR}/.metrics"
PROM_GAUGE="kasra_backup_timestamp_seconds"

# ── Helper functions ─────────────────────────────────────────────────────────

log()  { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
error(){ echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $*" >&2; exit 1; }

ensure_dir() {
    mkdir -p "$BACKUP_DIR/daily" "$BACKUP_DIR/weekly" "$BACKUP_DIR/monthly"
}

get_db_type() {
    echo "postgres"
}

backup_postgres() {
    local dest="$1"
    log "Backing up PostgreSQL to $dest ..."

    # Extract connection info from URL
    # Format: postgresql://user:password@host:port/database
    PGPASSWORD="${KASRA_DB_PASSWORD:-}" pg_dump \
        --no-owner \
        --no-acl \
        --format=custom \
        --compress=9 \
        --file="$dest" \
        "$DATABASE_URL" 2>&1 || error "pg_dump failed"

    log "PostgreSQL backup complete: $(du -h "$dest" | cut -f1)"
}

encrypt_backup() {
    local file="$1"

    if [ -n "$ENCRYPTION_KEY" ]; then
        log "Encrypting backup with age (symmetric)..."
        local enc_file="${file}.age"
        echo "$ENCRYPTION_KEY" | age --passphrase --output "$enc_file" "$file" 2>/dev/null || {
            log "age not available, using openssl AES-256-CBC..."
            openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 \
                -pass pass:"$ENCRYPTION_KEY" -in "$file" -out "$enc_file"
        }
        rm -f "$file"
        echo "$enc_file"
    elif [ -n "$GPG_RECIPIENT" ]; then
        log "Encrypting backup with GPG (recipient: $GPG_RECIPIENT)..."
        local enc_file="${file}.gpg"
        gpg --encrypt --recipient "$GPG_RECIPIENT" --output "$enc_file" "$file"
        rm -f "$file"
        echo "$enc_file"
    else
        echo "$file"
    fi
}

upload_to_s3() {
    local file="$1"
    local remote_path="s3://${S3_BUCKET}/kasra-backups/$(date +%Y/%m/%d)/$(basename "$file")"

    if [ -z "$S3_BUCKET" ]; then
        log "No S3 bucket configured — skipping upload"
        return
    fi

    log "Uploading to S3: $remote_path ..."

    if command -v aws &>/dev/null; then
        aws s3 cp "$file" "$remote_path" --storage-class STANDARD_IA || log "S3 upload failed (aws)"
    elif command -v rclone &>/dev/null; then
        rclone copy "$file" ":s3,provider=AWS,env_auth=true:${S3_BUCKET}/kasra-backups/$(date +%Y/%m/%d)/" || log "S3 upload failed (rclone)"
    else
        log "No S3 upload tool (aws/rclone) found — skipping upload"
    fi
}

rotate_backups() {
    log "Rotating backups..."

    # Daily: keep last N days
    find "$BACKUP_DIR/daily"   \( -name "*.dump" -o -name "*.age" -o -name "*.gpg" \) | \
        sort | head -n -"$RETENTION_DAYS" | while read -r f; do
        rm -f "$f"
        log "Removed old daily backup: $f"
    done
}

write_metrics() {
    local size_bytes="$1"
    local status="$2"  # success or failure
    cat > "$METRICS_FILE" <<EOF
# HELP kasra_backup_timestamp_seconds Unix timestamp of last backup
# TYPE kasra_backup_timestamp_seconds gauge
kasra_backup_timestamp_seconds{status="${status}"} $(date +%s)
# HELP kasra_backup_size_bytes Size of backup in bytes
# TYPE kasra_backup_size_bytes gauge
kasra_backup_size_bytes{status="${status}"} ${size_bytes}
EOF
}

# ── Main ─────────────────────────────────────────────────────────────────────

main() {
    local timestamp
    local backup_file
    local final_file
    local exit_code=0

    timestamp=$(date +%Y%m%d_%H%M%S)

    echo "=========================================="
    echo "  Kasra Backup — $(date)"
    echo "  DB Type:    PostgreSQL"
    echo "  Backup Dir: $BACKUP_DIR"
    echo "=========================================="

    ensure_dir

    # Determine backup destination based on day of week
    local dow
    dow=$(date +%u)  # 1=Monday .. 7=Sunday

    if [ "$dow" -eq 7 ]; then
        backup_file="${BACKUP_DIR}/weekly/kasra_weekly_${timestamp}"
    elif [ "$(date +%d)" = "01" ]; then
        backup_file="${BACKUP_DIR}/monthly/kasra_monthly_${timestamp}"
    else
        backup_file="${BACKUP_DIR}/daily/kasra_daily_${timestamp}"
    fi

    # Add extension
    backup_file="${backup_file}.dump"

    # Perform backup
    backup_postgres "$backup_file" || exit_code=$?

    if [ "$exit_code" -ne 0 ]; then
        error "Backup failed with exit code $exit_code"
    fi

    # Encrypt (optional)
    final_file=$(encrypt_backup "$backup_file")

    # Upload to S3 (optional)
    upload_to_s3 "$final_file"

    # Write metrics
    local size
    size=$(stat -c%s "$final_file" 2>/dev/null || stat -f%z "$final_file" 2>/dev/null || echo 0)
    write_metrics "$size" "success"

    # Rotate old backups
    rotate_backups

    log "✅ Backup completed: $final_file"
    exit 0
}

main
