# Kasra Enterprise Production Deployment Guide

## 📋 Prerequisites

| Requirement | Version | Purpose |
|-------------|---------|---------|
| Python | 3.11+ | Application runtime |
| PostgreSQL | 16+ | Production database (recommended) |
| Nginx | 1.25+ | Reverse proxy with SSL termination |
| Docker | 24+ | Container deployment |
| Docker Compose | 2.20+ | Multi-service orchestration |
| Node.js | 20+ | Frontend build (production only) |
| OpenSSL | 3.0+ | Key generation |

## 🚀 Quick Start (Docker Compose — Recommended)

```bash
# 1. Generate production secrets
export POSTGRES_PASSWORD=$(openssl rand -base64 32)
export KASRA_API_KEY=$(openssl rand -hex 64)
export KASRA_JWT_SECRET=$(openssl rand -hex 64)

# 2. Start production stack (PostgreSQL + Kasra)
docker compose --profile production up -d

# 3. Verify
curl -f http://localhost:8080/health
curl -f http://localhost:8080/v1/rules \
    -H "X-API-Key: $KASRA_API_KEY"

# 4. (Optional) Start monitoring stack
docker compose --profile monitoring up -d

# View logs
docker compose logs -f
```

## 🏗️ Production Deployment (systemd + nginx)

```bash
# 1. Install application
cd /opt/kasra
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[postgres]"

# 2. Build frontend
cd frontend && npm ci && npm run build && cd ..

# 3. Configure environment
cp .env.production /etc/kasra/kasra.env
chmod 600 /etc/kasra/kasra.env
# Edit /etc/kasra/kasra.env with your production secrets

# 4. Create data directories
mkdir -p /data/kasra
chown -R kasra:kasra /data/kasra

# 5. Setup systemd service
cp deploy/systemd/kasra.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable kasra
systemctl start kasra
systemctl status kasra

# 6. Setup nginx reverse proxy
cp deploy/nginx/kasra.conf /etc/nginx/sites-available/kasra
ln -sf /etc/nginx/sites-available/kasra /etc/nginx/sites-enabled/
# Edit server_name, SSL cert paths in the config
systemctl reload nginx

# 7. Setup log rotation
cp deploy/logrotate.conf /etc/logrotate.d/kasra

# 8. Setup fail2ban (optional)
cp deploy/fail2ban/filter-kasra-auth.conf /etc/fail2ban/filter.d/
cp deploy/fail2ban/jail.local /etc/fail2ban/jail.d/kasra.conf
systemctl restart fail2ban

# 9. Verify
curl -f http://localhost:8080/health
journalctl -u kasra -f
```

## 🔧 Configuration Reference

### Environment Variables (`KASRA_APP_*` prefix)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `KASRA_APP_API_KEY` | **Yes** | — | API authentication key (generate: `openssl rand -hex 64`) |
| `KASRA_APP_JWT_SECRET` | **Yes** | — | JWT signing secret (generate: `openssl rand -hex 64`) |
| `KASRA_APP_DATABASE_URL` | **Yes** | `sqlite:///./data/kasra.db` | Database connection string |
| `KASRA_APP_HOST` | No | `0.0.0.0` | Bind address |
| `KASRA_APP_PORT` | No | `8080` | HTTP port |
| `KASRA_APP_WORKERS` | No | `4` | Number of uvicorn workers |
| `KASRA_APP_LOG_LEVEL` | No | `info` | Log level (debug/info/warning/error) |
| `KASRA_APP_RATE_LIMIT_RPM` | No | `120` | Rate limit per IP per minute |
| `KASRA_APP_ALLOWED_ORIGINS` | No | `["*"]` | CORS allowed origins |
| `KASRA_APP_AUDIT_RETENTION_DAYS` | No | `90` | Audit log retention in days |
| `KASRA_APP_HTTPS_PROXY_ENABLED` | No | `false` | Enable HTTPS CONNECT proxy |
| `KASRA_APP_HTTPS_PROXY_PORT` | No | `8443` | HTTPS proxy port |

### PostgreSQL Database (Production)

```bash
export KASRA_APP_DATABASE_URL="postgresql+psycopg2://kasra:password@localhost:5432/kasra"
```

Connections are managed by SQLAlchemy's QueuePool:
- Pool size: 10 (configurable via `KASRA_DB_POOL_SIZE`)
- Max overflow: 20
- Connection recycle: 3600s

### Nginx Configuration

The nginx config at `deploy/nginx/kasra.conf` supports:
- SSL/TLS termination (TLSv1.2+ only, modern ciphers)
- HTTP/2
- Rate limiting per endpoint type
- Security headers (HSTS, CSP, X-Frame-Options, etc.)
- WebSocket/SSE proxying for MCP endpoint
- Request body size limiting (12MB)

## 📊 Monitoring Stack

Start with: `docker compose --profile monitoring up -d`

| Service | Port | Purpose |
|---------|------|---------|
| Prometheus | 9090 | Metrics collection (30-day retention) |
| Grafana | 3000 | Visualization dashboards |
| PostgreSQL Exporter | 9187 | Database metrics |
| Node Exporter | 9100 | Host-level metrics |

### Grafana Dashboards

- **Kasra Main Dashboard** (`kasra-main.json`): Service health, detection rates, request latency, active rules

### Prometheus Alert Rules

Pre-configured alerts in `deploy/prometheus/alerts.yml`:
- `KasraDown` — Service unreachable for >1m
- `KasraEngineUnhealthy` — Detection engine failure
- `KasraDatabaseDown` — Database connectivity loss
- `HighDetectionRate` — >100 detections/s
- `HighBlockRate` — >50 blocked requests/s
- `LowActiveRules` — <50 active rules
- `SlowDetection` — P95 >1000ms
- `SlowRequests` — P95 >5000ms

## 🔬 Database Migrations

```bash
# Run all pending migrations
alembic upgrade head

# Check pending migrations
alembic check

# Auto-generate a migration from model changes
alembic revision --autogenerate -m "add column xyz"

# Rollback one migration
alembic downgrade -1
```

## 💾 Backup

### Automatic (via cron in Docker)
The `pg-backup` service runs daily at 2 AM.

### Manual

```bash
# SQLite
bash deploy/scripts/backup.sh

# PostgreSQL
PGPASSWORD=xxx pg_dump -Fc -U kasra -h localhost kasra > backup.dump
```

### Restore

```bash
sudo bash deploy/scripts/restore.sh /var/backups/kasra/daily/kasra_daily_*.sqlite
```

## 🔒 Security Hardening

| Feature | Description |
|---------|-------------|
| **Non-root user** | Container and systemd run as `kasra` user |
| **Read-only filesystem** | Container rootfs is read-only (`read_only: true`) |
| **No new privileges** | `no-new-privileges:true` security option |
| **Capability dropping** | All capabilities dropped except `NET_BIND_SERVICE` |
| **systemd sandboxing** | `ProtectSystem=full`, `ProtectHome=true`, `PrivateTmp=true` |
| **CSP headers** | Content-Security-Policy via nginx |
| **HSTS** | Strict-Transport-Security via nginx |
| **Rate limiting** | Nginx + application-level rate limiting |
| **Fail2Ban** | Ban IPs after auth failures or rate limit abuse |
| **Request size limit** | 12MB max body size |
| **API key auth** | All endpoints protected except `/health` |
| **Alembic migrations** | Controlled schema changes with audit trail |

## 🐳 Makefile Reference

```bash
make install       # Install dependencies
make dev           # Install with dev dependencies
make test          # Run tests with coverage
make lint          # Run ruff linter
make docker        # Build production Docker image
make up            # Start development stack
make up-prod       # Start production stack
make backup        # Backup database
make restore       # Restore database from backup
make security      # Run security scanning (safety + bandit + ruff)
make clean         # Remove build artifacts
```

## 📁 Directory Structure

```
/opt/kasra/
├── app/                    # Application source
├── alembic/                # Database migrations
├── config/                 # Application configuration
├── data/                   # Runtime data (SQLite, audit logs)
├── db/                     # Database initialization scripts
├── deploy/                 # Enterprise deployment configs
│   ├── nginx/              # Nginx configuration
│   ├── systemd/            # Systemd service unit
│   ├── scripts/            # Backup, restore, healthcheck
│   ├── prometheus/         # Prometheus config + alerts
│   ├── grafana/            # Grafana dashboards + datasources
│   ├── fail2ban/           # Fail2Ban filters
│   └── README.md           # This guide
├── frontend/               # React frontend
├── tests/                  # Test suite
├── docker-compose.yml      # Docker Compose orchestration
├── Dockerfile              # Multi-stage Docker build
├── Makefile                # Build automation
├── pyproject.toml          # Python project configuration
└── .env.production         # Production environment template
```

## 🩺 Health Check

```bash
# Basic health (no auth required)
curl http://localhost:8080/health

# Expected response:
{
  "status": "healthy",
  "version": "0.1.0",
  "database": {"status": "healthy", "db_type": "postgres"},
  "engine": "initialized",
  "uptime_seconds": 3600,
  "active_users_24h": 5
}

# Authenticated API check
curl -H "X-API-Key: $KASRA_API_KEY" http://localhost:8080/v1/rules
```
