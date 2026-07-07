# Kasra Production Deployment

## Prerequisites

- Python 3.11+
- Node.js 20+ (for building frontend)
- Nginx (recommended reverse proxy)
- systemd (for service management)

## Quick Start

```bash
# 1. Clone and install
git clone <repo> /opt/kasra
cd /opt/kasra

# 2. Create Python virtualenv
python3 -m venv .venv
source .venv/bin/activate

# 3. Install SDK + App
pip install -e kasra-sdk
pip install -e kasra

# 4. Build frontend
cd frontend && npm install && npm run build && cd ..

# 5. Create data directory
mkdir -p data

# 6. Set production secrets
export KASRA_APP_API_KEY=$(openssl rand -hex 32)
export KASRA_APP_JWT_SECRET=$(openssl rand -hex 32)
export KASRA_APP_ALLOWED_ORIGINS='["https://kasra.example.com"]'
export KASRA_APP_RATE_LIMIT_RPM=120

# 7. Start service
uvicorn app.main:app --host 127.0.0.1 --port 8080 --workers 4
```

## Production Deployment (systemd + nginx)

```bash
# Copy service files
cp deploy/kasra.service /etc/systemd/system/
cp deploy/nginx.conf /etc/nginx/sites-available/kasra
ln -s /etc/nginx/sites-available/kasra /etc/nginx/sites-enabled/

# Enable and start
systemctl daemon-reload
systemctl enable kasra
systemctl start kasra
systemctl reload nginx

# Check status
systemctl status kasra
journalctl -u kasra -f
```

## Configuration

All settings via environment variables with prefix `KASRA_APP_`:

| Variable | Default | Description |
|----------|---------|-------------|
| `KASRA_APP_API_KEY` | `dev-api-key-change-in-production` | API authentication key |
| `KASRA_APP_JWT_SECRET` | `change-this-to-a-random-secret` | JWT signing secret |
| `KASRA_APP_DATABASE_URL` | `sqlite:///./data/kasra.db` | Database connection string |
| `KASRA_APP_HOST` | `0.0.0.0` | Bind address |
| `KASRA_APP_PORT` | `8080` | HTTP port |
| `KASRA_APP_LOG_LEVEL` | `info` | Log level |
| `KASRA_APP_RATE_LIMIT_RPM` | `120` | Rate limit per IP |
| `KASRA_APP_ALLOWED_ORIGINS` | `["*"]` | CORS allowed origins |
| `KASRA_APP_AUDIT_RETENTION_DAYS` | `90` | Audit log retention |

## Database

Development: SQLite (zero config).
Production: PostgreSQL for multi-worker deployments.

```bash
export KASRA_APP_DATABASE_URL=postgresql://kasra:password@localhost:5432/kasra
```

## Monitoring

- Health check: `GET /health`
- Metrics (Prometheus): expose via additional middleware
- Logs: `journalctl -u kasra -f`
- Audit logs: `/opt/kasra/data/kasra-audit.jsonl`

## Backup

```bash
# SQLite
cp /opt/kasra/data/kasra.db /backup/$(date +%Y%m%d)-kasra.db

# PostgreSQL
pg_dump -U kasra kasra > /backup/$(date +%Y%m%d)-kasra.sql
```
