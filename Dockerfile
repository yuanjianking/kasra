# =============================================================================
# Kasra — Enterprise Multi-Stage Docker Build
# =============================================================================
# Stages:
#   1. sdk-builder     — Build kasra-sdk wheel (from local source)
#   2. app-builder     — Build app wheel + install Python deps
#   3. frontend-builder — Build React frontend static files
#   4. production      — Minimal runtime image (non-root, read-only rootfs)
# =============================================================================

# ═══════════════════════════════════════════════════════════════════════════════
# Stage 1: SDK Builder — Build kasra-sdk from local source
# ═══════════════════════════════════════════════════════════════════════════════
FROM python:3.11-slim AS sdk-builder

ARG PIP_INDEX_URL=https://mirrors.aliyun.com/pypi/simple/

RUN pip install --no-cache-dir --timeout=120 --retries=5 -i "$PIP_INDEX_URL" --upgrade pip wheel setuptools

WORKDIR /build

# Copy SDK source from local repo (no GitHub needed)
COPY kasra-sdk/ ./kasra-sdk/

# Build SDK wheel
RUN pip wheel --no-cache-dir --timeout=120 --retries=5 -i "$PIP_INDEX_URL" --wheel-dir /build/wheels ./kasra-sdk


# ═══════════════════════════════════════════════════════════════════════════════
# Stage 2: App Builder — Build the Kasra application wheel + deps
# ═══════════════════════════════════════════════════════════════════════════════
FROM python:3.11-slim AS app-builder

RUN apt-get update && apt-get install -y --no-install-recommends gcc && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build

ARG PIP_INDEX_URL=https://mirrors.aliyun.com/pypi/simple/

RUN pip install --no-cache-dir --timeout=120 --retries=5 -i "$PIP_INDEX_URL" --upgrade pip wheel setuptools hatchling

# Copy SDK wheel from builder
COPY --from=sdk-builder /build/wheels /build/sdk-wheels

# Copy app source (prefixed with kasra/ since build context is parent dir)
COPY kasra/pyproject.toml kasra/README.md ./
COPY kasra/app/ ./app/

# Install SDK from prebuilt wheel, then the app without git dependency
RUN pip install --no-cache-dir --no-index --find-links /build/sdk-wheels kasra-sdk && \
    sed -i '/kasra-sdk/d' pyproject.toml && \
    pip install --no-cache-dir --timeout=120 --retries=5 -i "$PIP_INDEX_URL" -e ".[postgres,prod]"


# ═══════════════════════════════════════════════════════════════════════════════
# Stage 3: Frontend Builder — Build React static files
# ═══════════════════════════════════════════════════════════════════════════════
FROM node:20-alpine AS frontend-builder

WORKDIR /build/frontend

COPY kasra/frontend/package.json kasra/frontend/package-lock.json ./
RUN npm ci --quiet

COPY kasra/frontend/ ./
RUN npm run build


# ═══════════════════════════════════════════════════════════════════════════════
# Stage 4: Production — Minimal runtime image
# ═══════════════════════════════════════════════════════════════════════════════
FROM python:3.11-slim AS production

LABEL org.opencontainers.image.title="Kasra"
LABEL org.opencontainers.image.description="AI Development Security Governance Platform"
LABEL org.opencontainers.image.version="0.1.0"
LABEL org.opencontainers.image.vendor="Kasra AI Security"
LABEL org.opencontainers.image.licenses="Proprietary"
LABEL org.opencontainers.image.url="https://kasra.security"

# ── Security hardening: non-root user ────────────────────────────────────────
RUN groupadd -r -g 1001 kasra && \
    useradd -r -u 1001 -g kasra -d /app -s /sbin/nologin kasra && \
    mkdir -p /app /data /config && \
    chown -R kasra:kasra /app /data /config

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy installed Python packages from app-builder
COPY --from=app-builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=app-builder /usr/local/bin/uvicorn /usr/local/bin/
COPY --from=app-builder /build/app /app/app
COPY --from=app-builder /build/pyproject.toml /app/

# Copy frontend static files
COPY --from=frontend-builder /build/frontend/dist /app/frontend/dist

# Copy DDL/DML SQL files (rule seed data)
COPY kasra/db/ /app/db/

# Copy deploy scripts
COPY kasra/deploy/scripts/ /scripts/

WORKDIR /app

VOLUME ["/data", "/config"]

ENV KASRA_APP_HOST=0.0.0.0 \
    KASRA_APP_PORT=8090 \
    KASRA_APP_LOG_LEVEL=info \
    KASRA_APP_HTTPS_PROXY_ENABLED=true \
    KASRA_APP_HTTPS_PROXY_HOST=0.0.0.0 \
    KASRA_APP_HTTPS_PROXY_PORT=8443 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 8090 8443

USER kasra:kasra

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD /scripts/healthcheck.sh

ENTRYPOINT ["python", "-m", "app"]
