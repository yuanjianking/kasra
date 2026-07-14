"""Kasra Application — FastAPI entry point.

Creates the FastAPI application, initializes the SDK RuleEngine,
sets up middleware, and registers all API route handlers.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncGenerator

import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app import __version__
from app.config import settings
from app.database import init_db, get_db_type, check_db_health
from app.services.engine_service import engine_service
from app.metrics import (
    PrometheusMiddleware,
    metrics_endpoint,
    rules_loaded,
    rules_active,
    engine_health,
    db_health,
    audit_log_total,
    active_users_24h,
    detections_total,
)
from app.logging import configure_logging

logger = logging.getLogger("kasra")

# ── Periodic audit cleanup task ────────────────────────────────────────────
_cleanup_task: asyncio.Task | None = None


async def _cleanup_audit_logs() -> None:
    """Periodically delete audit logs older than retention_days."""
    while True:
        await asyncio.sleep(3600)  # Check every hour
        try:
            from app.database import SessionLocal
            from app.models.audit_log import AuditLog
            from datetime import datetime, timedelta, timezone
            db = SessionLocal()
            cutoff = datetime.now(timezone.utc) - timedelta(days=settings.audit_retention_days)
            deleted = db.query(AuditLog).filter(AuditLog.timestamp < cutoff).delete()
            if deleted:
                db.commit()
                logger.info("Cleaned up %d audit log entries older than %d days", deleted, settings.audit_retention_days)
            db.close()
        except Exception:
            logger.exception("Audit log cleanup failed")


# ── Application lifespan ───────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifecycle: startup and shutdown."""
    # ── Startup ──
    logger.info("Starting Kasra application (v%s)...", __version__)
    from app.config import validate_settings
    validate_settings(settings)

    # Schedule periodic audit log cleanup via asyncio (not threading)
    global _cleanup_task  # noqa: PLW0603
    _cleanup_task = asyncio.create_task(_cleanup_audit_logs())
    logger.info("Audit log cleanup scheduled every hour (retention: %d days)", settings.audit_retention_days)

    # 1. Initialize database
    logger.info("Initializing database...")
    init_db()
    logger.info("Database initialized.")

    # 1b. Run migrations (adds columns to existing tables + seeds master data)
    try:
        from app.db_migration import run_migrations
        run_migrations()
        logger.info("Migrations complete.")
    except Exception as exc:
        logger.warning("Migration step skipped: %s", exc)

    # 1c. Seed SDK rules from DML into the rules table (SQLite dev)
    try:
        from app.db_migration import seed_sdk_rules_from_dml
        seed_sdk_rules_from_dml()
    except Exception as exc:
        logger.warning("SDK rule seeding skipped: %s", exc)

    # 1d. Auto-seed sample data for development (skip in test mode)
    if os.environ.get("KASRA_APP_SEED_DATA", "true").lower() == "false":
        logger.debug("Seed data disabled via KASRA_APP_SEED_DATA=false")
    else:
        try:
            from app.database import SessionLocal
            from app.models.audit_log import AuditLog
            from app.models.user import User
            from app.models.user_behavior import UserBehavior
            from app.models.audit_chain import AuditChain
            from app.models.rule_config import Rule

            db = SessionLocal()
            if db.query(AuditLog).count() == 0:
                logger.info("Seeding development data...")

                # Users
                if not db.query(User).filter(User.username == "admin").first():
                    db.add(User(username="admin", role="admin", is_active=True))
                if not db.query(User).filter(User.username == "demo-user").first():
                    db.add(User(username="demo-user", role="user", is_active=True))

                # Sample audit logs
                from datetime import datetime, timedelta
                now = datetime.utcnow()
                sample_logs = [
                    AuditLog(timestamp=now-timedelta(hours=2),user_id="demo-user",session_id="sess_001",rule_id="I-05",rule_name="Generic Password/Secret",severity="P0",action="block",direction="input",matched_text="password=admin123",match_count=1,status="resolved"),
                    AuditLog(timestamp=now-timedelta(hours=1),user_id="demo-user",session_id="sess_002",rule_id="O-01",rule_name="Dangerous Function Call",severity="P0",action="warn",direction="output",matched_text="eval(request.body)",match_count=1,status="pending"),
                    AuditLog(timestamp=now-timedelta(minutes=30),user_id="demo-user",session_id="sess_003",rule_id="I-11",rule_name="Prompt Injection Attack",severity="P0",action="block",direction="input",matched_text="ignore all previous instructions",match_count=1,status="pending"),
                    AuditLog(timestamp=now-timedelta(minutes=15),user_id="admin",session_id="sess_004",rule_id="SEC-05",rule_name="SQL Injection",severity="P0",action="warn",direction="batch",matched_text='cursor.execute(f"SELECT * FROM users")',match_count=1,status="fp"),
                    AuditLog(timestamp=now-timedelta(minutes=5),user_id="demo-user",session_id="sess_001",rule_id="O-02",rule_name="Dangerous Shell Command",severity="P0",action="block",direction="output",matched_text='subprocess.call("rm -rf /", shell=True)',match_count=1,status="pending"),
                    AuditLog(timestamp=now,user_id="demo-user",session_id="sess_005",rule_id="I-06",rule_name="Generic Password/Secret",severity="P0",action="block",direction="input",matched_text="password=secret123",match_count=1,status="pending"),
                ]
                for log in sample_logs:
                    db.add(log)
                db.commit()
                logger.info("Development data seeded: users=%d, logs=%d", 2, len(sample_logs))
            db.close()
        except Exception as exc:
            logger.warning("Seed data skipped: %s", exc)

    # 2. Start TCP CONNECT proxy (optional — opt-in via config)
    connect_proxy = None
    if settings.https_proxy_enabled:
        from app.proxy.tcp_proxy import ConnectProxy

        _allowed = ["api.anthropic.com", "api.openai.com", "api.deepseek.com"]
        try:
            connect_proxy = ConnectProxy(
                host=settings.https_proxy_host,
                port=settings.https_proxy_port,
                allowed_upstreams=_allowed,
            )
            await connect_proxy.start()
        except OSError:
            logger.warning(
                "CONNECT proxy port %d already in use "
                "(another worker likely bound it — continuing)",
                settings.https_proxy_port,
            )
            connect_proxy = None

    # 3. Initialize SDK RuleEngine + load rules from DB
    logger.info("Initializing Kasra SDK RuleEngine...")
    engine_service.initialize()
    logger.info("RuleEngine created, loading rules from database...")

    try:
        from app.database import SessionLocal
        load_db = SessionLocal()
        count = engine_service.reload_rules_from_db(load_db)
        load_db.close()
        logger.info("RuleEngine loaded %d rules from database.", count)
    except Exception:
        logger.exception("Failed to load rules from DB into engine")

    # 3c. Sync Prometheus metrics (no longer uses sync_disabled_rules_from_db — it's
    #     handled inside reload_rules_from_db)

    # Initialize Prometheus metrics
    if engine_service.is_initialized:
        engine = engine_service.engine
        rules_loaded.set(engine.rule_count)
        rules_active.set(len([r for r in engine.get_rules() if r.enabled]))
        engine_health.set(1)
    else:
        engine_health.set(0)

    # Database health
    db_status = check_db_health()
    db_health.set(1 if db_status.get("status") == "healthy" else 0)

    yield

    # ── Shutdown ──
    logger.info("Shutting down Kasra application...")
    if _cleanup_task:
        _cleanup_task.cancel()
    if connect_proxy:
        await connect_proxy.stop()
    engine_service.shutdown()
    logger.info("Shutdown complete.")


# ── Rate limiter ───────────────────────────────────────────────────────────

class RateLimiter:
    """Simple in-memory rate limiter (sliding window).

    NOTE: In multi-worker deployments, each worker has its own limiter.
    For strict rate limiting across replicas, use a Redis-backed limiter.
    """
    def __init__(self, requests_per_minute: int = 60):
        self.rpm = requests_per_minute
        self._windows: dict[str, list[float]] = defaultdict(list)

    def check(self, key: str) -> tuple[bool, int]:
        now = time.monotonic()
        window = now - 60.0
        self._windows[key] = [t for t in self._windows[key] if t > window]
        count = len(self._windows[key])
        if count >= self.rpm:
            return False, self.rpm
        self._windows[key].append(now)
        return True, self.rpm - count - 1


rate_limiter = RateLimiter(requests_per_minute=settings.rate_limit_rpm)


# ── App factory ────────────────────────────────────────────────────────────

def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="Kasra API",
        description="AI Development Security Governance Platform",
        version=__version__,
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
        # Ensure unique operation IDs in case of routing edge cases
        generate_unique_id_function=lambda route: f"{route.name}_{route.path.replace('/', '_')}",
    )

    # ── Middleware ──
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Prometheus Metrics Middleware ──
    app.add_middleware(PrometheusMiddleware)

    # ── Security Middleware (body size limit + API key auth) ──
    MAX_BODY_SIZE = 10 * 1024 * 1024  # 10 MB

    @app.middleware("http")
    async def security_middleware(request: Request, call_next):
        # 1. Body size limit (prevent OOM attacks)
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > MAX_BODY_SIZE:
            return JSONResponse(status_code=413, content={"error": f"Request body too large. Max: {MAX_BODY_SIZE} bytes"})

        # 2. Rate limiting (skip for MCP/static paths)
        if not request.url.path.startswith(("/v1/mcp",)):
            client_ip = request.client.host if request.client else "unknown"
            allowed, remaining = rate_limiter.check(client_ip)
            if not allowed:
                return JSONResponse(
                    status_code=429,
                    content={"error": "Rate limit exceeded. Try again later."},
                    headers={"Retry-After": "60"},
                )

        # 3. API key auth (skip for public endpoints + frontend static files)
        public_paths = ("/health", "/redoc", "/docs", "/openapi.json", "/", "/favicon.svg")
        if (request.url.path not in public_paths
            and not request.url.path.startswith(("/v1/mcp",))
            and not request.url.path.startswith(("/assets/",))):
            api_key = request.headers.get("X-API-Key")
            if not api_key or api_key != settings.api_key:
                return JSONResponse(
                    status_code=401,
                    content={"error": "Missing or invalid API key. Provide X-API-Key header."},
                )

        return await call_next(request)

    # ── Prometheus Metrics endpoint (no auth required) ──
    from starlette.requests import Request as StarletteRequest

    @app.get("/metrics", include_in_schema=False)
    async def metrics(request: StarletteRequest):
        return metrics_endpoint(request)

    # ── Register Routers ──
    from app.api.router import api_router
    app.include_router(api_router)

    # ── MCP Server (SSE transport) — skip when running standalone MCP ──
    if not os.environ.get("KASRA_SKIP_MCP"):
        try:
            from app.mcp_server import kasra_server
            mcp_sse_app = kasra_server.sse_app()
            app.mount("/v1/mcp", mcp_sse_app)
            logger.info("MCP SSE endpoint mounted at /v1/mcp/sse")
        except Exception as exc:
            logger.warning("MCP SSE mount skipped: %s", exc)

    # ── Serve Frontend Static Files — skip when running standalone frontend ──
    if not os.environ.get("KASRA_SKIP_FRONTEND"):
        frontend_dist = Path(__file__).resolve().parent.parent / "frontend" / "dist"
        if frontend_dist.exists():
            from fastapi.staticfiles import StaticFiles
            app.mount("/", StaticFiles(directory=str(frontend_dist), html=True), name="frontend")
            logger.info("Frontend static files mounted from %s", frontend_dist)
        else:
            logger.info("Frontend dist not found at %s — skipping", frontend_dist)

    return app


app = create_app()


# ── Direct execution ──
if __name__ == "__main__":
    configure_logging(settings.log_level)
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        workers=1,
        log_level=settings.log_level,
    )
