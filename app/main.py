"""Kasra Application — FastAPI entry point.

Creates the FastAPI application, initializes the SDK RuleEngine,
sets up middleware, and registers all API route handlers.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncGenerator

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from app.config import settings
from app.database import init_db, get_db_type
from app.services.engine_service import engine_service

logger = logging.getLogger("kasra")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifecycle: startup and shutdown."""
    # ── Startup ──
    logger.info("Starting Kasra application...")

    # 1. Initialize database
    logger.info("Initializing database...")
    init_db()
    logger.info("Database initialized.")

    # 1b. Auto-seed sample data for development (SQLite only)
    if get_db_type(settings.database_url) == "sqlite":
        try:
            from app.database import SessionLocal
            from app.models.audit_log import AuditLog
            from app.models.user import User
            from app.models.rule_config import RuleConfig
            db = SessionLocal()
            if db.query(AuditLog).count() == 0:
                logger.info("Seeding development data...")

                # Users
                if not db.query(User).filter(User.username == "admin").first():
                    db.add(User(username="admin", role="admin", is_active=True))
                if not db.query(User).filter(User.username == "demo-user").first():
                    db.add(User(username="demo-user", role="user", is_active=True))

                # SDK rules snapshot
                sdk_rules = [
                    ("I-01","GitHub Token","credential_leak","P0","block"),
                    ("I-02","OpenAI API Key","credential_leak","P0","block"),
                    ("I-03","Anthropic API Key","credential_leak","P0","block"),
                    ("I-04","AWS Access Key","credential_leak","P0","block"),
                    ("I-05","Generic Password/Secret","credential_leak","P0","block"),
                    ("I-06","Private Key/PEM Certificate","credential_leak","P0","block"),
                    ("I-08","China Phone Number","pii","P1","redact"),
                    ("I-09","China National ID","pii","P1","redact"),
                    ("I-10","Email Address","pii","P1","redact"),
                    ("I-11","Prompt Injection Attack","injection","P0","block"),
                    ("I-12","Jailbreak/Role-Play Attack","injection","P0","block"),
                    ("O-01","Dangerous Function Call","code_security","P0","warn"),
                    ("O-02","Dangerous Shell Command","code_security","P0","block"),
                    ("SEC-05","SQL Injection","injection","P0","warn"),
                    ("SEC-12","XSS Risk","injection","P0","warn"),
                    ("IAC-01","Dockerfile Security","iac","P1","warn"),
                    ("IAC-02","K8s Security Config","iac","P1","warn"),
                    ("B-01","Late Night Anomaly","behavior","P1","warn"),
                    ("C-01","PII Compliance","compliance","P1","warn"),
                ]
                for rid, nm, cat, sev, act in sdk_rules:
                    if not db.query(RuleConfig).filter(RuleConfig.id == rid).first():
                        db.add(RuleConfig(id=rid, name=nm, category=cat, severity=sev, action=act, enabled=True, is_custom=False, source="sdk"))

                # Sample audit logs (6 entries)
                from datetime import datetime, timedelta
                now = datetime.utcnow()
                sample_logs = [
                    AuditLog(timestamp=now-timedelta(hours=2),user_id="demo-user",session_id="sess_001",rule_id="I-05",rule_name="Generic Password/Secret",severity="P0",action="block",direction="input",matched_text="password=admin123",match_count=1,status="resolved"),
                    AuditLog(timestamp=now-timedelta(hours=1),user_id="demo-user",session_id="sess_002",rule_id="O-01",rule_name="Dangerous Function Call",severity="P0",action="warn",direction="output",matched_text="eval(request.body)",match_count=1,status="pending"),
                    AuditLog(timestamp=now-timedelta(minutes=30),user_id="demo-user",session_id="sess_003",rule_id="I-11",rule_name="Prompt Injection Attack",severity="P0",action="block",direction="input",matched_text="ignore all previous instructions",match_count=1,status="pending"),
                    AuditLog(timestamp=now-timedelta(minutes=15),user_id="admin",session_id="sess_004",rule_id="SEC-05",rule_name="SQL Injection",severity="P0",action="warn",direction="batch",matched_text='cursor.execute(f"SELECT * FROM users")',match_count=1,status="fp"),
                    AuditLog(timestamp=now-timedelta(minutes=5),user_id="demo-user",session_id="sess_001",rule_id="B-01",rule_name="Late Night Anomaly",severity="P1",action="warn",direction="behavior",match_count=0,status="pending"),
                    AuditLog(timestamp=now,user_id="demo-user",session_id="sess_005",rule_id="O-02",rule_name="Dangerous Shell Command",severity="P0",action="block",direction="output",matched_text='subprocess.call("rm -rf /", shell=True)',match_count=1,status="pending"),
                ]
                for log in sample_logs:
                    db.add(log)
                db.commit()
                logger.info("Development data seeded: users=%d, rules=%d, logs=%d", 2, len(sdk_rules), len(sample_logs))
            db.close()
        except Exception as exc:
            logger.warning("Seed data skipped: %s", exc)

    # 2. Initialize SDK RuleEngine
    logger.info("Initializing Kasra SDK RuleEngine...")
    engine_service.initialize()
    logger.info(
        "RuleEngine initialized with %d rules.",
        engine_service.engine.rule_count,
    )

    yield

    # ── Shutdown ──
    logger.info("Shutting down Kasra application...")
    engine_service.shutdown()
    logger.info("Shutdown complete.")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="Kasra API",
        description="AI Development Security Governance Platform",
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # ── Middleware ──
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── API Key Authentication Middleware (optional for now) ──
    # @app.middleware("http")
    # async def api_key_middleware(request, call_next):
    #     ...

    # ── Register Routers ──
    from app.api.router import api_router
    app.include_router(api_router)

    # ── MCP Server (SSE transport) ──
    # Accessible at: http://localhost:8080/v1/mcp/sse
    try:
        from app.mcp_server import kasra_server
        mcp_sse_app = kasra_server.sse_app()
        app.mount("/v1/mcp", mcp_sse_app)
        logger.info("MCP SSE endpoint mounted at /v1/mcp/sse")
    except Exception as exc:
        logger.warning("MCP SSE mount skipped: %s", exc)

    # ── Serve Frontend Static Files (production) ──
    frontend_dist = Path(__file__).resolve().parent.parent / "frontend" / "dist"
    if frontend_dist.exists():
        from fastapi.staticfiles import StaticFiles
        app.mount("/", StaticFiles(directory=str(frontend_dist), html=True), name="frontend")
        logger.info("Frontend static files mounted from %s", frontend_dist)

    return app


app = create_app()


# ── Direct execution (uvicorn) ──
if __name__ == "__main__":
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        workers=1,  # workers=1 for dev; >1 in production
        log_level=settings.log_level,
    )
