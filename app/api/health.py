"""Health check endpoint — includes database status."""

from __future__ import annotations

from fastapi import APIRouter

from app import __version__
from app.database import check_db_health, get_db_type
from app.config import settings
from app.services.engine_service import engine_service

router = APIRouter(tags=["Health"])


@router.get("/health")
def health_check():
    """Health check — returns engine status, version, and database info."""
    # 1. Engine status
    engine_ok = engine_service.is_initialized
    engine_info = {}
    if engine_ok:
        engine = engine_service.engine
        engine_info = {
            "rules_loaded": engine.rule_count,
            "audit_enabled": engine.config.audit.enabled,
        }

    # 2. Database status
    db_health = check_db_health()

    overall = "healthy" if (engine_ok and db_health["status"] == "healthy") else "unhealthy"
    if not engine_ok:
        overall = "unhealthy"

    return {
        "status": overall,
        "version": __version__,
        "database": {
            "status": db_health["status"],
            "type": get_db_type(settings.database_url),
            "version": db_health.get("version"),
            "error": db_health.get("error"),
        },
        **engine_info,
    }
