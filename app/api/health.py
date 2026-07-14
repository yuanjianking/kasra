"""Health check endpoint — includes database, engine, and proxy status."""

from __future__ import annotations

from fastapi import APIRouter

from app import __version__
from app.database import check_db_health, get_db_type
from app.config import settings
from app.services.engine_service import engine_service

router = APIRouter(tags=["Health"])


@router.get("/health")
def health_check():
    """Health check — returns engine status, version, database info, and proxy status."""
    # 1. Engine status
    engine_ok = engine_service.is_initialized
    engine_info = {}
    if engine_ok:
        engine = engine_service.engine
        cr_rule_ids = set()
        try:
            cr_rule_ids = engine.disabled_code_review_rule_ids
            cr_rule_ids |= {r.get("id") for r in engine.get_code_review_rules() if r.get("id")}
        except Exception:
            pass
        cr_count = len(cr_rule_ids) if cr_rule_ids else 0
        if cr_count == 0:
            # fallback: try to count from scanner
            try:
                scanner = engine._get_code_review_scanner()
                cr_count = len(scanner.rules) + len(scanner._custom_rules)
            except Exception:
                pass
        engine_info = {
            "rules_loaded": engine.rule_count,
            "cr_rules_loaded": cr_count,
            "rules_total": engine.rule_count + cr_count,
            "audit_enabled": engine.config.audit.enabled,
        }

    # 2. Database status
    db_health = check_db_health()

    # 3. HTTPS CONNECT proxy status
    https_proxy = {
        "enabled": settings.https_proxy_enabled,
        "port": settings.https_proxy_port if settings.https_proxy_enabled else None,
    }

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
        "https_proxy": https_proxy,
        **engine_info,
    }
