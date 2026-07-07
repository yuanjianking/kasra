"""Master API router — aggregates all route modules."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.health import router as health_router
from app.api.scan import router as scan_router
from app.api.audit import router as audit_router
from app.api.rules import router as rules_router
from app.api.dashboard import router as dashboard_router
from app.api.proxy import router as proxy_router

api_router = APIRouter()

# Include all sub-routers
api_router.include_router(health_router)
api_router.include_router(scan_router)
api_router.include_router(audit_router)
api_router.include_router(rules_router)
api_router.include_router(dashboard_router)
api_router.include_router(proxy_router)
