"""Frontend static file server (SPA-compatible) with API proxy.

Serves the pre-built React frontend and proxies API calls (/v1/*, /health)
to the backend API service. This way the frontend JS (which uses relative
URLs) works without CORS or cross-origin issues.

Architecture:
  Browser → :8080 → Frontend Server
    ├── /assets/*           → static files (served directly)
    ├── /, /dashboard, ...  → index.html (SPA fallback)
    └── /v1/*, /health      → proxied to API service at :8090
"""
from __future__ import annotations

import logging
import os
from pathlib import Path

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles

logger = logging.getLogger("kasra.frontend")

API_TARGET = os.environ.get("KASRA_API_URL", "http://kasra-api:8090")

app = FastAPI(title="Kasra Frontend")

# Shared HTTP client for proxying
_client: httpx.AsyncClient | None = None


def _get_client() -> httpx.AsyncClient:
    global _client
    if _client is None:
        _client = httpx.AsyncClient(timeout=30.0)
    return _client


# ── API proxy: forward /v1/* and /health to API backend ─────────────────────

@app.api_route("/v1/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def proxy_v1(path: str, request: Request) -> Response:
    """Proxy API calls to the backend Kasra API service."""
    client = _get_client()
    target_url = f"{API_TARGET}/v1/{path}"

    # Forward query params
    if request.query_params:
        target_url += f"?{request.query_params}"

    # Forward headers (skip host, content-length, connection)
    headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in ("host", "content-length", "connection")
    }

    body = await request.body()

    try:
        resp = await client.request(
            method=request.method,
            url=target_url,
            headers=headers,
            content=body or None,
        )
        return Response(
            content=resp.content,
            status_code=resp.status_code,
            headers=dict(resp.headers),
        )
    except httpx.RequestError as e:
        logger.error("API proxy error: %s", e)
        return JSONResponse(
            status_code=502,
            content={"error": f"API backend unreachable: {e}"},
        )


@app.get("/health")
async def proxy_health(request: Request) -> Response:
    """Proxy health check to the backend."""
    client = _get_client()
    try:
        resp = await client.get(f"{API_TARGET}/health")
        return Response(content=resp.content, status_code=resp.status_code,
                        headers=dict(resp.headers))
    except httpx.RequestError as e:
        return JSONResponse(
            status_code=502,
            content={"status": "unhealthy", "detail": str(e)},
        )


# ── Frontend static files (SPA support) ─────────────────────────────────────

frontend_dist = Path(__file__).resolve().parent.parent / "frontend" / "dist"
if frontend_dist.exists():
    app.mount("/", StaticFiles(directory=str(frontend_dist), html=True), name="frontend")
    logger.info("Frontend static files served from %s", frontend_dist)
else:
    logger.warning("Frontend dist not found at %s", frontend_dist)

    @app.get("/")
    async def not_built():
        return {"status": "frontend not built", "dist": str(frontend_dist)}
