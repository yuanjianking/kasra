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
    from starlette.staticfiles import StaticFiles as StarletteStaticFiles

    # Serve assets (JS, CSS, images) directly — no fallback.
    app.mount(
        "/assets",
        StarletteStaticFiles(directory=str(frontend_dist / "assets")),
        name="assets",
    )

    # Catch-all SPA fallback: any unmatched GET route → index.html
    import html as html_mod

    index_html_path = frontend_dist / "index.html"
    index_content: str | None = None
    if index_html_path.exists():
        index_content = index_html_path.read_text(encoding="utf-8")
        logger.info("Frontend SPA fallback loaded from %s", index_html_path)

    @app.get("/{full_path:path}", include_in_schema=False)
    async def spa_fallback(full_path: str):
        # Let the API proxy handle /v1/* and /health
        if full_path.startswith("v1/") or full_path == "health":
            return JSONResponse(status_code=404, content={"detail": "Not found"})
        if index_content is not None:
            return Response(content=index_content, media_type="text/html")
        return JSONResponse(status_code=404, content={"detail": "Frontend not built"})
else:
    logger.warning("Frontend dist not found at %s", frontend_dist)

    @app.get("/")
    async def not_built():
        return {"status": "frontend not built", "dist": str(frontend_dist)}
