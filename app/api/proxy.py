"""Proxy API endpoint — HTTP proxy for AI tool traffic.

Usage:
    # Direct proxy to Anthropic API
    curl -X POST http://localhost:8080/v1/proxy/api.anthropic.com/v1/messages \\
        -H "x-api-key: sk-..." \\
        -H "anthropic-version: 2023-06-01" \\
        -H "content-type: application/json" \\
        -d '{"model":"claude-sonnet-4-20250514","messages":[{"role":"user","content":"Hello"}]}'
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

from app.proxy.http_proxy import proxy_request

logger = logging.getLogger("kasra.api.proxy")
router = APIRouter(prefix="/v1/proxy", tags=["Proxy"])


@router.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
async def proxy_handler(path: str, request: Request):
    """Proxy endpoint — forwards requests to upstream AI APIs with security scanning.

    The path format is ``{upstream_host}/{upstream_path}``.
    Example: ``api.anthropic.com/v1/messages`` proxies to ``https://api.anthropic.com/v1/messages``.

    Runs input detection on request content and output detection on responses.
    """
    body = await request.body()

    # Forward headers, preserving incoming auth headers
    headers = dict(request.headers.items())

    result = await proxy_request(
        method=request.method,
        path=path,
        headers=headers,
        body=body,
    )

    # Include detection metadata as a response header
    detection = result.get("detection")
    response_headers = dict(result.get("headers", {}))

    # Don't pass through transfer-encoding since we're re-serializing
    response_headers.pop("transfer-encoding", None)
    response_headers.pop("Transfer-Encoding", None)

    response = Response(
        content=result.get("body"),
        status_code=result.get("status_code", 502),
        headers=response_headers,
    )

    # Attach detection info as header if present
    if detection:
        import json as _json
        response.headers["X-Kasra-Detection"] = _json.dumps(detection)

    return response
