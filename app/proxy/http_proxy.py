"""HTTP proxy for transparent AI tool traffic interception.

Intercepts requests to AI API providers (Anthropic, OpenAI, etc.),
runs input/output detection, and conditionally forwards or blocks.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx

from app.services.engine_service import engine_service
from app.services.scan_service import _log_to_db
from app.database import SessionLocal

# Shared connection pool — reuse across all proxy requests
_shared_client: httpx.AsyncClient | None = None


def _get_client() -> httpx.AsyncClient:
    global _shared_client
    if _shared_client is None:
        _shared_client = httpx.AsyncClient(
            timeout=120.0,
            follow_redirects=True,
            limits=httpx.Limits(
                max_connections=50,
                max_keepalive_connections=20,
                keepalive_expiry=60.0,
            ),
        )
    return _shared_client


logger = logging.getLogger("kasra.proxy")

# Upstream AI API hosts we can proxy to
ALLOWED_UPSTREAMS = [
    "api.anthropic.com",
    "api.openai.com",
    "api.deepseek.com",
]

# Headers to NOT forward (security-sensitive)
STRIPPED_REQUEST_HEADERS = {
    "host", "authorization", "x-api-key",
    "cookie", "set-cookie", "transfer-encoding",
}


async def proxy_request(
    method: str,
    path: str,
    headers: dict[str, str],
    body: bytes | None,
) -> dict[str, Any]:
    """Proxy an HTTP request to the upstream AI API.

    Steps:
      1. Parse the request body to extract messages content.
      2. Run input detection on the content.
      3. If blocked, return 403 without forwarding.
      4. Forward the request to the upstream API.
      5. Read the response, run output detection.
      6. Return the proxied response with detection metadata.

    Args:
        method: HTTP method (GET, POST, etc.)
        path: Full path with host (e.g. ``api.anthropic.com/v1/messages``)
        headers: Request headers
        body: Raw request body bytes

    Returns:
        Dict with ``status_code``, ``headers``, ``body``, and ``detection``.
    """
    # ── 1. Parse upstream host from path ──
    if "/" not in path:
        return {
            "status_code": 400,
            "headers": {"content-type": "application/json"},
            "body": json.dumps({"error": "Invalid proxy path"}).encode(),
            "detection": None,
        }

    host = path.split("/")[0]
    upstream_path = "/" + "/".join(path.split("/")[1:])

    if host not in ALLOWED_UPSTREAMS:
        return {
            "status_code": 403,
            "headers": {"content-type": "application/json"},
            "body": json.dumps({
                "error": f"Upstream not allowed: {host}",
                "allowed": ALLOWED_UPSTREAMS,
            }).encode(),
            "detection": None,
        }

    # ── 2. Parse content for input detection ──
    content = ""
    if body and method in ("POST", "PUT", "PATCH"):
        try:
            req_body = json.loads(body)
            # Extract messages content (Anthropic format)
            messages = req_body.get("messages", [])
            for msg in messages:
                if isinstance(msg.get("content"), str):
                    content += msg["content"] + "\n"
                elif isinstance(msg.get("content"), list):
                    for block in msg["content"]:
                        if isinstance(block, dict) and block.get("type") == "text":
                            content += block.get("text", "") + "\n"

            # Also check system prompt
            system = req_body.get("system", "")
            if isinstance(system, str):
                content = system + "\n" + content
            elif isinstance(system, list):
                for block in system:
                    if isinstance(block, dict) and block.get("type") == "text":
                        content = block.get("text", "") + "\n" + content

            # OpenAI format
            if not content:
                for msg in messages:
                    if isinstance(msg.get("content"), str):
                        content += msg["content"] + "\n"
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

        # Also scan raw body as text if no structured content was extracted
        if not content.strip() and body and method in ("POST", "PUT", "PATCH"):
            try:
                content = body.decode("utf-8", errors="ignore")[:10000]
            except UnicodeDecodeError:
                pass

    # ── 3. Input detection ──
    input_result = None
    if content.strip():
        input_result = engine_service.detect_input(content)

    if input_result and input_result.triggered_rules:
        try:
            db = SessionLocal()
            _log_to_db(db, result=input_result, direction="input",
                        content=content, commit=True)
            db.close()
        except Exception:
            import logging as _lg
            _lg.getLogger("kasra.proxy").exception("Failed to log proxy input detection to DB")

    if input_result and input_result.blocked:
        logger.warning(
            "Proxy blocked input: %d rules triggered",
            len(input_result.triggered_rules),
        )
        return {
            "status_code": 403,
            "headers": {"content-type": "application/json"},
            "body": json.dumps({
                "error": "Content blocked by security policy",
                "blocked_by": [dr.rule_id for dr in input_result.triggered_rules],
                "warnings": input_result.warnings,
            }).encode(),
            "detection": {
                "input": {
                    "blocked": True,
                    "triggered_rules": [
                        {"rule_id": dr.rule_id, "severity": str(dr.severity)}
                        for dr in input_result.triggered_rules
                    ],
                },
            },
        }

    # ── 4. Forward request ──
    filtered_headers = {
        k: v for k, v in headers.items()
        if k.lower() not in STRIPPED_REQUEST_HEADERS
    }

    upstream_url = f"https://{host}{upstream_path}"

    try:
        client = _get_client()
        response = await client.request(
            method=method,
            url=upstream_url,
            headers=filtered_headers,
            content=body,
        )

        # ── 5. Output detection on response body ──
        response_body = response.content
        response_text = ""

        if response_body:
            try:
                resp_data = json.loads(response_body)
                if isinstance(resp_data, dict):
                    # Anthropic: content[].text
                    for block in resp_data.get("content", []):
                        if isinstance(block, dict) and block.get("type") == "text":
                            response_text += block.get("text", "") + "\n"
                    # OpenAI: choices[].message.content
                    for choice in resp_data.get("choices", []):
                        if isinstance(choice, dict):
                            msg = choice.get("message", {})
                            if isinstance(msg.get("content"), str):
                                response_text += msg["content"] + "\n"
                            # Delta for streaming
                            delta = choice.get("delta", {})
                            if isinstance(delta.get("content"), str):
                                response_text += delta["content"]
            except (json.JSONDecodeError, AttributeError):
                response_text = response_body.decode("utf-8", errors="replace")

        output_result = None
        if response_text.strip():
            output_result = engine_service.detect_output(response_text)

        # Log to audit database
        if output_result and output_result.triggered_rules:
            try:
                db = SessionLocal()
                _log_to_db(db, result=output_result, direction="output",
                            content=response_text, commit=True)
                db.close()
            except Exception:
                import logging as _lg
                _lg.getLogger("kasra.proxy").exception("Failed to log proxy detection to DB")

        detection_info = {
            "input": {
                "blocked": False,
                "triggered_rules": [
                    {"rule_id": dr.rule_id, "severity": str(dr.severity)}
                    for dr in (input_result.triggered_rules if input_result else [])
                ] if input_result and input_result.triggered_rules else [],
            },
            "output": {
                "warnings": [
                    {"rule_id": dr.rule_id, "severity": str(dr.severity)}
                    for dr in (output_result.triggered_rules if output_result else [])
                ] if output_result and output_result.triggered_rules else [],
            },
        }

        return {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": response_body,
            "detection": detection_info,
        }

    except httpx.TimeoutException:
        return {
            "status_code": 504,
            "headers": {"content-type": "application/json"},
            "body": json.dumps({"error": "Upstream request timed out"}).encode(),
            "detection": None,
        }
    except httpx.RequestError as e:
        logger.error("Proxy request failed: %s", e)
        return {
            "status_code": 502,
            "headers": {"content-type": "application/json"},
            "body": json.dumps({"error": f"Upstream connection failed: {str(e)}"}).encode(),
            "detection": None,
        }
