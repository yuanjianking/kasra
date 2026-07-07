"""Prometheus metrics for Kasra.

Exposes application metrics at /metrics endpoint.
Requires prometheus-client library (pip install prometheus-client).
If not installed, metrics are no-ops.
"""

from __future__ import annotations

import time
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

try:
    from prometheus_client import Counter, Gauge, Histogram, generate_latest, CONTENT_TYPE_LATEST
    _PROMETHEUS_AVAILABLE = True
except ImportError:
    _PROMETHEUS_AVAILABLE = False

    # Dummy classes for when prometheus_client is not installed
    class _DummyMetric:  # type: ignore
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass
        def labels(self, **kwargs: Any) -> _DummyMetric:
            return self
        def inc(self, amount: int = 1) -> None:
            pass
        def set(self, value: Any) -> None:
            pass
        def observe(self, value: Any) -> None:
            pass

    Counter = _DummyMetric  # type: ignore
    Gauge = _DummyMetric  # type: ignore
    Histogram = _DummyMetric  # type: ignore

    def generate_latest() -> bytes:
        return b"# prometheus_client not installed\n"
    CONTENT_TYPE_LATEST = "text/plain"


# ── Counters ──

detections_total = Counter(
    "kasra_detections_total",
    "Total number of detection events",
    ["direction", "action", "severity"],
)

detections_blocked_total = Counter(
    "kasra_detections_blocked_total",
    "Number of blocked requests",
    ["direction"],
)

# ── Histograms ──

detection_duration_ms = Histogram(
    "kasra_detection_duration_ms",
    "Detection execution time in milliseconds",
    ["direction"],
    buckets=[1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000],
)

request_duration_ms = Histogram(
    "kasra_request_duration_ms",
    "HTTP request duration in milliseconds",
    ["method", "path", "status"],
    buckets=[5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000],
)

# ── Gauges ──

rules_loaded = Gauge(
    "kasra_rules_loaded",
    "Number of loaded security rules",
)

rules_active = Gauge(
    "kasra_rules_enabled",
    "Number of enabled security rules",
)

db_health = Gauge(
    "kasra_db_health",
    "Database health status (1=healthy, 0=unhealthy)",
)

engine_health = Gauge(
    "kasra_engine_health",
    "Engine health status (1=healthy, 0=unhealthy)",
)

audit_log_total = Gauge(
    "kasra_audit_log_total",
    "Total number of audit log entries",
)

active_users_24h = Gauge(
    "kasra_active_users_24h",
    "Number of active users in the last 24 hours",
)

# ── Middleware ──


class PrometheusMiddleware(BaseHTTPMiddleware):
    """ASGI middleware that records request duration and updates metrics."""

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        start = time.monotonic()

        response = await call_next(request)

        duration = (time.monotonic() - start) * 1000
        path = request.url.path

        # Normalize path for label cardinality
        # Group /v1/scan/input, /v1/audit/logs, etc. by their base path
        for prefix in ("/v1/proxy/", "/v1/rules/", "/v1/audit/"):
            if path.startswith(prefix):
                # Keep the first two path segments
                parts = path.strip("/").split("/")
                if len(parts) >= 3:
                    path = f"/{'/'.join(parts[:3])}/..."
                break

        request_duration_ms.labels(
            method=request.method,
            path=path,
            status=str(response.status_code),
        ).observe(duration)

        return response


def metrics_endpoint(request: Request) -> Response:
    """Expose Prometheus metrics."""
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST,
    )
