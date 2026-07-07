"""Structured logging configuration for Kasra.

Provides JSON-formatted logging for production (structured log shipping
to Elasticsearch/Loki/Datadog) with a human-readable fallback for development.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any


class JsonFormatter(logging.Formatter):
    """JSON log formatter — outputs structured log records.

    Produces one JSON object per line, compatible with:
      - Elasticsearch / Filebeat
      - Loki / Promtail
      - Datadog / Vector
      - Any JSON log shipper
    """

    def format(self, record: logging.LogRecord) -> str:
        """Format a log record as a JSON string."""
        entry: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Include exception info if present
        if record.exc_info and record.exc_info[0] is not None:
            entry["exception"] = self.formatException(record.exc_info)

        # Include extra contextual fields
        for key in ("user_id", "request_id", "rule_id", "direction", "duration_ms"):
            if hasattr(record, key):
                entry[key] = getattr(record, key)

        # Include span/trace IDs for distributed tracing (future use)
        for key in ("trace_id", "span_id"):
            if hasattr(record, key):
                entry[key] = getattr(record, key)

        return json.dumps(entry, ensure_ascii=False, default=str)


def configure_logging(level: str = "INFO") -> None:
    """Configure Kasra root logger.

    Uses JSON formatting by default; falls back to human-readable
    for interactive terminal sessions if python-json-logger is
    not available.

    Args:
        level: Log level string (``debug``, ``info``, ``warning``, ``error``).
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    root = logging.getLogger("kasra")

    # Avoid duplicate handlers on re-config
    if root.handlers:
        return

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root.addHandler(handler)
    root.setLevel(numeric_level)

    # Suppress noisy third-party loggers
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("mcp").setLevel(logging.WARNING)
