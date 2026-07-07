"""CLI entry point for Kasra server.

Invoked via ``pip install kasra && kasra-server`` or ``python -m app``.
"""

from __future__ import annotations

import sys


def main() -> None:
    """Launch the Kasra application server."""
    from app.logging import configure_logging
    from app.config import settings

    configure_logging(settings.log_level)

    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        workers=settings.workers,
        log_level=settings.log_level,
    )


if __name__ == "__main__":
    sys.exit(main())
