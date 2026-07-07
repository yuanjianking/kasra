"""RuleEngine singleton management.

Initializes, configures, and provides access to the kasra-sdk RuleEngine
throughout the application lifecycle.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from kasra import RuleEngine
from kasra.models.result import AggregatedResult

from app.config import settings

logger = logging.getLogger("kasra.engine")


class EngineService:
    """Manages the RuleEngine singleton lifecycle.

    Usage::

        engine_service = EngineService()
        engine_service.initialize()
        result = engine_service.engine.detect_input("content")
        engine_service.shutdown()
    """

    def __init__(self) -> None:
        self._engine: RuleEngine | None = None

    # ── Properties ──

    @property
    def engine(self) -> RuleEngine:
        """Return the initialized RuleEngine instance.

        Raises:
            RuntimeError: If ``initialize()`` has not been called.
        """
        if self._engine is None:
            raise RuntimeError(
                "RuleEngine not initialized. Call initialize() first."
            )
        return self._engine

    @property
    def is_initialized(self) -> bool:
        return self._engine is not None

    # ── Lifecycle ──

    def initialize(
        self,
        rules_dir: str | os.PathLike | None = None,
        config_dir: str | os.PathLike | None = None,
    ) -> None:
        """Create, configure, and start the RuleEngine.

        Args:
            rules_dir: Path to SDK rule JSON bundle directory.
                Auto-detected by the SDK by default.
            config_dir: Path to SDK YAML config directory.
                Auto-detected by the SDK by default.
        """
        if self._engine is not None:
            logger.warning("RuleEngine already initialized — skipping.")
            return

        logger.info("Creating RuleEngine...")
        self._engine = RuleEngine(
            rules_dir=rules_dir,
            config_dir=config_dir,
        )

        # Override audit config from app settings
        self._engine.config.audit.jsonl_path = str(
            Path(settings.data_dir) / "kasra-audit.jsonl"
        )

        logger.info("Loading rules...")
        count = self._engine.load_rules()
        logger.info("Loaded %d rules.", count)

        logger.info("Starting audit logger...")
        self._engine.start()
        logger.info("RuleEngine ready.")

    def shutdown(self) -> None:
        """Stop the RuleEngine and flush audit logs."""
        if self._engine is None:
            return
        logger.info("Stopping RuleEngine...")
        self._engine.stop()
        self._engine = None
        logger.info("RuleEngine stopped.")

    # ── Detection methods ──

    def detect_input(
        self,
        content: str,
        **context_kwargs: Any,
    ) -> AggregatedResult:
        """Run input detection pipeline.

        Args:
            content: Text content to evaluate.
            **context_kwargs: user_id, session_id, request_id, etc.

        Returns:
            AggregatedResult with detection findings.
        """
        kwargs = {k: v for k, v in context_kwargs.items() if v is not None}
        return self.engine.detect_input(content, **kwargs)

    def detect_output(
        self,
        content: str,
        **context_kwargs: Any,
    ) -> AggregatedResult:
        """Run output detection pipeline."""
        kwargs = {k: v for k, v in context_kwargs.items() if v is not None}
        return self.engine.detect_output(content, **kwargs)

    def scan_file(
        self,
        file_path: str | os.PathLike,
        **context_kwargs: Any,
    ) -> AggregatedResult:
        """Scan a single file for rule violations."""
        kwargs = {k: v for k, v in context_kwargs.items() if v is not None}
        return self.engine.scan_file(file_path, **kwargs)

    def scan_directory(
        self,
        dir_path: str | os.PathLike,
        **context_kwargs: Any,
    ) -> list[AggregatedResult]:
        """Scan all files in a directory."""
        kwargs = {k: v for k, v in context_kwargs.items() if v is not None}
        return self.engine.scan_directory(dir_path, **kwargs)

    def track_behavior(
        self,
        content: str,
        session_id: str,
        **context_kwargs: Any,
    ) -> AggregatedResult:
        """Run behavior monitoring pipeline."""
        kwargs = {k: v for k, v in context_kwargs.items() if v is not None}
        return self.engine.track_behavior(content, session_id, **kwargs)


# Module-level singleton
engine_service = EngineService()
