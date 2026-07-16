"""RuleEngine singleton management.

Initializes, configures, and provides access to the kasra-sdk RuleEngine
throughout the application lifecycle. Rules are loaded from the database
at startup — the engine itself does not read from disk.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

from kasra import RuleEngine
from kasra.models.enums import ActionType, MatchMode, PatternType as SdkPatternType, Severity
from kasra.models.rule import DetectionConfig, PatternDefinition, RuleDefinition
from kasra.models.result import AggregatedResult
from kasra.scanner.models import CodeReviewResult

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

        Rules are loaded from the database — call ``reload_rules_from_db()``
        after this method to inject rules into the engine.

        Args:
            rules_dir: Ignored when loading from DB. Kept for backward compat.
            config_dir: Optional path to SDK YAML config directory.
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

        # Don't call load_rules() — we'll inject rules from DB via
        # reload_rules_from_db() after this method returns.
        logger.info("Starting audit logger...")
        self._engine.start()
        logger.info("RuleEngine ready (no rules loaded yet).")

    def reload_rules_from_db(self, db_session: Any) -> int:
        """Reload all rules from the database into the engine.

        Reads both built-in (``rules`` table) and custom rules
        (``custom_rules`` table), converts them to ``RuleDefinition``
        objects, and injects them via ``load_rules_from_list()``.

        Args:
            db_session: SQLAlchemy database session.

        Returns:
            Number of rules loaded into the engine.
        """
        from app.models.rule_config import Rule as RuleModel
        from app.models.custom_rule import CustomRule
        from app.services.dictionary_service import load_active_dictionary_map

        # Pre-load dictionary refs so conversion functions can expand them
        dict_map = load_active_dictionary_map(db_session)

        rules_defs: list[RuleDefinition] = []

        # 1. Load built-in SDK rules (all — enabled state will be synced after)
        sdk_rules = db_session.query(RuleModel).all()
        for r in sdk_rules:
            rule_def = _rule_model_to_definition(r, dict_map)
            if rule_def is not None:
                rules_defs.append(rule_def)

        # 2. Load custom rules (all — enabled state will be synced after)
        custom_rules = db_session.query(CustomRule).all()
        for cr in custom_rules:
            rule_def = _custom_rule_to_definition(cr)
            if rule_def is not None:
                rules_defs.append(rule_def)

        # 3. Inject code review rules into scanner (all — state synced after)
        cr_rules = db_session.query(RuleModel).filter(
            RuleModel.rule_type == "code_review",
        ).all()
        cr_rule_dicts = []
        for r in cr_rules:
            cr_dict = _rule_model_to_cr_dict(r, dict_map)
            if cr_dict is not None:
                cr_rule_dicts.append(cr_dict)
        scanner = self._engine._get_code_review_scanner()
        scanner.set_rules(cr_rule_dicts)

        # Also inject custom CR rules
        custom_cr_rules = db_session.query(CustomRule).filter(
            CustomRule.rule_type == "code_review",
        ).all()
        for cr in custom_cr_rules:
            try:
                cr_dict = _custom_rule_to_cr_dict(cr)
                if cr_dict is not None:
                    scanner.add_custom_rule(cr_dict)
            except Exception:
                logger.warning("Failed to inject custom CR rule %s", cr.id)

        # 4. Inject into engine (I/O rules)
        rules_defs = [rd for rd in rules_defs
                      if not getattr(rd, "rule_type", None) == "code_review"
                      and "batch" not in (rd.applicable_stages or [])]
        count = self._engine.load_rules_from_list(rules_defs)
        logger.info(
            "Loaded %d rules from DB into engine (%d SDK + %d custom).",
            count, len(sdk_rules), len(custom_rules),
        )

        # 5. Sync disabled states from DB to engine
        disabled = db_session.query(RuleModel).filter(
            RuleModel.enabled == False  # noqa: E712
        ).all()
        for r in disabled:
            try:
                if r.rule_type == "code_review":
                    self._engine.disable_code_review_rule(r.id)
                else:
                    self._engine.disable_rule(r.id)
            except (KeyError, ValueError):
                pass

        # Also sync disabled custom rules
        disabled_cr = db_session.query(CustomRule).filter(
            CustomRule.enabled == False  # noqa: E712
        ).all()
        for cr in disabled_cr:
            try:
                if cr.rule_type == "code_review":
                    self._engine.remove_custom_cr_rule(cr.id)
                else:
                    self._engine.disable_rule(cr.id)
            except (KeyError, ValueError):
                pass

        if disabled or disabled_cr:
            logger.info("Synced %d disabled rules state to engine.", len(disabled) + len(disabled_cr))

        return count

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

    def review_code(
        self,
        path: str | os.PathLike,
    ) -> CodeReviewResult:
        """Run code review security scan on a file or directory.

        Args:
            path: Path to a file or directory to scan.

        Returns:
            A ``CodeReviewResult`` with all findings.
        """
        return self.engine.review_code(path)

    def track_behavior(
        self,
        content: str,
        session_id: str,
        **context_kwargs: Any,
    ) -> AggregatedResult:
        """Run behavior monitoring pipeline."""
        kwargs = {k: v for k, v in context_kwargs.items() if v is not None}
        return self.engine.track_behavior(content, session_id, **kwargs)


# ── Conversion helpers ──────────────────────────────────────────────────


def _resolve_dict_refs(
    patterns_raw: list[dict[str, Any]],
    dict_map: dict[str, list[str]],
) -> list[dict[str, Any]]:
    """Expand ``type=dictionary`` patterns into keyword patterns.

    Each ``{"type": "dictionary", "ref": "<code>", "confidence": N}`` is
    replaced with one ``{"type": "keyword", "value": <entry>, "confidence": N}``
    per entry in the referenced dictionary.
    """
    resolved: list[dict[str, Any]] = []
    for p in patterns_raw:
        if p.get("type") == "dictionary":
            ref = p.get("ref", "")
            entries = dict_map.get(ref, [])
            conf = p.get("confidence", 0.8)
            for entry in entries:
                resolved.append({"type": "keyword", "value": entry, "confidence": conf})
        else:
            resolved.append(p)
    return resolved


def _rule_model_to_definition(
    r: RuleModel,
    dict_map: dict[str, list[str]] | None = None,
) -> RuleDefinition | None:
    """Convert a ``Rule`` ORM model to a ``RuleDefinition``."""
    dc = r.detection_config
    if isinstance(dc, str):
        try:
            dc = json.loads(dc)
        except (json.JSONDecodeError, TypeError):
            dc = {}
    dc = dc or {}
    patterns_raw = dc.get("patterns", [])

    # Resolve dictionary refs if a dict_map was provided
    if dict_map:
        patterns_raw = _resolve_dict_refs(patterns_raw, dict_map)

    patterns = []
    for p in patterns_raw:
        try:
            ptype = SdkPatternType(p.get("type", "regex"))
        except ValueError:
            ptype = SdkPatternType.REGEX
        patterns.append(PatternDefinition(
            type=ptype,
            value=p.get("value", ""),
            confidence=float(p.get("confidence", 0.8)),
        ))

    try:
        sev = Severity(r.severity) if r.severity else Severity.P2
    except ValueError:
        sev = Severity.P2

    try:
        act = ActionType(r.action) if r.action else ActionType.WARN
    except ValueError:
        act = ActionType.WARN

    stages = r.applicable_stages or ["input"]
    if isinstance(stages, str):
        try:
            stages = json.loads(stages)
        except (json.JSONDecodeError, TypeError):
            stages = ["input"]

    return RuleDefinition(
        id=r.id,
        name=r.name,
        description=r.description or r.name,
        category=getattr(r, "category", "sdk") or "sdk",
        severity=sev,
        action=act,
        applicable_stages=list(stages),
        detection=DetectionConfig(
            mode=MatchMode(dc.get("mode", "any")) if dc.get("mode") else MatchMode.ANY,
            patterns=patterns,
        ),
        enabled=True,
    )


def _rule_model_to_cr_dict(
    r: RuleModel,
    dict_map: dict[str, list[str]] | None = None,
) -> dict[str, Any] | None:
    """Convert a ``Rule`` ORM model with rule_type=code_review to a CR dict."""
    if not r.id:
        return None
    dc = r.detection_config
    if isinstance(dc, str):
        try:
            dc = json.loads(dc)
        except (json.JSONDecodeError, TypeError):
            dc = {}
    dc = dc or {}
    patterns_raw = dc.get("patterns", [])

    # Resolve dictionary refs if a dict_map was provided
    if dict_map:
        patterns_raw = _resolve_dict_refs(patterns_raw, dict_map)

    target_files = dc.get("target_files", ["**/*"])
    if isinstance(target_files, str):
        try:
            target_files = json.loads(target_files)
        except (json.JSONDecodeError, TypeError):
            target_files = ["**/*"]

    cr_dict = {
        "id": r.id,
        "name": r.name,
        "description": r.description or r.name,
        "category": getattr(r, "category", "code_security") or "code_security",
        "severity": r.severity or "P2",
        "action": r.action or "warn",
        "target_files": list(target_files) if isinstance(target_files, list) else ["**/*"],
        "fp_risk": "medium",
        "performance": "high",
        "priority": 3,
        "detection_method": patterns_raw[0].get("type", "regex") if patterns_raw else "regex",
        "detection": {
            "patterns": [
                {"type": p.get("type", "regex"), "value": p.get("value", ""), "confidence": float(p.get("confidence", 0.8))}
                for p in patterns_raw
            ],
        },
    }
    return cr_dict


def _custom_rule_to_cr_dict(cr: CustomRule) -> dict[str, Any] | None:
    """Convert a ``CustomRule`` ORM model with rule_type=code_review to a CR dict."""
    if not cr.pattern_value:
        return None
    stages = cr.applicable_stages or ["batch"]
    if isinstance(stages, str):
        try:
            stages = json.loads(stages)
        except (json.JSONDecodeError, TypeError):
            stages = ["batch"]
    target_files = cr.target_files or ["**/*"]
    if isinstance(target_files, str):
        try:
            target_files = json.loads(target_files)
        except (json.JSONDecodeError, TypeError):
            target_files = ["**/*"]

    return {
        "id": cr.id,
        "name": cr.name,
        "description": cr.description or cr.name,
        "category": getattr(cr, "category", "custom") or "custom",
        "severity": cr.severity or "P2",
        "action": cr.action or "warn",
        "target_files": list(target_files),
        "fp_risk": "medium",
        "performance": "high",
        "priority": 3,
        "detection_method": cr.pattern_type or "regex",
        "detection": {
            "patterns": [
                {
                    "type": cr.pattern_type or "regex",
                    "value": cr.pattern_value,
                    "confidence": float(cr.pattern_confidence or "0.8"),
                }
            ],
        },
    }


def _custom_rule_to_definition(cr: CustomRule) -> RuleDefinition | None:
    """Convert a ``CustomRule`` ORM model to a ``RuleDefinition``."""
    if not cr.pattern_value:
        return None

    try:
        ptype = SdkPatternType(cr.pattern_type) if cr.pattern_type else SdkPatternType.REGEX
    except ValueError:
        ptype = SdkPatternType.REGEX

    try:
        sev = Severity(cr.severity) if cr.severity else Severity.P2
    except ValueError:
        sev = Severity.P2

    try:
        act = ActionType(cr.action) if cr.action else ActionType.WARN
    except ValueError:
        act = ActionType.WARN

    stages = cr.applicable_stages or ["input"]

    return RuleDefinition(
        id=cr.id,
        name=cr.name,
        description=cr.description or f"Custom rule: {cr.name}",
        category=getattr(cr, "category", "custom") or "custom",
        severity=sev,
        action=act,
        applicable_stages=list(stages),
        detection=DetectionConfig(
            mode=MatchMode.ANY,
            patterns=[
                PatternDefinition(
                    type=ptype,
                    value=cr.pattern_value,
                    confidence=float(cr.pattern_confidence or "0.8"),
                )
            ],
        ),
        enabled=cr.enabled,
    )


# Module-level singleton
engine_service = EngineService()
