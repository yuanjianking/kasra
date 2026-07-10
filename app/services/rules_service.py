"""Rules service — manage SDK built-in rules + custom user rules.

Two separate storage backends:
  1. ``rules`` table (``RuleConfig``) — enabled/disabled override state for SDK rules
  2. ``custom_rules`` table (``CustomRule``) — user-defined rules with full detection config
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.orm import Session as DBSession

from kasra.exceptions import RuleNotFoundError
from kasra.models.enums import ActionType, MatchMode, PatternType, Severity
from kasra.models.rule import DetectionConfig, PatternDefinition, RuleDefinition

from app.models.custom_rule import CustomRule
from app.models.rule_config import RuleConfig
from app.schemas.rules import RuleCreate, RuleSchema, RuleUpdate
from app.services.engine_service import engine_service

logger = logging.getLogger("kasra.service.rules")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _rule_group(rule_id: str) -> str:
    """Determine the display group of an SDK rule from its ID."""
    prefix = rule_id.split("-", 1)[0] if "-" in rule_id else rule_id
    if prefix == "I":
        return "input"
    if prefix == "O":
        return "output"
    return "code_review"


def _stages_to_group(stages: list[str]) -> str:
    """Derive UI group from applicable_stages."""
    if "batch" in stages:
        return "code_review"
    if "output" in stages:
        return "output"
    return "input"


def _build_rule_definition(cr: CustomRule) -> RuleDefinition | None:
    """Build a ``RuleDefinition`` from a ``CustomRule`` DB record."""
    if not cr.pattern_value:
        return None

    return RuleDefinition(
        id=cr.id,
        name=cr.name,
        description=cr.description or f"Custom rule: {cr.name}",
        category=cr.category or "custom",
        severity=Severity(cr.severity),
        action=ActionType(cr.action),
        applicable_stages=list(cr.applicable_stages or ["input"]),
        detection=DetectionConfig(
            mode=MatchMode.ANY,
            patterns=[
                PatternDefinition(
                    type=PatternType(cr.pattern_type),
                    value=cr.pattern_value,
                    confidence=float(cr.pattern_confidence or "0.8"),
                )
            ],
        ),
        enabled=cr.enabled,
    )


def _build_cr_rule_dict(cr: CustomRule) -> dict[str, Any]:
    """Build a code-review rule dict from a ``CustomRule`` DB record."""
    return {
        "id": cr.id,
        "name": cr.name,
        "description": cr.description or f"Custom rule: {cr.name}",
        "category": cr.category or "custom",
        "severity": cr.severity,
        "action": cr.action,
        "target_files": cr.target_files or ["**/*"],
        "fp_risk": "medium",
        "performance": "high",
        "priority": 3,
        "detection_method": cr.pattern_type,
        "detection": {
            "patterns": [
                {
                    "type": cr.pattern_type,
                    "value": cr.pattern_value,
                    "confidence": float(cr.pattern_confidence or "0.8"),
                }
            ]
        },
    }


def _is_cr_custom_rule(cr: CustomRule) -> bool:
    """Check if a custom rule targets code review (batch stage)."""
    return "batch" in (cr.applicable_stages or [])


def _sync_to_engine(cr: CustomRule) -> None:
    """Inject a custom rule into the live RuleEngine."""
    engine = engine_service.engine

    if _is_cr_custom_rule(cr):
        engine.add_custom_cr_rule(_build_cr_rule_dict(cr))
        if not cr.enabled:
            engine.disable_code_review_rule(cr.id)
        logger.debug("Synced custom CR rule %s to scanner", cr.id)
    else:
        rule_def = _build_rule_definition(cr)
        if rule_def is not None:
            engine.add_custom_rule(rule_def)
            if not cr.enabled:
                engine.disable_rule(cr.id)
            logger.debug("Synced custom I/O rule %s to store", cr.id)


def _remove_from_engine(rule_id: str) -> None:
    """Remove a custom rule from the live RuleEngine."""
    engine = engine_service.engine
    if engine.remove_custom_rule(rule_id):
        return
    engine.remove_custom_cr_rule(rule_id)


def _schema_from_custom(cr: CustomRule) -> RuleSchema:
    """Convert a ``CustomRule`` DB record to a ``RuleSchema``."""
    return RuleSchema(
        id=cr.id,
        name=cr.name,
        description=cr.description,
        category=cr.category,
        severity=cr.severity,
        action=cr.action,
        pattern=None,
        pattern_type=cr.pattern_type,
        pattern_value=cr.pattern_value,
        applicable_stages=list(cr.applicable_stages or ["input"]),
        target_files=cr.target_files,
        enabled=cr.enabled,
        is_custom=True,
        source="user",
        group=_stages_to_group(cr.applicable_stages or ["input"]),
    )


# ---------------------------------------------------------------------------
# Startup sync
# ---------------------------------------------------------------------------

def sync_disabled_rules_from_db(db: DBSession) -> None:
    """Sync disabled SDK rule states from DB to the engine on startup."""
    engine = engine_service.engine
    disabled = db.query(RuleConfig).filter(
        RuleConfig.enabled == False,  # noqa: E712
        RuleConfig.is_custom == False,
    ).all()
    if not disabled:
        return

    try:
        engine.get_code_review_rules()
    except Exception:
        pass

    io_count = cr_count = 0
    for rec in disabled:
        grp = _rule_group(rec.id)
        try:
            if grp == "code_review":
                engine.disable_code_review_rule(rec.id)
                cr_count += 1
            else:
                engine.disable_rule(rec.id)
                io_count += 1
        except (RuleNotFoundError, ValueError):
            pass

    if cr_count or io_count:
        logger.info(
            "Synced disabled state from DB: %d I/O rules, %d CR rules",
            io_count, cr_count,
        )


def sync_custom_rules_from_db(db: DBSession) -> int:
    """Load all enabled custom rules from DB into the engine at startup."""
    engine = engine_service.engine
    try:
        engine.get_code_review_rules()
    except Exception:
        pass

    rules = db.query(CustomRule).filter(CustomRule.enabled == True).all()  # noqa: E712
    count = 0
    for cr in rules:
        try:
            _sync_to_engine(cr)
            count += 1
        except Exception as exc:
            logger.warning("Failed to load custom rule %s: %s", cr.id, exc)

    if count:
        logger.info("Loaded %d custom rules from DB into engine", count)
    return count


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

def list_rules(
    db: DBSession,
    *,
    category: str | None = None,
    severity: str | None = None,
    enabled_only: bool | None = None,
    custom_only: bool | None = None,
    group: str | None = None,
    page: int = 1,
    page_size: int = 100,
) -> dict[str, Any]:
    """List rules from three sources: SDK I/O rules + SDK CR rules + custom rules."""
    engine = engine_service.engine

    # 1. SDK I/O rules
    sdk_rules = engine.get_rules()
    db_overrides = {r.id: r for r in db.query(RuleConfig).all()}

    merged: list[RuleSchema] = []

    for rule in sdk_rules:
        override = db_overrides.get(rule.id)
        merged.append(RuleSchema(
            id=rule.id,
            name=rule.name,
            description=rule.description,
            category=rule.category,
            severity=str(rule.severity.value) if hasattr(rule.severity, "value") else str(rule.severity),
            action=str(rule.action.value) if hasattr(rule.action, "value") else str(rule.action),
            enabled=override.enabled if override else rule.enabled,
            is_custom=False,
            source="sdk",
            group=_rule_group(rule.id),
        ))

    # 2. SDK CR rules (from engine scanner)
    try:
        disabled_ids = engine.disabled_code_review_rule_ids
        for _r in engine.get_code_review_rules():
            _rid = _r.get("id", "")
            if not _rid:
                continue
            override = db_overrides.get(_rid)
            merged.append(RuleSchema(
                id=_rid,
                name=_r.get("name", _rid),
                description=_r.get("description", ""),
                category=_r.get("category", "code_security"),
                severity=_r.get("severity", "P1"),
                action=_r.get("action", "warn"),
                enabled=override.enabled if override else (_rid not in disabled_ids),
                is_custom=False,
                source="sdk",
                group="code_review",
            ))
    except Exception:
        pass

    # 3. Custom rules (from custom_rules table)
    for cr in db.query(CustomRule).all():
        merged.append(_schema_from_custom(cr))

    # Filters
    if category:
        merged = [r for r in merged if r.category == category]
    if severity:
        merged = [r for r in merged if r.severity == severity]
    if enabled_only is not None:
        merged = [r for r in merged if r.enabled == enabled_only]
    if group:
        merged = [r for r in merged if r.group == group]
    if custom_only:
        merged = [r for r in merged if r.is_custom]

    merged.sort(key=lambda r: r.id)

    total = len(merged)
    offset = (page - 1) * page_size
    return {
        "items": merged[offset:offset + page_size],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


def get_rule(db: DBSession, rule_id: str) -> RuleSchema | None:
    """Get a single rule by ID from SDK or custom rules."""
    engine = engine_service.engine

    # SDK I/O rules
    try:
        sdk_rule = engine.get_rule(rule_id)
        override = db.query(RuleConfig).filter(RuleConfig.id == rule_id).first()
        return RuleSchema(
            id=sdk_rule.id,
            name=sdk_rule.name,
            description=sdk_rule.description,
            category=sdk_rule.category,
            severity=str(sdk_rule.severity.value) if hasattr(sdk_rule.severity, "value") else str(sdk_rule.severity),
            action=str(sdk_rule.action.value) if hasattr(sdk_rule.action, "value") else str(sdk_rule.action),
            enabled=override.enabled if override else sdk_rule.enabled,
            is_custom=False,
            source="sdk",
            group=_rule_group(rule_id),
        )
    except (KeyError, RuleNotFoundError):
        pass

    # SDK CR rules
    try:
        disabled_ids = engine.disabled_code_review_rule_ids
        for _r in engine.get_code_review_rules():
            if _r.get("id") == rule_id:
                override = db.query(RuleConfig).filter(RuleConfig.id == rule_id).first()
                return RuleSchema(
                    id=_r["id"],
                    name=_r.get("name", rule_id),
                    description=_r.get("description", ""),
                    category=_r.get("category", "code_security"),
                    severity=_r.get("severity", "P1"),
                    action=_r.get("action", "warn"),
                    enabled=override.enabled if override else (rule_id not in disabled_ids),
                    is_custom=False,
                    source="sdk",
                    group="code_review",
                )
    except Exception:
        pass

    # Custom rules
    cr = db.query(CustomRule).filter(CustomRule.id == rule_id).first()
    if cr:
        return _schema_from_custom(cr)

    return None


def create_rule(db: DBSession, rule: RuleCreate) -> RuleSchema:
    """Create a new custom rule and sync to live engine."""
    if not rule.id.startswith("U-"):
        raise ValueError("Custom rule IDs must start with U-")

    if db.query(CustomRule).filter(CustomRule.id == rule.id).first():
        raise ValueError(f"Rule {rule.id} already exists")

    conf_str = str(rule.pattern_confidence) if rule.pattern_confidence is not None else "0.8"

    cr = CustomRule(
        id=rule.id,
        name=rule.name,
        description=rule.description,
        category=rule.category,
        severity=rule.severity,
        action=rule.action,
        pattern_type=rule.pattern_type,
        pattern_value=rule.pattern_value,
        pattern_confidence=conf_str,
        applicable_stages=rule.applicable_stages,
        target_files=rule.target_files,
        enabled=rule.enabled,
    )
    db.add(cr)
    db.commit()
    db.refresh(cr)

    try:
        _sync_to_engine(cr)
        logger.info("Custom rule %s synced to engine", rule.id)
    except Exception as exc:
        logger.warning("Rule %s created but engine sync failed: %s", rule.id, exc)

    return _schema_from_custom(cr)


def update_rule(db: DBSession, rule_id: str, update: RuleUpdate) -> RuleSchema | None:
    """Update a rule — custom rule fields or SDK rule enabled/disabled."""
    # Check custom rule table first
    cr = db.query(CustomRule).filter(CustomRule.id == rule_id).first()
    if cr:
        if update.name is not None:
            cr.name = update.name
        if update.description is not None:
            cr.description = update.description
        if update.severity is not None:
            cr.severity = update.severity
        if update.action is not None:
            cr.action = update.action
        if update.pattern_type is not None:
            cr.pattern_type = update.pattern_type
        if update.pattern_value is not None:
            cr.pattern_value = update.pattern_value
        if update.pattern_confidence is not None:
            cr.pattern_confidence = update.pattern_confidence
        if update.applicable_stages is not None:
            cr.applicable_stages = update.applicable_stages
        if update.target_files is not None:
            cr.target_files = update.target_files
        if update.enabled is not None:
            cr.enabled = update.enabled

        db.commit()
        db.refresh(cr)

        try:
            _remove_from_engine(rule_id)
            _sync_to_engine(cr)
            logger.debug("Re-synced custom rule %s after update", rule_id)
        except Exception as exc:
            logger.warning("Engine re-sync failed for %s: %s", rule_id, exc)

        return _schema_from_custom(cr)

    # SDK rule — create or update override in RuleConfig
    sdk_rule = db.query(RuleConfig).filter(RuleConfig.id == rule_id).first()

    if sdk_rule is None:
        if rule_id.startswith("U-"):
            return None  # U-series must be created first

        # Validate it's a real SDK rule
        is_valid = False
        try:
            engine_service.engine.get_rule(rule_id)
            is_valid = True
        except (KeyError, RuleNotFoundError):
            pass
        if not is_valid:
            try:
                if rule_id in engine_service.engine.get_code_review_rule_ids():
                    is_valid = True
            except Exception:
                pass
        if not is_valid:
            return None

        sdk_rule = RuleConfig(id=rule_id, name=rule_id, enabled=True, is_custom=False, source="sdk")
        db.add(sdk_rule)

    if update.enabled is not None:
        sdk_rule.enabled = update.enabled
    db.commit()
    db.refresh(sdk_rule)

    # Sync to engine
    if update.enabled is not None:
        engine = engine_service.engine
        try:
            if sdk_rule.enabled:
                engine.enable_rule(rule_id)
            else:
                engine.disable_rule(rule_id)
        except RuleNotFoundError:
            try:
                if sdk_rule.enabled:
                    engine.enable_code_review_rule(rule_id)
                else:
                    engine.disable_code_review_rule(rule_id)
            except ValueError:
                pass

    return get_rule(db, rule_id)


def delete_rule(db: DBSession, rule_id: str) -> bool:
    """Delete a custom rule (or reset an SDK rule override)."""
    # Check custom rules first
    cr = db.query(CustomRule).filter(CustomRule.id == rule_id).first()
    if cr:
        db.delete(cr)
        db.commit()
        try:
            _remove_from_engine(rule_id)
            logger.info("Custom rule %s removed from engine", rule_id)
        except Exception as exc:
            logger.warning("Engine remove failed for %s: %s", rule_id, exc)
        return True

    # SDK rule — delete the override record
    sdk_rule = db.query(RuleConfig).filter(RuleConfig.id == rule_id).first()
    if sdk_rule:
        db.delete(sdk_rule)
        db.commit()
        return True

    return False
