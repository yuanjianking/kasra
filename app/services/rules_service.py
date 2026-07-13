"""Rules service — manage SDK built-in rules + custom user rules.

Two separate storage backends:
  1. ``rules`` table — built-in SDK rules (seeded from JSON bundles)
  2. ``custom_rules`` table — user-defined rules with full detection config

Both tables reference ``categories`` and ``pattern_types`` master tables.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from kasra.exceptions import RuleNotFoundError

from fastapi import UploadFile
from sqlalchemy.orm import Session as DBSession

from app.models.category import Category
from app.models.custom_rule import CustomRule
from app.models.pattern_type import PatternType
from app.models.rule_config import Rule as RuleModel
from app.schemas.rules import RuleCreate, RuleSchema, RuleUpdate
from app.services.engine_service import engine_service

logger = logging.getLogger("kasra.service.rules")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_json_col(val: Any, default: Any = None) -> Any:
    """Parse a JSON column that might be stored as a string (SQLite)."""
    if val is None:
        return default
    if isinstance(val, (list, dict)):
        return val
    if isinstance(val, str):
        try:
            return json.loads(val)
        except (json.JSONDecodeError, TypeError):
            return default
    return val


def _rule_group(rule_id: str) -> str:
    """Determine the display group of an SDK rule from its ID."""
    prefix = rule_id.split("-", 1)[0] if "-" in rule_id else rule_id
    if prefix in ("I", "O"):
        return "input" if prefix == "I" else "output" if prefix == "O" else "input"
    return "code_review"


def _stages_to_group(stages: list[str] | Any) -> str:
    """Derive UI group from applicable_stages."""
    stages = _parse_json_col(stages, ["input"])
    if not isinstance(stages, list):
        return "input"
    if "batch" in stages:
        return "code_review"
    if "output" in stages:
        return "output"
    return "input"


def _resolve_category_name(db: DBSession, category_id: int | None) -> str | None:
    """Resolve a category ID to its name string."""
    if category_id is None:
        return None
    cat = db.query(Category).filter(Category.id == category_id).first()
    return cat.name if cat else None


def _schema_from_rule(db: DBSession, r: RuleModel) -> RuleSchema:
    """Convert a ``Rule`` ORM model to a ``RuleSchema``."""
    cat_name = _resolve_category_name(db, r.category_id)
    return RuleSchema(
        id=r.id,
        name=r.name,
        description=r.description,
        category=cat_name,
        category_id=r.category_id,
        severity=r.severity,
        action=r.action,
        rule_type=r.rule_type,
        applicable_stages=list(_parse_json_col(r.applicable_stages, ["input"])),
        detection_config=_parse_json_col(r.detection_config, {}),
        enabled=r.enabled,
        is_custom=False,
        source=r.source or "sdk",
        group=_rule_group(r.id),
        sdk_version=r.sdk_version,
    )


def _schema_from_custom(db: DBSession, cr: CustomRule) -> RuleSchema:
    """Convert a ``CustomRule`` DB record to a ``RuleSchema``."""
    cat_name = _resolve_category_name(db, cr.category_id)
    pt_name = None
    if cr.pattern_type_id:
        pt = db.query(PatternType).filter(PatternType.id == cr.pattern_type_id).first()
        pt_name = pt.name if pt else None

    return RuleSchema(
        id=cr.id,
        name=cr.name,
        description=cr.description,
        category=cat_name,
        category_id=cr.category_id,
        severity=cr.severity,
        action=cr.action,
        rule_type=cr.rule_type,
        pattern_type=pt_name or cr.pattern_type,
        pattern_value=cr.pattern_value,
        pattern_confidence=float(cr.pattern_confidence) if cr.pattern_confidence else None,
        applicable_stages=list(_parse_json_col(cr.applicable_stages, ["input"])),
        target_files=cr.target_files,
        detection_config=_parse_json_col(cr.detection_config),
        enabled=cr.enabled,
        is_custom=True,
        source="user",
        group=_stages_to_group(_parse_json_col(cr.applicable_stages, ["input"])),
    )


def _sync_to_engine(cr: CustomRule) -> None:
    """Inject a custom rule into the live RuleEngine."""
    from app.services.engine_service import _custom_rule_to_definition

    engine = engine_service.engine
    rule_def = _custom_rule_to_definition(cr)
    if rule_def is not None:
        engine.add_custom_rule(rule_def)
        logger.debug("Synced custom rule %s to engine", cr.id)


def _remove_from_engine(rule_id: str) -> None:
    """Remove a custom rule from the live RuleEngine."""
    engine = engine_service.engine
    engine.remove_custom_rule(rule_id)


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------


def sync_disabled_rules_from_db(db: DBSession) -> None:
    """Sync disabled SDK rule states from DB to the engine on startup."""
    engine = engine_service.engine
    disabled = db.query(RuleModel).filter(
        RuleModel.enabled == False  # noqa: E712
    ).all()
    if not disabled:
        return
    for rec in disabled:
        try:
            engine.disable_rule(rec.id)
        except (KeyError, ValueError):
            pass
    logger.info("Synced %d disabled rules to engine.", len(disabled))


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
    """List rules from both built-in (rules) and custom (custom_rules) tables."""
    merged: list[RuleSchema] = []

    # 1. Built-in SDK rules
    query = db.query(RuleModel)
    if category:
        cat = db.query(Category).filter(Category.name == category).first()
        if cat:
            query = query.filter(RuleModel.category_id == cat.id)
    if severity:
        query = query.filter(RuleModel.severity == severity)
    if enabled_only is not None:
        query = query.filter(RuleModel.enabled == enabled_only)
    for r in query.all():
        merged.append(_schema_from_rule(db, r))

    # 2. Custom rules
    cq = db.query(CustomRule)
    if category:
        cat = db.query(Category).filter(Category.name == category).first()
        if cat:
            cq = cq.filter(CustomRule.category_id == cat.id)
    if severity:
        cq = cq.filter(CustomRule.severity == severity)
    if enabled_only is not None:
        cq = cq.filter(CustomRule.enabled == enabled_only)
    for cr in cq.all():
        merged.append(_schema_from_custom(db, cr))

    # Filter by group
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
    """Get a single rule by ID from built-in or custom rules."""
    # Built-in rules
    r = db.query(RuleModel).filter(RuleModel.id == rule_id).first()
    if r:
        return _schema_from_rule(db, r)

    # Custom rules
    cr = db.query(CustomRule).filter(CustomRule.id == rule_id).first()
    if cr:
        return _schema_from_custom(db, cr)

    return None


def create_rule(db: DBSession, rule: RuleCreate) -> RuleSchema:
    """Create a new custom rule and sync to live engine."""
    if not rule.id.startswith("U-"):
        raise ValueError("Custom rule IDs must start with U-")

    if db.query(CustomRule).filter(CustomRule.id == rule.id).first():
        raise ValueError(f"Rule {rule.id} already exists")

    # Resolve category_id
    category_id = None
    if rule.category:
        cat = db.query(Category).filter(Category.name == rule.category).first()
        if cat:
            category_id = cat.id

    # Resolve pattern_type_id
    pattern_type_id = None
    pt = db.query(PatternType).filter(PatternType.name == rule.pattern_type).first()
    if pt:
        pattern_type_id = pt.id

    conf_str = str(rule.pattern_confidence) if rule.pattern_confidence is not None else "0.8"

    cr = CustomRule(
        id=rule.id,
        name=rule.name,
        description=rule.description,
        category_id=category_id,
        severity=rule.severity,
        action=rule.action,
        rule_type="code_review" if "batch" in (rule.applicable_stages or []) else "io",
        pattern_type=rule.pattern_type,
        pattern_value=rule.pattern_value,
        pattern_confidence=conf_str,
        pattern_type_id=pattern_type_id,
        applicable_stages=rule.applicable_stages or ["input"],
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

    return _schema_from_custom(db, cr)


def update_rule(db: DBSession, rule_id: str, update: RuleUpdate) -> RuleSchema | None:
    """Update a rule — custom rule fields or SDK rule toggle."""
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
            pt = db.query(PatternType).filter(PatternType.name == update.pattern_type).first()
            cr.pattern_type_id = pt.id if pt else None
        if update.pattern_value is not None:
            cr.pattern_value = update.pattern_value
        if update.pattern_confidence is not None:
            cr.pattern_confidence = update.pattern_confidence
        if update.applicable_stages is not None:
            cr.applicable_stages = update.applicable_stages
            cr.rule_type = "code_review" if "batch" in update.applicable_stages else "io"
        if update.target_files is not None:
            cr.target_files = update.target_files
        if update.enabled is not None:
            cr.enabled = update.enabled
        if update.category is not None:
            cat = db.query(Category).filter(Category.name == update.category).first()
            cr.category_id = cat.id if cat else None

        db.commit()
        db.refresh(cr)

        try:
            _remove_from_engine(rule_id)
            if cr.enabled:
                _sync_to_engine(cr)
            logger.debug("Re-synced custom rule %s after update", rule_id)
        except Exception as exc:
            logger.warning("Engine re-sync failed for %s: %s", rule_id, exc)

        return _schema_from_custom(db, cr)

    # SDK rule — toggle enabled/disabled
    r = db.query(RuleModel).filter(RuleModel.id == rule_id).first()
    if r is None:
        return None

    if update.enabled is not None:
        r.enabled = update.enabled
        db.commit()
        db.refresh(r)

        engine = engine_service.engine
        try:
            if r.enabled:
                engine.enable_rule(rule_id)
            else:
                engine.disable_rule(rule_id)
        except (KeyError, ValueError):
            pass
        except RuleNotFoundError:
            try:
                if r.enabled:
                    engine.enable_code_review_rule(rule_id)
                else:
                    engine.disable_code_review_rule(rule_id)
            except ValueError:
                pass

    return _schema_from_rule(db, r)


def delete_rule(db: DBSession, rule_id: str) -> bool:
    """Delete a custom rule."""
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

    # SDK rule — just disable it
    r = db.query(RuleModel).filter(RuleModel.id == rule_id).first()
    if r:
        r.enabled = False
        db.commit()
        return True

    return False


# ---------------------------------------------------------------------------
# Import / Export
# ---------------------------------------------------------------------------


IMPORT_BUNDLE_SCHEMA = {
    "type": "object",
    "properties": {
        "bundle": {
            "type": "object",
            "properties": {
                "series": {"type": "string"},
                "name": {"type": "string"},
                "version": {"type": "string"},
                "total": {"type": "integer"},
            },
            "required": ["series", "name"],
        },
        "rules": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "name": {"type": "string"},
                    "severity": {"type": "string"},
                    "action": {"type": "string"},
                    "applicable_stages": {"type": "array", "items": {"type": "string"}},
                    "category": {"type": "string"},
                    "description": {"type": "string"},
                    "detection": {"type": "object"},
                    "enabled": {"type": "boolean"},
                },
                "required": ["id", "name"],
            },
        },
    },
    "required": ["bundle", "rules"],
}


def _detection_config_from_bundle_rule(rule_dict: dict) -> dict:
    """Convert a bundle rule dict to detection_config JSON."""
    detection = rule_dict.get("detection", {})
    return {
        "mode": detection.get("mode", "any"),
        "patterns": detection.get("patterns", []),
    }


def import_rules_from_bundle(
    db: DBSession,
    bundle_data: dict[str, Any],
) -> dict[str, Any]:
    """Import rules from a bundle JSON dict.

    Returns import stats: total, created, updated, errors.
    """
    stats = {"total": 0, "created": 0, "updated": 0, "errors": []}
    rules_list = bundle_data.get("rules", [])
    bundle_info = bundle_data.get("bundle", {})
    series = bundle_info.get("series", "X")
    version = bundle_info.get("version", 1)

    stats["total"] = len(rules_list)

    for rule_dict in rules_list:
        rule_id = rule_dict.get("id", "")
        if not rule_id:
            stats["errors"].append("Rule missing 'id' field")
            continue

        # Resolve category
        category_id = None
        cat_name = rule_dict.get("category") or bundle_info.get("name")
        if cat_name:
            cat = db.query(Category).filter(
                Category.name == cat_name
            ).first()
            if not cat:
                # Try by label
                cat = db.query(Category).filter(
                    Category.label == cat_name
                ).first()
            if cat:
                category_id = cat.id

        stages = rule_dict.get("applicable_stages", ["input"])
        rule_type = "code_review" if "batch" in stages else "io"

        existing = db.query(RuleModel).filter(RuleModel.id == rule_id).first()
        detection_config = _detection_config_from_bundle_rule(rule_dict)

        if existing:
            existing.name = rule_dict.get("name", existing.name)
            existing.description = rule_dict.get("description", existing.description)
            existing.severity = rule_dict.get("severity", existing.severity)
            existing.action = rule_dict.get("action", existing.action)
            existing.category_id = category_id or existing.category_id
            existing.rule_type = rule_type
            existing.applicable_stages = stages
            existing.detection_config = detection_config
            existing.sdk_version = int(str(version).split(".")[0])
            if "enabled" in rule_dict:
                existing.enabled = rule_dict["enabled"]
            stats["updated"] += 1
        else:
            new_rule = RuleModel(
                id=rule_id,
                name=rule_dict.get("name", rule_id),
                description=rule_dict.get("description"),
                severity=rule_dict.get("severity", "P2"),
                action=rule_dict.get("action", "warn"),
                category_id=category_id,
                rule_type=rule_type,
                applicable_stages=stages,
                detection_config=detection_config,
                source="sdk",
                bundle_series=series,
                sdk_version=int(str(version).split(".")[0]),
                enabled=rule_dict.get("enabled", True),
            )
            db.add(new_rule)
            stats["created"] += 1

    db.commit()
    return stats


async def import_rules_from_file(db: DBSession, file: UploadFile) -> dict[str, Any]:
    """Import rules from an uploaded JSON file."""
    content = await file.read()
    try:
        bundle_data = json.loads(content)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON: {e}") from e

    return import_rules_from_bundle(db, bundle_data)


def export_rules_to_bundle(
    db: DBSession,
    *,
    series: str | None = None,
    category: str | None = None,
) -> dict[str, Any]:
    """Export rules as a bundle JSON dict.

    Args:
        db: Database session.
        series: Optional bundle series filter (I, O, SEC, IAC).
        category: Optional category name filter.

    Returns:
        A bundle dict compatible with the import format.
    """
    query = db.query(RuleModel)

    if series:
        query = query.filter(RuleModel.bundle_series == series)
    if category:
        cat = db.query(Category).filter(Category.name == category).first()
        if cat:
            query = query.filter(RuleModel.category_id == cat.id)

    rules = query.all()
    if not rules:
        return {"bundle": {"series": series or "ALL", "name": "Exported Rules", "version": "1", "total": 0}, "rules": []}

    # Determine series
    actual_series = series or (rules[0].bundle_series or "X")
    name_map = {"I": "Input Detection Rules", "O": "Output Detection Rules", "SEC": "Code Security Rules", "IAC": "Infrastructure as Code Rules"}

    bundle = {
        "bundle": {
            "series": actual_series,
            "name": name_map.get(actual_series, "Kasra Rules"),
            "version": str(max((r.sdk_version or 1) for r in rules)),
            "total": len(rules),
        },
        "rules": [],
    }

    for r in rules:
        cat_name = _resolve_category_name(db, r.category_id)
        rule_dict = {
            "id": r.id,
            "name": r.name,
            "severity": r.severity,
            "action": r.action,
            "applicable_stages": list(_parse_json_col(r.applicable_stages, ["input"])),
            "category": cat_name,
            "detection": _parse_json_col(r.detection_config, {}),
            "enabled": r.enabled,
        }
        if r.description:
            rule_dict["description"] = r.description
        bundle["rules"].append(rule_dict)

    return bundle
