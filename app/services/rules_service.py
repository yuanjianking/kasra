"""Rules service — manage rules (SDK built-in + custom user rules)."""

from __future__ import annotations

import json
import logging
from typing import Any

from sqlalchemy.orm import Session as DBSession

from app.models.rule_config import RuleConfig
from app.schemas.rules import RuleCreate, RuleSchema, RuleUpdate
from app.services.engine_service import engine_service

logger = logging.getLogger("kasra.service.rules")


def list_rules(
    db: DBSession,
    *,
    category: str | None = None,
    severity: str | None = None,
    enabled_only: bool | None = None,
    custom_only: bool | None = None,
    page: int = 1,
    page_size: int = 100,
) -> dict[str, Any]:
    """List rules from both SDK and custom DB records.

    Combines SDK built-in rules with user-created custom rules.
    """
    # 1. Load SDK rules (from engine)
    sdk_rules = engine_service.engine.get_rules()

    # 2. Load DB custom rules + overrides
    db_query = db.query(RuleConfig)
    if category:
        db_query = db_query.filter(RuleConfig.category == category)
    if severity:
        db_query = db_query.filter(RuleConfig.severity == severity)
    if enabled_only is not None:
        db_query = db_query.filter(RuleConfig.enabled == enabled_only)
    if custom_only:
        db_query = db_query.filter(RuleConfig.is_custom == True)

    db_rules = {r.id: r for r in db_query.all()}

    # 3. Merge: SDK rules first, then custom rules
    merged: list[RuleSchema] = []

    for rule in sdk_rules:
        db_override = db_rules.get(rule.id)
        merged.append(RuleSchema(
            id=rule.id,
            name=rule.name,
            description=rule.description,
            category=rule.category,
            severity=rule.severity.value if hasattr(rule.severity, "value") else str(rule.severity),
            action=rule.action.value if hasattr(rule.action, "value") else str(rule.action),
            pattern=None,
            enabled=db_override.enabled if db_override else rule.enabled,
            is_custom=False,
            source="sdk",
        ))

    # Add user custom rules
    for rid, r in db_rules.items():
        if r.is_custom:
            merged.append(RuleSchema(
                id=r.id,
                name=r.name,
                description=r.description,
                category=r.category,
                severity=r.severity,
                action=r.action,
                pattern=r.pattern,
                enabled=r.enabled,
                is_custom=True,
                source="user",
            ))

    # Apply filters
    if category:
        merged = [r for r in merged if r.category == category]
    if severity:
        merged = [r for r in merged if r.severity == severity]
    if enabled_only is not None:
        merged = [r for r in merged if r.enabled == enabled_only]

    total = len(merged)
    offset = (page - 1) * page_size
    page_items = merged[offset:offset + page_size]

    return {
        "items": page_items,
        "total": total,
        "page": page,
        "page_size": page_size,
    }


def get_rule(db: DBSession, rule_id: str) -> RuleSchema | None:
    """Get a single rule by ID (checks SDK rules + DB custom rules)."""
    # Check SDK rules
    try:
        sdk_rule = engine_service.engine.get_rule(rule_id)
        db_override = db.query(RuleConfig).filter(RuleConfig.id == rule_id).first()
        return RuleSchema(
            id=sdk_rule.id,
            name=sdk_rule.name,
            description=sdk_rule.description,
            category=sdk_rule.category,
            severity=sdk_rule.severity.value if hasattr(sdk_rule.severity, "value") else str(sdk_rule.severity),
            action=sdk_rule.action.value if hasattr(sdk_rule.action, "value") else str(sdk_rule.action),
            pattern=None,
            enabled=db_override.enabled if db_override else sdk_rule.enabled,
            is_custom=False,
            source="sdk",
        )
    except KeyError:
        pass

    # Check DB custom rules
    db_rule = db.query(RuleConfig).filter(RuleConfig.id == rule_id).first()
    if db_rule:
        return RuleSchema(
            id=db_rule.id,
            name=db_rule.name,
            description=db_rule.description,
            category=db_rule.category,
            severity=db_rule.severity,
            action=db_rule.action,
            pattern=db_rule.pattern,
            enabled=db_rule.enabled,
            is_custom=db_rule.is_custom,
            source="user",
        )

    return None


def create_rule(db: DBSession, rule: RuleCreate) -> RuleSchema:
    """Create a new custom rule (U-series)."""
    if not rule.id.startswith("U-"):
        raise ValueError("Custom rule IDs must start with U-")

    existing = db.query(RuleConfig).filter(RuleConfig.id == rule.id).first()
    if existing:
        raise ValueError(f"Rule {rule.id} already exists")

    db_rule = RuleConfig(
        id=rule.id,
        name=rule.name,
        description=rule.description,
        category=rule.category,
        severity=rule.severity,
        action=rule.action,
        pattern=rule.pattern,
        enabled=rule.enabled,
        is_custom=True,
        source="user",
        metadata={"created_via": "api"},
    )
    db.add(db_rule)
    db.commit()
    db.refresh(db_rule)

    return RuleSchema(
        id=db_rule.id,
        name=db_rule.name,
        description=db_rule.description,
        category=db_rule.category,
        severity=db_rule.severity,
        action=db_rule.action,
        pattern=db_rule.pattern,
        enabled=db_rule.enabled,
        is_custom=True,
        source="user",
    )


def update_rule(db: DBSession, rule_id: str, update: RuleUpdate) -> RuleSchema | None:
    """Update rule override (for SDK rules) or custom rule (for U-series)."""
    db_rule = db.query(RuleConfig).filter(RuleConfig.id == rule_id).first()

    if db_rule is None:
        # Create an override record for SDK rules
        if rule_id.startswith("U-"):
            return None  # U-series must be created first

        # Check if it's a valid SDK rule
        try:
            engine_service.engine.get_rule(rule_id)
        except KeyError:
            return None

        db_rule = RuleConfig(
            id=rule_id,
            name=update.name or rule_id,
            enabled=True,
            is_custom=False,
            source="sdk",
        )
        db.add(db_rule)

    # Apply updates
    if update.name is not None:
        db_rule.name = update.name
    if update.description is not None:
        db_rule.description = update.description
    if update.severity is not None:
        db_rule.severity = update.severity
    if update.action is not None:
        db_rule.action = update.action
    if update.pattern is not None:
        db_rule.pattern = update.pattern
    if update.enabled is not None:
        db_rule.enabled = update.enabled

    db.commit()
    db.refresh(db_rule)

    return RuleSchema(
        id=db_rule.id,
        name=db_rule.name,
        description=db_rule.description,
        category=db_rule.category,
        severity=db_rule.severity,
        action=db_rule.action,
        pattern=db_rule.pattern,
        enabled=db_rule.enabled,
        is_custom=db_rule.is_custom,
        source=db_rule.source,
    )


def delete_rule(db: DBSession, rule_id: str) -> bool:
    """Delete a custom rule or reset an SDK rule override."""
    db_rule = db.query(RuleConfig).filter(RuleConfig.id == rule_id).first()
    if db_rule is None:
        return False

    db.delete(db_rule)
    db.commit()
    return True
