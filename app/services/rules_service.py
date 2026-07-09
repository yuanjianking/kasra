"""Rules service — manage rules (SDK built-in + custom user rules)."""

from __future__ import annotations

import json
import logging
from typing import Any

from sqlalchemy.orm import Session as DBSession

from kasra.exceptions import RuleNotFoundError

from app.models.rule_config import RuleConfig
from app.schemas.rules import RuleCreate, RuleSchema, RuleUpdate
from app.services.engine_service import engine_service

logger = logging.getLogger("kasra.service.rules")


def sync_disabled_rules_from_db(db: DBSession) -> None:
    """Sync disabled rule states from the database to the in-memory engine.

    Called once at startup after ``engine_service.initialize()`` so that
    rules previously disabled via the frontend remain disabled across restarts.

    Handles both I/O rules (I-xx, O-xx → ``engine.disable_rule()``) and
    code review rules (SEC-xx, IAC-xx → ``engine.disable_code_review_rule()``).
    """
    engine = engine_service.engine

    # Query all DB override records where the user explicitly disabled a rule
    disabled_records = db.query(RuleConfig).filter(
        RuleConfig.enabled == False,  # noqa: E712
        RuleConfig.is_custom == False,
    ).all()

    if not disabled_records:
        return

    # Pre-warm the code review scanner so its disabled_rule_ids set exists
    try:
        engine.get_code_review_rules()
    except Exception:
        pass

    io_count = 0
    cr_count = 0

    for record in disabled_records:
        rule_id = record.id
        group = _rule_group(rule_id)

        try:
            if group == "code_review":
                engine.disable_code_review_rule(rule_id)
                cr_count += 1
            else:
                engine.disable_rule(rule_id)
                io_count += 1
        except (RuleNotFoundError, ValueError):
            # Rule may have been removed from the SDK — skip silently
            pass

    if cr_count or io_count:
        logger.info(
            "Synced disabled state from DB: %d I/O rules, %d code review rules",
            io_count, cr_count,
        )


def _rule_group(rule_id: str) -> str:
    """Determine the display group of a rule from its ID.

    Returns ``"input"``, ``"output"``, or ``"code_review"``.
    """
    prefix = rule_id.split("-", 1)[0] if "-" in rule_id else rule_id
    if prefix == "I":
        return "input"
    if prefix == "O":
        return "output"
    # SEC, IAC, ARCH — all code review rules
    return "code_review"


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
    """List rules from both SDK and custom DB records.

    Combines SDK built-in rules with user-created custom rules.
    """
    # 1. Load SDK rules (from engine)
    sdk_rules = engine_service.engine.get_rules()

    # 2. Load DB custom rules + overrides
    # NOTE: category/severity/enabled filters are applied in-memory below
    # to ensure SDK rules are also filtered consistently.
    db_query = db.query(RuleConfig)
    if custom_only:
        db_query = db_query.filter(RuleConfig.is_custom == True)

    db_rules = {r.id: r for r in db_query.all()}

    # 3. Merge: SDK I/O rules + scanner rules + custom rules
    merged: list[RuleSchema] = []

    for rule in sdk_rules:
        db_override = db_rules.get(rule.id)
        merged.append(RuleSchema(
            id=rule.id,
            name=rule.name,
            description=rule.description,
            category=rule.category,
            severity=str(rule.severity.value) if hasattr(rule.severity, "value") else str(rule.severity),
            action=str(rule.action.value) if hasattr(rule.action, "value") else str(rule.action),
            pattern=None,
            enabled=db_override.enabled if db_override else rule.enabled,
            is_custom=False,
            source="sdk",
            group=_rule_group(rule.id),
        ))

    # 3b. Add scanner rules (SEC and IAC series) — loaded from the SDK's
    #     get_code_review_rules() which reads _code-review-rules.json.
    #     These rules run during review_code().
    try:
        for _r in engine_service.engine.get_code_review_rules():
            _rid = _r.get("id", "")
            if not _rid:
                continue
            db_override = db_rules.get(_rid)
            disabled_ids = engine_service.engine.disabled_code_review_rule_ids
            merged.append(RuleSchema(
                id=_rid,
                name=_r.get("name", _rid),
                description=_r.get("description", ""),
                category=_r.get("category", "code_security"),
                severity=_r.get("severity", "P1"),
                action=_r.get("action", "warn"),
                pattern=None,
                enabled=db_override.enabled if db_override else (_rid not in disabled_ids),
                is_custom=False,
                source="sdk",
                group=_rule_group(_rid),
            ))
    except Exception:
        pass

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
                group=_rule_group(r.id),
            ))

    # Apply filters
    if category:
        merged = [r for r in merged if r.category == category]
    if custom_only:
        merged = [r for r in merged if r.is_custom]
    if severity:
        merged = [r for r in merged if r.severity == severity]
    if enabled_only is not None:
        merged = [r for r in merged if r.enabled == enabled_only]
    if group:
        merged = [r for r in merged if _rule_group(r.id) == group]

    # Sort by ID for consistent ordering
    merged.sort(key=lambda r: r.id)

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
            group=_rule_group(rule_id),
        )
    except (KeyError, RuleNotFoundError):
        pass

    # Check scanner rules (SEC/IAC series) — via engine.get_code_review_rules()
    try:
        for _r in engine_service.engine.get_code_review_rules():
            if _r.get("id") == rule_id:
                db_override = db.query(RuleConfig).filter(RuleConfig.id == rule_id).first()
                disabled_ids = engine_service.engine.disabled_code_review_rule_ids
                return RuleSchema(
                    id=_r["id"],
                    name=_r.get("name", rule_id),
                    description=_r.get("description", ""),
                    category=_r.get("category", "code_security"),
                    severity=_r.get("severity", "P1"),
                    action=_r.get("action", "warn"),
                    pattern=None,
                    enabled=db_override.enabled if db_override else (rule_id not in disabled_ids),
                    is_custom=False,
                    source="sdk",
                    group=_rule_group(rule_id),
                )
    except Exception:
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
            group=_rule_group(rule_id),
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
    """Update rule override (for SDK rules) or custom rule (for U-series).

    When toggling ``enabled`` on an SDK rule, the change is pushed to the
    live RuleEngine in-memory immediately — no restart needed.
    """
    db_rule = db.query(RuleConfig).filter(RuleConfig.id == rule_id).first()

    if db_rule is None:
        # Create an override record for SDK rules
        if rule_id.startswith("U-"):
            return None  # U-series must be created first

        # Check if it's a valid SDK rule
        is_valid = False
        try:
            engine_service.engine.get_rule(rule_id)
            is_valid = True
        except (KeyError, RuleNotFoundError):
            pass

        # Also check scanner rules (SEC series) via the engine's code review rule IDs
        if not is_valid:
            try:
                if rule_id in engine_service.engine.get_code_review_rule_ids():
                    is_valid = True
            except Exception:
                pass

        if not is_valid:
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

    # ── Sync enabled state to live SDK engine ────────────────────────────
    # Without this, toggling a rule in the frontend writes to DB but the
    # in-memory SDK engine still uses the old value.
    #
    # Two categories of rules:
    #   I/O rules (I-xx, O-xx)  → engine.enable_rule / disable_rule
    #   Code review rules (SEC-xx, IAC-xx) → engine.enable_code_review_rule / disable_code_review_rule
    if update.enabled is not None:
        engine = engine_service.engine
        try:
            if db_rule.enabled:
                engine.enable_rule(rule_id)
            else:
                engine.disable_rule(rule_id)
            logger.debug("Synced I/O rule %s enabled=%s", rule_id, db_rule.enabled)
        except RuleNotFoundError:
            # Not an I/O rule — try code review rule methods
            try:
                if db_rule.enabled:
                    engine.enable_code_review_rule(rule_id)
                else:
                    engine.disable_code_review_rule(rule_id)
                logger.debug("Synced code review rule %s enabled=%s", rule_id, db_rule.enabled)
            except ValueError:
                pass  # Not a code review rule either (U-series custom rule)

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
