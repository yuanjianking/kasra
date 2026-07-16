"""Kasra ORM models — all models are imported here for Base.metadata awareness."""
from app.models.audit_log import AuditLog  # noqa: F401
from app.models.audit_chain import AuditChain  # noqa: F401
from app.models.category import Category  # noqa: F401
from app.models.custom_rule import CustomRule  # noqa: F401
from app.models.dictionary import Dictionary  # noqa: F401
from app.models.pattern_type import PatternType  # noqa: F401
from app.models.rule_config import Rule  # noqa: F401
from app.models.user import User  # noqa: F401
from app.models.user_behavior import UserBehavior  # noqa: F401
