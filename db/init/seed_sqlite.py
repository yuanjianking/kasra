#!/usr/bin/env python3
"""Kasra — SQLite seed data script.

Called by the migrate.sh seed command to insert initial data for SQLite.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta

# Ensure the app module is findable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from app.database import SessionLocal, init_db
from app.models.rule_config import RuleConfig
from app.models.user import User
from app.models.audit_log import AuditLog


def seed():
    """Insert seed data for development/demo."""
    init_db()
    db = SessionLocal()

    try:
        # ── 1. Create default users ──
        if not db.query(User).filter(User.username == "admin").first():
            db.add(User(
                username="admin",
                email="admin@kasra.security",
                role="admin",
                is_active=True,
            ))
            print("  ✓ Created admin user")

        if not db.query(User).filter(User.username == "demo-user").first():
            db.add(User(
                username="demo-user",
                email="demo@example.com",
                role="user",
                is_active=True,
            ))
            print("  ✓ Created demo-user user")

        # ── 2. Register built-in rule snapshots ──
        sdk_rules = [
            ("I-01", "GitHub Token", "credential_leak", "P0", "block"),
            ("I-02", "OpenAI API Key", "credential_leak", "P0", "block"),
            ("I-03", "Anthropic API Key", "credential_leak", "P0", "block"),
            ("I-04", "AWS Access Key", "credential_leak", "P0", "block"),
            ("I-05", "Generic Password/Secret", "credential_leak", "P0", "block"),
            ("I-06", "Private Key/PEM Certificate", "credential_leak", "P0", "block"),
            ("I-08", "China Phone Number", "pii", "P1", "redact"),
            ("I-09", "China National ID", "pii", "P1", "redact"),
            ("I-10", "Email Address", "pii", "P1", "redact"),
            ("I-11", "Prompt Injection Attack", "injection", "P0", "block"),
            ("I-12", "Jailbreak/Role-Play Attack", "injection", "P0", "block"),
            ("O-01", "Dangerous Function Call", "code_security", "P0", "warn"),
            ("O-02", "Dangerous Shell Command", "code_security", "P0", "block"),
            ("O-03", "Credential Leak", "credential_leak", "P0", "block"),
            ("O-04", "SQL Injection", "code_security", "P2", "warn"),
            ("SEC-01", "Hardcoded Secret", "credential_leak", "P0", "warn"),
            ("SEC-05", "SQL Injection", "injection", "P0", "warn"),
            ("SEC-06", "Path Traversal", "injection", "P0", "warn"),
            ("SEC-12", "XSS Risk", "injection", "P0", "warn"),
            ("IAC-01", "Dockerfile Security", "iac", "P1", "warn"),
            ("IAC-02", "K8s Security Config", "iac", "P1", "warn"),
            ("ARCH-01", "Circular Dependency", "architecture", "P2", "warn"),
            ("B-01", "Late Night Anomaly", "behavior", "P1", "warn"),
            ("B-02", "Repeated Rule Trigger", "behavior", "P1", "warn"),
            ("B-03", "Jailbreak Attempt", "behavior", "P0", "block"),
            ("C-01", "PII Compliance", "compliance", "P1", "warn"),
            ("C-02", "Open Source License Compliance", "compliance", "P1", "warn"),
        ]

        rule_count = 0
        for rule_id, name, category, severity, action in sdk_rules:
            existing = db.query(RuleConfig).filter(RuleConfig.id == rule_id).first()
            if not existing:
                db.add(RuleConfig(
                    id=rule_id,
                    name=name,
                    category=category,
                    severity=severity,
                    action=action,
                    enabled=True,
                    is_custom=False,
                    source="sdk",
                ))
                rule_count += 1

        if rule_count > 0:
            print(f"  ✓ Registered {rule_count} built-in rules")

        # ── 3. Insert sample audit logs (only if empty) ──
        if db.query(AuditLog).count() == 0:
            now = datetime.utcnow()
            logs = [
                AuditLog(timestamp=now - timedelta(hours=2), user_id="demo-user", session_id="sess_001",
                         rule_id="I-05", rule_name="Generic Password/Secret", severity="P0", action="block",
                         direction="input", matched_text="password=admin123", match_count=1, status="resolved"),
                AuditLog(timestamp=now - timedelta(hours=1), user_id="demo-user", session_id="sess_002",
                         rule_id="O-01", rule_name="Dangerous Function Call", severity="P0", action="warn",
                         direction="output", matched_text="eval(request.body)", match_count=1, status="pending"),
                AuditLog(timestamp=now - timedelta(minutes=30), user_id="demo-user", session_id="sess_003",
                         rule_id="I-11", rule_name="Prompt Injection Attack", severity="P0", action="block",
                         direction="input", matched_text="ignore all previous instructions", match_count=1, status="pending"),
                AuditLog(timestamp=now - timedelta(minutes=15), user_id="admin", session_id="sess_004",
                         rule_id="SEC-05", rule_name="SQL Injection", severity="P0", action="warn",
                         direction="batch", matched_text='cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
                         match_count=1, status="fp"),
                AuditLog(timestamp=now - timedelta(minutes=5), user_id="demo-user", session_id="sess_001",
                         rule_id="B-01", rule_name="Late Night Anomaly", severity="P1", action="warn",
                         direction="behavior", match_count=0, status="pending"),
                AuditLog(timestamp=now, user_id="demo-user", session_id="sess_005",
                         rule_id="O-02", rule_name="Dangerous Shell Command", severity="P0", action="block",
                         direction="output", matched_text='subprocess.call("rm -rf /", shell=True)',
                         match_count=1, status="pending"),
            ]
            for log in logs:
                db.add(log)
            print("  ✓ Inserted 6 sample audit logs")

        db.commit()
        print("\n✅ Seed data initialized successfully!")

    except Exception as e:
        db.rollback()
        print(f"\n❌ Seed data initialization failed: {e}")
        raise
    finally:
        db.close()


if __name__ == "__main__":
    seed()
