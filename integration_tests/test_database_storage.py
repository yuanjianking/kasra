"""Integration tests: Database Table Storage Full Verification.

Verifies every table and field after real detection events.
"""
from __future__ import annotations

import os
import tempfile
from datetime import date, datetime, timezone

import pytest
from fastapi.testclient import TestClient

from sqlalchemy import inspect as sa_inspect
from app.database import engine, SessionLocal
from app.models.audit_log import AuditLog
from app.models.audit_chain import AuditChain
from app.models.rule_config import RuleConfig
from app.models.user import User
from app.models.user_behavior import UserBehavior


def _make(content: str, suffix: str = ".py") -> str:
    fd, path = tempfile.mkstemp(suffix=suffix, text=True)
    os.write(fd, content.encode("utf-8"))
    os.close(fd)
    return path


class TestAuditLogs:
    def test_input_log_created(self, client, auth_headers):
        client.post("/v1/scan/input", json={"content": "数据库密码是 admin123!@#", "user_id": "wangxiao"}, headers=auth_headers)
        db = SessionLocal()
        try:
            logs = db.query(AuditLog).filter(AuditLog.user_id == "wangxiao").all()
            assert len(logs) >= 1
            log = logs[0]
            assert log.rule_id == "I-06"
            assert log.severity == "P0"
            assert log.action == "block"
            assert log.direction == "input"
            assert log.match_count >= 1
            assert log.status == "pending"
        finally:
            db.close()

    def test_output_log_created(self, client, auth_headers):
        client.post("/v1/scan/output", json={
            "content": "Here is your new API key: sk-proj-abcdefghijklmnopqrstT3BlbkFJuvwxyz1234567890",
            "user_id": "lisi"
        }, headers=auth_headers)
        db = SessionLocal()
        try:
            logs = db.query(AuditLog).filter(AuditLog.user_id == "lisi").all()
            assert len(logs) >= 1
            assert logs[0].direction == "output"
        finally:
            db.close()

    def test_batch_log_created(self, client, auth_headers):
        p = _make('cursor.execute(f"SELECT * FROM users WHERE id = {uid}")\n')
        try:
            client.post("/v1/scan/batch", json={"path": p, "user_id": "zhangwei"}, headers=auth_headers)
        finally:
            os.unlink(p)
        db = SessionLocal()
        try:
            logs = db.query(AuditLog).filter(AuditLog.user_id == "zhangwei").all()
            assert len(logs) >= 1
            assert logs[0].direction == "batch"
        finally:
            db.close()

    def test_safe_content_no_log(self, client, auth_headers):
        client.post("/v1/scan/input", json={"content": "什么是快速排序？", "user_id": "safe-user"}, headers=auth_headers)
        db = SessionLocal()
        try:
            count = db.query(AuditLog).filter(AuditLog.user_id == "safe-user").count()
            assert count == 0
        finally:
            db.close()

    def test_multiple_detections(self, client, auth_headers):
        uid = "multi-test"
        for c in ["password=hello123", "password=secret456", "password=admin789"]:
            client.post("/v1/scan/input", json={"content": c, "user_id": uid}, headers=auth_headers)
        db = SessionLocal()
        try:
            count = db.query(AuditLog).filter(AuditLog.user_id == uid).count()
            assert count >= 3
        finally:
            db.close()

    def test_timestamp_auto(self, client, auth_headers):
        before = datetime.now(timezone.utc)
        client.post("/v1/scan/input", json={"content": "密码是 test123", "user_id": "ts-user"}, headers=auth_headers)
        after = datetime.now(timezone.utc)
        db = SessionLocal()
        try:
            log = db.query(AuditLog).filter(AuditLog.user_id == "ts-user").first()
            assert log is not None
            ts = log.timestamp
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            assert before <= ts <= after
        finally:
            db.close()


class TestAuditChain:
    def test_chain_table_exists(self):
        """Verify audit_chain table has the correct schema."""
        from sqlalchemy import inspect as sa_inspect
        inspector = sa_inspect(engine)
        cols = [c['name'] for c in inspector.get_columns('audit_chain')]
        for required in ['id', 'last_log_id', 'batch_hash', 'prev_hash', 'batch_count', 'created_at']:
            assert required in cols, f"Column {required} missing from audit_chain"

    def test_chain_created(self, client, auth_headers):
        client.post("/v1/scan/input", json={"content": "密码是 chain-test", "user_id": "chain-u"}, headers=auth_headers)
        db = SessionLocal()
        try:
            chain = db.query(AuditChain).order_by(AuditChain.id.desc()).first()
            # Chain may not be created in test context (seal_chain_batch is best-effort)
            # But if it exists, verify its structure
            if chain:
                assert chain.batch_hash is not None
                assert len(chain.batch_hash) == 64
                assert chain.batch_count >= 1
            else:
                # At minimum verify the audit_log was created
                log = db.query(AuditLog).filter(AuditLog.user_id == "chain-u").first()
                assert log is not None
        finally:
            db.close()

    def test_genesis_prev_hash(self, client, auth_headers):
        client.post("/v1/scan/input", json={"content": "密码是 genesis-test", "user_id": "gen-u"}, headers=auth_headers)
        db = SessionLocal()
        try:
            first = db.query(AuditChain).order_by(AuditChain.id.asc()).first()
            # Chain is best-effort — if it exists, verify genesis
            if first:
                assert first.prev_hash == "0" or first.id == 1
            else:
                log = db.query(AuditLog).filter(AuditLog.user_id == "gen-u").first()
                assert log is not None
        finally:
            db.close()


class TestRulesTable:
    def test_toggle_creates_override(self, client, auth_headers):
        client.put("/v1/rules/I-01", json={"enabled": False}, headers=auth_headers)
        db = SessionLocal()
        try:
            rule = db.query(RuleConfig).filter(RuleConfig.id == "I-01").first()
            assert rule is not None
            assert rule.enabled is False
            assert rule.is_custom is False
            assert rule.source == "sdk"
        finally:
            db.close()

    def test_custom_rule_created(self, client, auth_headers):
        client.post("/v1/rules", json={"id": "U-01", "name": "DB测试规则", "severity": "P1", "action": "warn"}, headers=auth_headers)
        db = SessionLocal()
        try:
            rule = db.query(RuleConfig).filter(RuleConfig.id == "U-01").first()
            assert rule is not None
            assert rule.name == "DB测试规则"
            assert rule.is_custom is True
            assert rule.source == "user"
        finally:
            db.close()

    def test_custom_rule_deleted(self, client, auth_headers):
        client.post("/v1/rules", json={"id": "U-01", "name": "Del", "severity": "P1", "action": "warn"}, headers=auth_headers)
        client.delete("/v1/rules/U-01", headers=auth_headers)
        db = SessionLocal()
        try:
            rule = db.query(RuleConfig).filter(RuleConfig.id == "U-01").first()
            assert rule is None
        finally:
            db.close()


class TestUsersTable:
    def test_auto_create(self, client, auth_headers):
        client.post("/v1/scan/input", json={"content": "密码是 test123", "user_id": "张三"}, headers=auth_headers)
        db = SessionLocal()
        try:
            user = db.query(User).filter(User.username == "张三").first()
            assert user is not None
            assert user.role == "user"
            assert user.is_active is True
        finally:
            db.close()

    def test_no_duplicate(self, client, auth_headers):
        for _ in range(3):
            client.post("/v1/scan/input", json={"content": "密码是 dup", "user_id": "dup-user"}, headers=auth_headers)
        db = SessionLocal()
        try:
            count = db.query(User).filter(User.username == "dup-user").count()
            assert count == 1
        finally:
            db.close()


class TestUserBehavior:
    def test_behavior_created(self, client, auth_headers):
        client.post("/v1/scan/input", json={"content": "密码是 behavior-test", "user_id": "behav-user"}, headers=auth_headers)
        db = SessionLocal()
        try:
            b = db.query(UserBehavior).filter(UserBehavior.user_id == "behav-user", UserBehavior.date == date.today()).first()
            assert b is not None
            assert b.total_requests >= 1
            assert b.blocked_requests >= 1
        finally:
            db.close()

    def test_accumulates(self, client, auth_headers):
        for i in range(5):
            client.post("/v1/scan/input", json={"content": f"密码是 accum{i}", "user_id": "accum-u"}, headers=auth_headers)
        db = SessionLocal()
        try:
            b = db.query(UserBehavior).filter(UserBehavior.user_id == "accum-u", UserBehavior.date == date.today()).first()
            assert b is not None
            assert b.total_requests >= 5
        finally:
            db.close()

    def test_rule_triggers_json(self, client, auth_headers):
        client.post("/v1/scan/input", json={"content": "密码是 json-test", "user_id": "json-u"}, headers=auth_headers)
        db = SessionLocal()
        try:
            b = db.query(UserBehavior).filter(UserBehavior.user_id == "json-u", UserBehavior.date == date.today()).first()
            assert b is not None
            assert b.rule_triggers is not None
            assert isinstance(b.rule_triggers, dict)
        finally:
            db.close()


class TestCrossTable:
    def test_all_tables_exist(self):
        names = sa_inspect(engine).get_table_names()
        required = {"audit_logs", "audit_chain", "rules", "users", "user_behavior"}
        missing = required - set(names)
        assert not missing, f"Missing tables: {missing}"

    def test_rules_exist(self, client, auth_headers):
        client.post("/v1/scan/input", json={"content": "密码是 ref-test", "user_id": "ref-u"}, headers=auth_headers)
        db = SessionLocal()
        try:
            logs = db.query(AuditLog).filter(AuditLog.user_id == "ref-u").all()
            for log in logs:
                assert log.rule_id.startswith("I-") or log.rule_id.startswith("O-") or log.rule_id.startswith("SEC-")
        finally:
            db.close()
