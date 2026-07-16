"""Integration test fixtures — shared across all integration test suites.

Optimised for speed: tables created once per session, data cleaned per function.
"""
from __future__ import annotations

import logging
import os
import tempfile
from typing import Generator

import pytest
from fastapi.testclient import TestClient

# Create a temporary database file for testing
_test_db_fd, _test_db_path = tempfile.mkstemp(suffix="_kasra_integration_test.db")

# Override settings BEFORE importing app modules — also skip heavy services
os.environ["KASRA_APP_DATABASE_URL"] = f"sqlite:///{_test_db_path}"
os.environ["KASRA_APP_API_KEY"] = "integration-test-api-key"
os.environ["KASRA_SKIP_FRONTEND"] = "true"
os.environ["KASRA_SKIP_MCP"] = "true"
os.environ["KASRA_APP_HTTPS_PROXY_ENABLED"] = "false"
os.environ["KASRA_APP_SEED_DATA"] = "false"

from app.database import Base, engine
from app.services.engine_service import engine_service

# Import models so Base.metadata knows about them
from app.models.audit_log import AuditLog  # noqa: F401
from app.models.audit_chain import AuditChain  # noqa: F401
from app.models.rule_config import Rule  # noqa: F401
from app.models.custom_rule import CustomRule  # noqa: F401
from app.models.dictionary import Dictionary  # noqa: F401
from app.models.user import User  # noqa: F401
from app.models.user_behavior import UserBehavior  # noqa: F401

# Suppress app logging during tests
logging.getLogger("kasra").setLevel(logging.CRITICAL)


@pytest.fixture(scope="session", autouse=True)
def _setup_db():
    """Create all tables once per test session."""
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)
    try:
        os.unlink(_test_db_path)
    except OSError:
        pass


def _clear_tables():
    """Delete all rows from all tables (much faster than drop/create)."""
    from sqlalchemy import text
    with engine.begin() as conn:
        conn.execute(text("PRAGMA foreign_keys=OFF"))
        for table in reversed(Base.metadata.sorted_tables):
            conn.execute(table.delete())
        conn.execute(text("PRAGMA foreign_keys=ON"))


@pytest.fixture(scope="function")
def client() -> Generator[TestClient, None, None]:
    """Test client with clean database and freshly initialised engine."""
    from app.main import create_app

    _clear_tables()

    # Fresh engine per test so rule state never leaks
    if engine_service.is_initialized:
        engine_service.shutdown()
    engine_service.initialize()

    # Seed SDK rules from DML and load into engine
    from app.database import SessionLocal, init_db
    from app.db_migration import seed_sdk_rules_from_dml
    init_db()
    seed_sdk_rules_from_dml()
    load_db = SessionLocal()

    # Seed dictionaries for rules that use dictionary refs
    from app.models.dictionary import Dictionary
    from sqlalchemy import text
    I_CAT = load_db.execute(text("SELECT id FROM categories WHERE name = 'I'")).scalar()
    O_CAT = load_db.execute(text("SELECT id FROM categories WHERE name = 'O'")).scalar()
    SEC_CAT = load_db.execute(text("SELECT id FROM categories WHERE name = 'SEC'")).scalar()
    dict_seeds = [
        ('pi_override_verbs', ['ignore','disregard','forget','override','overwrite','skip','bypass','无视','忽略'], I_CAT),
        ('pi_jailbreak_names', ['DAN','STAN','Jailbreak','developer mode','unrestricted mode','no filter','god mode'], I_CAT),
        ('pi_output_verbs', ['repeat','reveal','show','display','print','output','write','copy','paste','return','extract','复述','重复','输出'], I_CAT),
        ('context_reset_verbs', ['forget','ignore','clear','reset','erase','remove','delete','discard','abandon','清除','重置','忽略','删除','清空'], I_CAT),
        ('context_reset_nouns', ['history','context','conversation','messages','chat','memory','session','过去的','上下文','历史','对话'], I_CAT),
        ('gdpr_health', ['diagnosis','medical','patient','clinical','糖尿病','肿瘤','癌症','患者','诊断','治疗'], I_CAT),
        ('gdpr_biometric', ['fingerprint','biometric','face_recognition','iris_scan','dna','gene'], I_CAT),
        ('name_indicators', ['name','full_name','联系人','姓名','Best','Sincerely','此致','敬礼'], I_CAT),
        ('se_authority_titles', ['CEO','CTO','CIO','security','auditor','compliance','manager','director','VP','president','admin','管理员','老板','经理'], I_CAT),
        ('se_urgency_phrases', ['emergency','urgent','immediately','critical','ASAP','紧急','立刻','马上'], I_CAT),
        ('bypass_action_verbs', ['bypass','disable','deactivate','turn off','shut down','stop','override','绕过','关闭','禁用','取消'], I_CAT),
        ('bypass_target_nouns', ['proxy','gateway','firewall','security gateway','content filter','代理','限制','过滤'], I_CAT),
        ('pi_system_nouns', ['system prompt','system instructions','initial prompt','base prompt','core instructions'], I_CAT),
        ('pi_jailbreak_pretend', ['you are now','act as if','pretend to be','从今以后','你现在是'], I_CAT),
        ('harmful_weapon_terms', ['bomb','explosive','weapon','drug','narcotic','poison','toxin','chemical weapon','bioweapon'], O_CAT),
        ('harmful_self_harm', ['suicide','self-harm','self injury'], O_CAT),
        ('harmful_child_safety', ['child porn','child exploit','child abuse','CSAM'], O_CAT),
        ('harmful_create_verbs', ['make','build','create','manufacture','synthesize','commit','perform','carry out'], O_CAT),
        ('weaponized_c2_malware', ['C2 server','backdoor','remote access trojan','RAT server','DDoS','botnet','rootkit','cryptominer'], O_CAT),
        ('weak_passwords', ['password123','admin123','test123','P@ssw0rd','letmein','welcome','changeme','qwerty','abc123','default'], SEC_CAT),
        ('default_usernames', ['admin','root','test','guest','sa'], SEC_CAT),
        ('file_access_verbs', ['read','open','view','get','fetch','show','display','dump','cat','less','more'], I_CAT),
        ('file_access_nouns', ['file','document','config','configuration','settings','content'], I_CAT),
        ('archive_verbs', ['extract','unzip','untar','decompress','expand'], I_CAT),
        ('internal_network_labels', ['internal','private','corp','intranet','local'], I_CAT),
    ]
    for code, entries, cat_id in dict_seeds:
        existing = load_db.query(Dictionary).filter(Dictionary.code == code).first()
        if not existing:
            d = Dictionary(code=code, name=code, entries=entries, category_id=cat_id, is_active=True)
            load_db.add(d)
    load_db.commit()

    engine_service.reload_rules_from_db(load_db)
    load_db.close()

    app = create_app()

    with TestClient(app) as c:
        yield c

    if engine_service.is_initialized:
        engine_service.shutdown()


@pytest.fixture(scope="function")
def auth_headers() -> dict[str, str]:
    """Default auth headers for integration tests."""
    return {"X-API-Key": "integration-test-api-key"}
