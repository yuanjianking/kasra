"""Test fixtures for Kasra App tests."""
from __future__ import annotations

import logging
import os
import tempfile
from typing import Generator

import pytest
from fastapi.testclient import TestClient

# Create a temporary database file for testing
_test_db_fd, _test_db_path = tempfile.mkstemp(suffix="_kasra_test.db")

# Override settings for testing BEFORE importing app modules
os.environ["KASRA_APP_DATABASE_URL"] = f"sqlite:///{_test_db_path}"
os.environ["KASRA_APP_API_KEY"] = "test-api-key"
os.environ["KASRA_APP_SEED_DATA"] = "false"
os.environ["KASRA_SKIP_FRONTEND"] = "true"
os.environ["KASRA_SKIP_MCP"] = "true"
os.environ["KASRA_APP_HTTPS_PROXY_ENABLED"] = "false"

from app.database import Base, engine, init_db
from app.services.engine_service import engine_service

# Import ALL models so Base.metadata knows about them
from app.models import (  # noqa: F401
    AuditLog, AuditChain, Category, CustomRule,
    Dictionary, PatternType, Rule, User, UserBehavior,
)

# Suppress app logging during tests
logging.getLogger("kasra").setLevel(logging.CRITICAL)


@pytest.fixture(scope="function")
def client() -> Generator[TestClient, None, None]:
    """Test client with clean database per test."""
    if engine_service.is_initialized:
        engine_service.shutdown()
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    # Seed master data + rules
    from app.db_migration import seed_sdk_rules_from_dml
    from app.models import Category, PatternType
    from app.database import SessionLocal
    from sqlalchemy import text

    # Seed categories and pattern types directly
    db = SessionLocal()
    for name, label, desc, color in [
        ('I', 'Input Detection', 'Input detection rules', '#ef4444'),
        ('O', 'Output Detection', 'Output detection rules', '#f97316'),
        ('SEC', 'Code Security', 'Code review security rules', '#8b5cf6'),
        ('IAC', 'Infrastructure as Code', 'IAC misconfiguration rules', '#06b6d4'),
        ('BEHAVIOR', 'Behavior Monitoring', 'Behavior monitoring rules', '#ec4899'),
    ]:
        db.execute(text("INSERT OR IGNORE INTO categories (name, label, description, color) VALUES (:n, :l, :d, :c)"),
                   {'n': name, 'l': label, 'd': desc, 'c': color})
    for name, label, desc in [
        ('regex', 'Regex Match', 'Regex matching'),
        ('keyword', 'Keyword Match', 'Keyword matching'),
        ('dictionary', 'Dictionary Match', 'Dictionary matching'),
        ('yaml_path', 'YAML Path Match', 'YAML path matching'),
        ('dockerfile', 'Dockerfile Match', 'Dockerfile matching'),
        ('keyvalue', 'Key-Value Match', 'Key-value matching'),
    ]:
        db.execute(text("INSERT OR IGNORE INTO pattern_types (name, label, description) VALUES (:n, :l, :d)"),
                   {'n': name, 'l': label, 'd': desc})
    db.commit()

    seed_sdk_rules_from_dml()

    # Seed dictionaries (for rules that use dictionary refs)
    from app.models.dictionary import Dictionary
    import json
    I_CAT = db.execute(text("SELECT id FROM categories WHERE name = 'I'")).scalar()
    O_CAT = db.execute(text("SELECT id FROM categories WHERE name = 'O'")).scalar()
    SEC_CAT = db.execute(text("SELECT id FROM categories WHERE name = 'SEC'")).scalar()
    dictionary_seeds = [
        ('gdpr_health', 'GDPR Health Data', ['diagnosis','medical','patient','clinical','症状','疾病','诊断','糖尿病','患者','病人'], I_CAT),
        ('gdpr_biometric', 'GDPR Biometric', ['fingerprint','biometric','face_recognition','iris_scan','dna','gene','genetic'], I_CAT),
        ('name_indicators', 'Person Names', ['name','full_name','联系人','姓名','Best','Sincerely','此致','敬礼'], I_CAT),
        ('pi_override_verbs', 'PI Override Verbs', ['ignore','disregard','forget','override','overwrite','skip','bypass','无视','忽略'], I_CAT),
        ('pi_instruction_nouns', 'PI Instruction Nouns', ['instructions','directives','rules','prompts','constraints','限制','指令','规则'], I_CAT),
        ('pi_jailbreak_names', 'PI Jailbreak Names', ['DAN','STAN','Jailbreak','developer mode','unrestricted mode','no filter','god mode'], I_CAT),
        ('pi_jailbreak_pretend', 'PI Role-Play', ['you are now','act as if','pretend to be','从今以后','你现在是'], I_CAT),
        ('pi_output_verbs', 'PI Output Verbs', ['repeat','reveal','show','display','print','output','write','copy','paste','return','extract','start','begin','initialize','复述','重复','输出'], I_CAT),
        ('pi_system_nouns', 'PI System Nouns', ['system prompt','system instructions','initial prompt','base prompt','core instructions','original prompt'], I_CAT),
        ('context_reset_verbs', 'Context Reset Verbs', ['forget','ignore','clear','reset','erase','remove','delete','discard','abandon','restart','清除','重置','忽略','删除','清空'], I_CAT),
        ('context_reset_nouns', 'Context Reset Nouns', ['history','context','conversation','messages','chat','memory','session','过去的','上下文','历史','对话'], I_CAT),
        ('se_authority_titles', 'SE Authority Titles', ['CEO','CTO','CIO','security','auditor','compliance','manager','director','VP','president','admin','管理员','老板','经理'], I_CAT),
        ('se_urgency_phrases', 'SE Urgency', ['emergency','urgent','immediately','critical','ASAP','紧急','立刻','马上'], I_CAT),
        ('bypass_action_verbs', 'Bypass Action Verbs', ['bypass','disable','deactivate','turn off','shut down','stop','override','绕过','关闭','禁用','停止','取消'], I_CAT),
        ('bypass_target_nouns', 'Bypass Targets', ['proxy','gateway','firewall','security gateway','content filter','代理','限制','过滤'], I_CAT),
        ('file_access_verbs', 'File Access Verbs', ['read','open','view','get','fetch','show','display','dump','cat','less','more','tail','head','输出','读取','打开','查看'], I_CAT),
        ('file_access_nouns', 'File Access Nouns', ['file','document','config','configuration','settings','content','源码','代码','文件','配置','日志'], I_CAT),
        ('archive_verbs', 'Archive Verbs', ['extract','unzip','untar','decompress','expand','解压','提取','展开'], I_CAT),
        ('internal_network_labels', 'Internal Network', ['internal','private','corp','intranet','local','内部','内网'], I_CAT),
        ('harmful_weapon_terms', 'Harmful Weapons', ['bomb','explosive','weapon','drug','narcotic','poison','toxin','chemical weapon','bioweapon'], O_CAT),
        ('harmful_self_harm', 'Self Harm', ['suicide','self-harm','self injury'], O_CAT),
        ('harmful_child_safety', 'Child Safety', ['child porn','child exploit','child abuse','CSAM'], O_CAT),
        ('harmful_create_verbs', 'Harmful Create', ['make','build','create','manufacture','synthesize','commit','perform','carry out'], O_CAT),
        ('weaponized_c2_malware', 'C2/Malware', ['C2 server','backdoor','remote access trojan','RAT server','DDoS','botnet','rootkit','cryptominer'], O_CAT),
        ('weak_passwords', 'Weak Passwords', ['password123','admin123','test123','P@ssw0rd','letmein','welcome','changeme','qwerty','abc123','default'], SEC_CAT),
        ('default_usernames', 'Default Usernames', ['admin','root','test','guest','sa'], SEC_CAT),
        ('credential_field_names', 'Credential Fields', ['password','passwd','pwd','secret','api_key','api_secret','auth_token','access_token','token','credential'], SEC_CAT),
    ]
    for code, name, entries, cat_id in dictionary_seeds:
        existing = db.query(Dictionary).filter(Dictionary.code == code).first()
        if not existing:
            d = Dictionary(code=code, name=name, entries=entries, category_id=cat_id, is_active=True)
            db.add(d)
    db.commit()

    # Initialize engine with rules
    engine_service.initialize()
    engine_service.reload_rules_from_db(db)
    db.close()

    # Create app with lifespan disabled
    from app.main import create_app
    app = create_app()

    with TestClient(app) as c:
        yield c

    if engine_service.is_initialized:
        engine_service.shutdown()


@pytest.fixture(scope="function")
def auth_headers() -> dict[str, str]:
    """Default auth headers for tests."""
    return {"X-API-Key": "test-api-key"}
