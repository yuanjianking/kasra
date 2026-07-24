-- ============================================================================
-- Kasra — Master Data Seed (categories + pattern_types + dictionaries)
-- ============================================================================
-- Safe to re-run — all INSERTs use WHERE NOT EXISTS.
-- Load BEFORE rule JSON files.
-- ============================================================================

-- ── Categories ──
INSERT INTO categories (name, label, description, color)
SELECT * FROM (VALUES
    ('I', 'Input Detection', 'Rules that detect security issues in user input', '#ef4444'),
    ('O', 'Output Detection', 'Rules that detect security issues in AI output', '#f97316'),
    ('SEC', 'Code Security', 'Code review rules for security vulnerabilities', '#8b5cf6'),
    ('IAC', 'Infrastructure as Code', 'Rules for Docker, K8s, and IaC misconfigurations', '#06b6d4'),
    ('BEHAVIOR', 'Behavior Monitoring', 'Rules for detecting anomalous user/agent behavior', '#ec4899')
) AS v(name, label, description, color)
WHERE NOT EXISTS (SELECT 1 FROM categories WHERE categories.name = v.name);

-- ── Pattern Types ──
INSERT INTO pattern_types (name, label, description)
SELECT * FROM (VALUES
    ('regex', 'Regex Match', 'Regular expression pattern matching'),
    ('keyword', 'Keyword Match', 'Exact keyword or substring matching'),
    ('dictionary', 'Dictionary Match', 'Dictionary/list-based matching'),
    ('yaml_path', 'YAML Path Match', 'YAML key path with value regex'),
    ('dockerfile', 'Dockerfile Match', 'Dockerfile instruction matching'),
    ('keyvalue', 'Key-Value Match', 'Key=value pair matching for .env files')
) AS v(name, label, description)
WHERE NOT EXISTS (SELECT 1 FROM pattern_types WHERE pattern_types.name = v.name);

-- ── Dictionaries ──
INSERT INTO dictionaries (code, name, description, entries, category_id, is_active, version)
SELECT 'archive_verbs', 'Archive — Extract/Decompress Verbs', 'Verbs used for archive extraction operations',
       '["extract", "unzip", "untar", "decompress", "expand", "解压", "提取", "展开", "解凍", "展開する"]'::jsonb,
       (SELECT id FROM categories WHERE name = 'I'), TRUE, 1
WHERE NOT EXISTS (SELECT 1 FROM dictionaries WHERE dictionaries.code = 'archive_verbs');
INSERT INTO dictionaries (code, name, description, entries, category_id, is_active, version)
SELECT 'bypass_action_verbs', 'Security Bypass — Action Verbs', 'Verbs requesting disabling of security controls',
       '["bypass", "disable", "deactivate", "turn off", "shut down", "stop", "override", "绕过", "关闭", "禁用", "停止", "暂停", "取消", "跳过", "规避", "バイパス", "無効化", "スキップ", "回避", "迂回"]'::jsonb,
       (SELECT id FROM categories WHERE name = 'I'), TRUE, 1
WHERE NOT EXISTS (SELECT 1 FROM dictionaries WHERE dictionaries.code = 'bypass_action_verbs');
INSERT INTO dictionaries (code, name, description, entries, category_id, is_active, version)
SELECT 'bypass_target_nouns', 'Security Bypass — Target Nouns', 'Nouns referring to security controls to be bypassed',
       '["proxy", "gateway", "firewall", "security gateway", "security control", "content filter", "内容过滤", "安全控制", "代理", "限制", "过滤", "保护", "ゲートウェイ", "セキュリティ", "制限", "フィルター", "プロキシ"]'::jsonb,
       (SELECT id FROM categories WHERE name = 'I'), TRUE, 1
WHERE NOT EXISTS (SELECT 1 FROM dictionaries WHERE dictionaries.code = 'bypass_target_nouns');
INSERT INTO dictionaries (code, name, description, entries, category_id, is_active, version)
SELECT 'context_reset_nouns', 'Context Reset — History/Context References', 'Nouns referring to conversation context or history',
       '["history", "context", "conversation", "messages", "chat", "memory", "session", "logs", "records", "data", "content", "过去的", "所有", "全部", "上下文", "历史", "对话", "聊天记录", "记忆", "会話", "履歴", "記憶", "過去", "セッション"]'::jsonb,
       (SELECT id FROM categories WHERE name = 'I'), TRUE, 1
WHERE NOT EXISTS (SELECT 1 FROM dictionaries WHERE dictionaries.code = 'context_reset_nouns');
INSERT INTO dictionaries (code, name, description, entries, category_id, is_active, version)
SELECT 'context_reset_verbs', 'Context Reset — Reset/Discard Verbs', 'Verbs used to reset or discard conversation context',
       '["forget", "ignore", "clear", "reset", "erase", "remove", "delete", "discard", "abandon", "restart", "purge", "truncate", "wipe", "清除", "重置", "忽略", "删除", "清空", "重新开始", "移除", "销毁", "抹除", "清理", "忘れる", "無視する", "リセット", "消去", "削除", "初期化"]'::jsonb,
       (SELECT id FROM categories WHERE name = 'I'), TRUE, 1
WHERE NOT EXISTS (SELECT 1 FROM dictionaries WHERE dictionaries.code = 'context_reset_verbs');
INSERT INTO dictionaries (code, name, description, entries, category_id, is_active, version)
SELECT 'credential_field_names', 'Credential Field Names', 'Common variable/field names for credentials and secrets',
       '["password", "passwd", "pwd", "secret", "api_key", "api_secret", "auth_token", "access_token", "token", "credential", "jwt_secret", "signing_secret", "signing_key", "secret_key", "aes_key", "hmac"]'::jsonb,
       (SELECT id FROM categories WHERE name = 'SEC'), TRUE, 1
WHERE NOT EXISTS (SELECT 1 FROM dictionaries WHERE dictionaries.code = 'credential_field_names');
INSERT INTO dictionaries (code, name, description, entries, category_id, is_active, version)
SELECT 'default_usernames', 'Default / Test Usernames', 'Common default or test usernames',
       '["admin", "root", "test", "guest", "sa"]'::jsonb,
       (SELECT id FROM categories WHERE name = 'SEC'), TRUE, 1
WHERE NOT EXISTS (SELECT 1 FROM dictionaries WHERE dictionaries.code = 'default_usernames');
INSERT INTO dictionaries (code, name, description, entries, category_id, is_active, version)
SELECT 'file_access_nouns', 'File Access — Target Nouns', 'Nouns referring to files or code content',
       '["file", "document", "config", "configuration", "settings", "content", "source code", "源码", "代码", "文件", "配置", "内容", "日志", "ファイル", "ドキュメント", "設定"]'::jsonb,
       (SELECT id FROM categories WHERE name = 'I'), TRUE, 1
WHERE NOT EXISTS (SELECT 1 FROM dictionaries WHERE dictionaries.code = 'file_access_nouns');
INSERT INTO dictionaries (code, name, description, entries, category_id, is_active, version)
SELECT 'file_access_verbs', 'File Access — Action Verbs', 'Verbs used to request reading or viewing files',
       '["read", "open", "view", "get", "fetch", "show", "display", "dump", "list", "output", "cat", "less", "more", "tail", "head", "输出", "读取", "打开", "查看", "显示", "打印", "読み取り", "読み込む", "開く", "表示", "見る", "取得"]'::jsonb,
       (SELECT id FROM categories WHERE name = 'I'), TRUE, 1
WHERE NOT EXISTS (SELECT 1 FROM dictionaries WHERE dictionaries.code = 'file_access_verbs');
INSERT INTO dictionaries (code, name, description, entries, category_id, is_active, version)
SELECT 'gdpr_biometric', 'GDPR Biometric Data Keywords', 'Biometric data terms under GDPR Art.9',
       '["fingerprint", "biometric", "face_recognition", "iris_scan", "retina", "voiceprint", "palm_vein", "dna", "gene", "genetic", "thumbprint", "hand_geometry", "facial_recognition", "指紋", "生体認証", "虹彩", "顔認識", "DNA", "遺伝子", "声紋"]'::jsonb,
       (SELECT id FROM categories WHERE name = 'I'), TRUE, 1
WHERE NOT EXISTS (SELECT 1 FROM dictionaries WHERE dictionaries.code = 'gdpr_biometric');
INSERT INTO dictionaries (code, name, description, entries, category_id, is_active, version)
SELECT 'gdpr_health', 'GDPR Health Data Keywords', 'Medical/health terms indicating special category data under GDPR Art.9',
       '["diagnosis", "medical", "health", "patient", "clinical", "symptom", "treatment", "disease", "diabetes", "cancer", "cardiac", "surgery", "therapy", "prescription", "medication", "病历", "诊断", "糖尿病", "肿瘤", "癌症", "心脏病", "手术", "治疗", "患者", "病人", "症状", "疾病", "药物", "处方", "住院", "急诊", "康复", "体检", "疫苗", "診断", "カルテ"]'::jsonb,
       (SELECT id FROM categories WHERE name = 'I'), TRUE, 1
WHERE NOT EXISTS (SELECT 1 FROM dictionaries WHERE dictionaries.code = 'gdpr_health');
INSERT INTO dictionaries (code, name, description, entries, category_id, is_active, version)
SELECT 'harmful_child_safety', 'Harmful Content — Child Safety Terms', 'Terms related to child exploitation',
       '["child porn", "child exploit", "child abuse", "child traffick", "child sexualize", "CSAM"]'::jsonb,
       (SELECT id FROM categories WHERE name = 'O'), TRUE, 1
WHERE NOT EXISTS (SELECT 1 FROM dictionaries WHERE dictionaries.code = 'harmful_child_safety');
INSERT INTO dictionaries (code, name, description, entries, category_id, is_active, version)
SELECT 'harmful_create_verbs', 'Harmful Content — Create Verbs', 'Verbs used in harmful content generation requests',
       '["make", "build", "create", "manufacture", "synthesize", "commit", "perform", "carry out", "作る", "作成", "生成", "構築", "実行"]'::jsonb,
       (SELECT id FROM categories WHERE name = 'O'), TRUE, 1
WHERE NOT EXISTS (SELECT 1 FROM dictionaries WHERE dictionaries.code = 'harmful_create_verbs');
INSERT INTO dictionaries (code, name, description, entries, category_id, is_active, version)
SELECT 'harmful_self_harm', 'Harmful Content — Self-Harm Terms', 'Terms related to suicide and self-harm',
       '["suicide", "self-harm", "self injury", "自殺", "自傷"]'::jsonb,
       (SELECT id FROM categories WHERE name = 'O'), TRUE, 1
WHERE NOT EXISTS (SELECT 1 FROM dictionaries WHERE dictionaries.code = 'harmful_self_harm');
INSERT INTO dictionaries (code, name, description, entries, category_id, is_active, version)
SELECT 'harmful_weapon_terms', 'Harmful Content — Weapons/Explosives', 'Terms related to weapons, explosives, and harmful substances',
       '["bomb", "explosive", "weapon", "drug", "narcotic", "poison", "toxin", "chemical weapon", "bioweapon", "nerve agent", "nerve gas", "chemical", "pipe bomb", "IED", "爆弾", "爆発物", "武器", "薬物", "毒物", "毒素"]'::jsonb,
       (SELECT id FROM categories WHERE name = 'O'), TRUE, 1
WHERE NOT EXISTS (SELECT 1 FROM dictionaries WHERE dictionaries.code = 'harmful_weapon_terms');
INSERT INTO dictionaries (code, name, description, entries, category_id, is_active, version)
SELECT 'internal_network_labels', 'Internal Network — Labels', 'Labels indicating internal or private network resources',
       '["internal", "private", "corp", "intranet", "local", "内部", "内网", "内部ネットワーク", "社内", "プライベート"]'::jsonb,
       (SELECT id FROM categories WHERE name = 'I'), TRUE, 1
WHERE NOT EXISTS (SELECT 1 FROM dictionaries WHERE dictionaries.code = 'internal_network_labels');
INSERT INTO dictionaries (code, name, description, entries, category_id, is_active, version)
SELECT 'name_indicators', 'Person Name Indicators', 'Field labels and signature closings that indicate a real name',
       '["name", "full_name", "user_name", "real_name", "联系人", "姓名", "Best", "Sincerely", "Regards", "Yours", "此致", "敬礼", "祝好", "氏名", "名前", "連絡先"]'::jsonb,
       (SELECT id FROM categories WHERE name = 'I'), TRUE, 1
WHERE NOT EXISTS (SELECT 1 FROM dictionaries WHERE dictionaries.code = 'name_indicators');
INSERT INTO dictionaries (code, name, description, entries, category_id, is_active, version)
SELECT 'pi_instruction_nouns', 'Prompt Injection — Instruction Nouns', 'Nouns referring to AI system instructions or constraints',
       '["instructions", "directives", "rules", "prompts", "commands", "constraints", "guidelines", "directions", "safety", "security", "filter", "boundaries", "system prompt", "system instructions", "限制", "指令", "规则", "提示", "约束", "安全", "过滤", "指示", "命令", "制限", "ルール", "規則", "フィルター"]'::jsonb,
       (SELECT id FROM categories WHERE name = 'I'), TRUE, 1
WHERE NOT EXISTS (SELECT 1 FROM dictionaries WHERE dictionaries.code = 'pi_instruction_nouns');
INSERT INTO dictionaries (code, name, description, entries, category_id, is_active, version)
SELECT 'pi_jailbreak_names', 'Prompt Injection — Jailbreak Mode Names', 'Known jailbreak role names and mode labels',
       '["DAN", "STAN", "AoE", "Jailbreak", "developer mode", "unlocked mode", "unrestricted mode", "no filter", "no restrictions", "no rules", "free mode", "god mode", "bypassed", "uncensored", "開発者モード", "無制限モード", "制限なし"]'::jsonb,
       (SELECT id FROM categories WHERE name = 'I'), TRUE, 1
WHERE NOT EXISTS (SELECT 1 FROM dictionaries WHERE dictionaries.code = 'pi_jailbreak_names');
INSERT INTO dictionaries (code, name, description, entries, category_id, is_active, version)
SELECT 'pi_jailbreak_pretend', 'Prompt Injection — Role-Play Prefixes', 'Phrases used to start a role-play jailbreak',
       '["you are now", "act as if", "pretend to be", "从今以后", "你现在是", "你扮演", "hypothetical", "fictional", "academic", "research", "testing", "educational", "for science", "for research", "あなたは", "ふりをする", "学術研究", "教育目的"]'::jsonb,
       (SELECT id FROM categories WHERE name = 'I'), TRUE, 1
WHERE NOT EXISTS (SELECT 1 FROM dictionaries WHERE dictionaries.code = 'pi_jailbreak_pretend');
INSERT INTO dictionaries (code, name, description, entries, category_id, is_active, version)
SELECT 'pi_output_verbs', 'Prompt Injection — Output Extraction Verbs', 'Verbs demanding the AI output its own instructions or prompts',
       '["repeat", "reveal", "show", "display", "print", "output", "write", "copy", "paste", "return", "extract", "start", "begin", "initialize", "复述", "重复", "输出", "显示", "展示", "提示", "复制", "泄露", "泄漏", "出力", "表示", "印刷", "コピー", "抽出"]'::jsonb,
       (SELECT id FROM categories WHERE name = 'I'), TRUE, 1
WHERE NOT EXISTS (SELECT 1 FROM dictionaries WHERE dictionaries.code = 'pi_output_verbs');
INSERT INTO dictionaries (code, name, description, entries, category_id, is_active, version)
SELECT 'pi_override_verbs', 'Prompt Injection — Instruction Override Verbs', 'Verbs used to override or discard system instructions',
       '["ignore", "disregard", "forget", "override", "overwrite", "skip", "bypass", "无视", "忽略", "忘记", "覆盖", "無視", "忘れ", "無効", "バイパス", "スキップ"]'::jsonb,
       (SELECT id FROM categories WHERE name = 'I'), TRUE, 1
WHERE NOT EXISTS (SELECT 1 FROM dictionaries WHERE dictionaries.code = 'pi_override_verbs');
INSERT INTO dictionaries (code, name, description, entries, category_id, is_active, version)
SELECT 'pi_system_nouns', 'Prompt Injection — System Instruction References', 'Nouns referring to the AI''s system prompt or initial instructions',
       '["system prompt", "system instructions", "initial prompt", "base prompt", "core instructions", "original prompt", "starting prompt", "opening prompt", "first message", "prompt above", "above prompt", "システムプロンプト", "システム指示"]'::jsonb,
       (SELECT id FROM categories WHERE name = 'I'), TRUE, 1
WHERE NOT EXISTS (SELECT 1 FROM dictionaries WHERE dictionaries.code = 'pi_system_nouns');
INSERT INTO dictionaries (code, name, description, entries, category_id, is_active, version)
SELECT 'reverse_engineering_verbs', 'Reverse Engineering — Analysis Verbs', 'Verbs used to request analysis of proprietary or compiled code',
       '["analyze", "analyse", "explain", "understand", "examine", "reverse", "decompile", "disassemble", "リバース", "逆コンパイル", "デコンパイル", "逆解析"]'::jsonb,
       (SELECT id FROM categories WHERE name = 'I'), TRUE, 1
WHERE NOT EXISTS (SELECT 1 FROM dictionaries WHERE dictionaries.code = 'reverse_engineering_verbs');
INSERT INTO dictionaries (code, name, description, entries, category_id, is_active, version)
SELECT 'se_authority_titles', 'Social Engineering — Authority Titles', 'Executive or authority titles used in impersonation attacks',
       '["CEO", "CTO", "CIO", "security", "auditor", "compliance", "manager", "director", "VP", "president", "admin", "supervisor", "管理员", "老板", "经理", "负责人", "セキュリティ", "監査", "管理者", "IT管理者"]'::jsonb,
       (SELECT id FROM categories WHERE name = 'I'), TRUE, 1
WHERE NOT EXISTS (SELECT 1 FROM dictionaries WHERE dictionaries.code = 'se_authority_titles');
INSERT INTO dictionaries (code, name, description, entries, category_id, is_active, version)
SELECT 'se_urgency_phrases', 'Social Engineering — Urgency Words', 'Urgency language used to pressure bypass of security controls',
       '["emergency", "urgent", "immediately", "critical", "ASAP", "紧急", "立刻", "马上", "緊急", "至急", "すぐに", "今すぐ"]'::jsonb,
       (SELECT id FROM categories WHERE name = 'I'), TRUE, 1
WHERE NOT EXISTS (SELECT 1 FROM dictionaries WHERE dictionaries.code = 'se_urgency_phrases');
INSERT INTO dictionaries (code, name, description, entries, category_id, is_active, version)
SELECT 'weak_passwords', 'Weak / Test Passwords', 'Commonly used weak or default passwords',
       '["password123", "admin123", "test123", "P@ssw0rd", "letmein", "welcome", "changeme", "passw0rd", "qwerty", "abc123", "default", "password1", "pass123", "temp123", "secret123", "changeme123", "123456", "12345678"]'::jsonb,
       (SELECT id FROM categories WHERE name = 'SEC'), TRUE, 1
WHERE NOT EXISTS (SELECT 1 FROM dictionaries WHERE dictionaries.code = 'weak_passwords');
INSERT INTO dictionaries (code, name, description, entries, category_id, is_active, version)
SELECT 'weaponized_c2_malware', 'Weaponized Code — C2/Malware Terms', 'Terms related to command & control and malware types',
       '["C2 server", "C2 framework", "C2 channel", "command and control", "backdoor", "remote access trojan", "RAT server", "DDoS", "botnet", "flooder", "stresser", "bootkit", "rootkit", "cryptominer", "cryptojack", "monero min", "バックドア", "マルウェア", "ボットネット", "ルートキット"]'::jsonb,
       (SELECT id FROM categories WHERE name = 'O'), TRUE, 1
WHERE NOT EXISTS (SELECT 1 FROM dictionaries WHERE dictionaries.code = 'weaponized_c2_malware');

-- ── Extended dictionaries for O-38/O-39 multi-language support ──
UPDATE dictionaries
SET entries = (entries::jsonb || '["毒ガス", "神経ガス", "毒气", "神经毒剂", "爆炸物", "化学武器", "化学兵器"]'::jsonb)::json,
    version = version + 1
WHERE code = 'harmful_weapon_terms'
  AND NOT entries::jsonb @> '["毒ガス", "神経ガス", "毒气", "神经毒剂", "爆炸物", "化学武器", "化学兵器"]'::jsonb;
INSERT INTO dictionaries (code, name, description, entries, category_id, is_active, version)
SELECT 'harmful_explosive_compounds', 'Harmful Content — Explosive Compounds', 'Specific explosive compounds and precursors',
       '["TATP", "triacetone triperoxide", "hydrogen peroxide", "sulfuric acid", "nitroglycerin", "HMTD", "C-4", "ammonium nitrate", "过氧化氢", "硫酸", "硝酸铵", "過酸化水素", "硫酸", "硝酸アンモニウム"]'::jsonb,
       (SELECT id FROM categories WHERE name = 'O'), TRUE, 1
WHERE NOT EXISTS (SELECT 1 FROM dictionaries WHERE dictionaries.code = 'harmful_explosive_compounds');
INSERT INTO dictionaries (code, name, description, entries, category_id, is_active, version)
SELECT 'harmful_manufacturing_terms', 'Harmful Content — Manufacturing/Process Terms', 'Terms describing the process of making harmful substances',
       '["制作步骤", "合成方法", "合成路线", "化学品清单", "製造手順", "合成経路", "化学物質リスト"]'::jsonb,
       (SELECT id FROM categories WHERE name = 'O'), TRUE, 1
WHERE NOT EXISTS (SELECT 1 FROM dictionaries WHERE dictionaries.code = 'harmful_manufacturing_terms');
UPDATE dictionaries
SET entries = (entries::jsonb || '["C2 服务器", "C2服务器", "僵尸网络", "拒绝服务", "键盘记录", "远程控制", "后门", "木马", "勒索", "套接字", "漏洞利用", "C2サーバー", "ランサムウェア", "ボットネット", "キーロガー", "サービス拒否", "バックドア", "遠隔操作", "不正アクセス", "ソケット", "リモートシェル", "トロイの木馬"]'::jsonb)::json,
    version = version + 1
WHERE code = 'weaponized_c2_malware'
  AND NOT entries::jsonb @> '["C2 服务器", "C2服务器", "僵尸网络", "拒绝服务", "键盘记录", "远程控制", "后门", "木马", "勒索", "套接字", "漏洞利用", "C2サーバー", "ランサムウェア", "ボットネット", "キーロガー", "サービス拒否", "バックドア", "遠隔操作", "不正アクセス", "ソケット", "リモートシェル", "トロイの木馬"]'::jsonb;
