"""Migrate natural-language keyword patterns from rules to dictionary refs.

Rules are updated in-place.  This script is idempotent (safe to re-run).

For each multi-keyword pattern it decides:
- pure_kw:  pattern value ≈ alternation of words → create dictionary + ref
- mixed:    keywords embedded in structural regex → keep regex, add comment
- no_dict:  code/structural keywords, not natural language → skip
"""
import json, re, sys
from collections import defaultdict

# ── Dictionary definitions ──────────────────────────────────────────────
# Each entry: code, name, description, keywords, category_name
DICTIONARIES = [
    # ── GDPR / PII ──
    ("gdpr_health", "GDPR Health Data Keywords",
     "Medical/health terms indicating special category data under GDPR Art.9",
     ["diagnosis","medical","health","patient","clinical","symptom","treatment","disease",
      "diabetes","cancer","cardiac","surgery","therapy","prescription","medication",
      "病历","诊断","糖尿病","肿瘤","癌症","心脏病","手术","治疗","患者","病人",
      "症状","疾病","药物","处方","住院","急诊","康复","体检","疫苗"], "I"),

    ("gdpr_biometric", "GDPR Biometric Data Keywords",
     "Biometric data terms under GDPR Art.9",
     ["fingerprint","biometric","face_recognition","iris_scan","retina","voiceprint",
      "palm_vein","dna","gene","genetic","thumbprint","hand_geometry","facial_recognition"], "I"),

    ("name_indicators", "Person Name Indicators",
     "Field labels and signature closings that indicate a real name",
     ["name","full_name","user_name","real_name","联系人","姓名",
      "Best","Sincerely","Regards","Yours","此致","敬礼","祝好"], "I"),

    # ── Prompt Injection ──
    ("pi_override_verbs", "Prompt Injection — Instruction Override Verbs",
     "Verbs used to override or discard system instructions",
     ["ignore","disregard","forget","override","overwrite","skip","bypass",
      "无视","忽略","忘记","覆盖"], "I"),

    ("pi_instruction_nouns", "Prompt Injection — Instruction Nouns",
     "Nouns referring to AI system instructions or constraints",
     ["instructions","directives","rules","prompts","commands","constraints","guidelines",
      "directions","safety","security","filter","boundaries",
      "system prompt","system instructions",
      "限制","指令","规则","提示","约束","安全","过滤"], "I"),

    ("pi_jailbreak_names", "Prompt Injection — Jailbreak Mode Names",
     "Known jailbreak role names and mode labels",
     ["DAN","STAN","AoE","Jailbreak","developer mode","unlocked mode","unrestricted mode",
      "no filter","no restrictions","no rules","free mode","god mode","bypassed","uncensored"], "I"),

    ("pi_jailbreak_pretend", "Prompt Injection — Role-Play Prefixes",
     "Phrases used to start a role-play jailbreak",
     ["you are now","act as if","pretend to be","从今以后","你现在是","你扮演",
      "hypothetical","fictional","academic","research","testing","educational",
      "for science","for research"], "I"),

    ("pi_output_verbs", "Prompt Injection — Output Extraction Verbs",
     "Verbs demanding the AI output its own instructions or prompts",
     ["repeat","reveal","show","display","print","output","write","copy","paste",
      "return","extract","start","begin","initialize",
      "复述","重复","输出","显示","展示","提示","复制","泄露","泄漏"], "I"),

    ("pi_system_nouns", "Prompt Injection — System Instruction References",
     "Nouns referring to the AI's system prompt or initial instructions",
     ["system prompt","system instructions","initial prompt","base prompt","core instructions",
      "original prompt","starting prompt","opening prompt","first message",
      "prompt above","above prompt"], "I"),

    # ── Context Reset / Manipulation ──
    ("context_reset_verbs", "Context Reset — Reset/Discard Verbs",
     "Verbs used to reset conversation history or context",
     ["forget","ignore","clear","reset","erase","remove","delete","discard","abandon",
      "restart","purge","truncate","wipe",
      "清除","重置","忽略","删除","清空","重新开始","移除","销毁","抹除","清理"], "I"),

    ("context_reset_nouns", "Context Reset — History/Context References",
     "Nouns referring to conversation context or history",
     ["history","context","conversation","messages","chat","memory","session","logs","records",
      "过去的","所有","全部","上下文","历史","对话","聊天记录","记忆"], "I"),

    # ── Social Engineering ──
    ("se_authority_titles", "Social Engineering — Authority Titles",
     "Executive or authority titles used in impersonation attacks",
     ["CEO","CTO","CIO","security","auditor","compliance","manager","director",
      "VP","president","admin","supervisor","coordinator",
      "管理员","老板","经理","负责人"], "I"),

    ("se_urgency_phrases", "Social Engineering — Urgency Words",
     "Urgency language used to pressure bypass of security controls",
     ["emergency","urgent","immediately","critical","ASAP",
      "紧急","立刻","马上"], "I"),

    # ── Security Control Bypass ──
    ("bypass_action_verbs", "Security Bypass — Action Verbs",
     "Verbs requesting disabling of security controls",
     ["bypass","disable","deactivate","turn off","shut down","stop","override",
      "绕过","关闭","禁用","停止","暂停","取消","跳过","规避"], "I"),

    ("bypass_target_nouns", "Security Bypass — Target Nouns",
     "Nouns referring to security controls to be bypassed",
     ["proxy","gateway","firewall","security gateway","security control","content filter",
      "内容过滤","安全控制","代理","限制","过滤","保护"], "I"),

    # ── Sensitive Data Access ──
    ("file_access_verbs", "File Access — Action Verbs",
     "Verbs used to request reading or viewing files",
     ["read","open","view","get","fetch","show","display","dump","list","output",
      "cat","less","more","tail","head",
      "输出","读取","打开","查看","显示","打印"], "I"),

    ("file_access_nouns", "File Access — Target Nouns",
     "Nouns referring to files or code content",
     ["file","document","config","configuration","settings","content",
      "source code","源码","代码","文件","配置","内容","日志"], "I"),

    ("archive_verbs", "Archive — Extract/Decompress Verbs",
     "Verbs used for archive extraction operations",
     ["extract","unzip","untar","decompress","expand","解压","提取","展开"], "I"),

    ("binary_extensions", "Binary / Archive File Extensions",
     "File extensions for binary and archive file types",
     [".db",".sqlite",".exe",".dll",".so",".dylib",".zip",".tar.gz",".tar.bz2",".tar.xz",
      ".7z",".rar",".iso",".bin",".dmg",".pkg"], "I"),

    ("binary_file_types", "Binary / Executable File References",
     "References to binary or executable files",
     ["binary","executable","compiled","image","database","dump","archive",
      "压缩包","二进制","数据库"], "I"),

    ("reverse_engineering_verbs", "Reverse Engineering — Analysis Verbs",
     "Verbs used to request analysis of proprietary or compiled code",
     ["analyze","analyse","explain","understand","examine","reverse",
      "decompile","disassemble","reverse engineer"], "I"),

    # ── SSRF / Internal Network ──
    ("internal_network_labels", "Internal Network — Labels",
     "Labels indicating internal or private network resources",
     ["internal","private","corp","intranet","local","内部","内网"], "I"),

    # ── Harmful / Illegal Content ──
    ("harmful_weapons", "Harmful Content — Weapons/Explosives",
     "Terms related to weapons, explosives, and harmful substances",
     ["bomb","explosive","weapon","drug","narcotic","poison","toxin",
      "chemical weapon","bioweapon","nerve agent","nerve gas"], "O"),

    ("harmful_self_harm", "Harmful Content — Self-Harm Terms",
     "Terms related to suicide and self-harm",
     ["suicide","self-harm","self injury"], "O"),

    ("harmful_child_safety", "Harmful Content — Child Safety Terms",
     "Terms related to child exploitation (CSAM detection)",
     ["child porn","child exploit","child abuse","child traffick","child sexualize",
      "CSAM"], "O"),

    ("harmful_violent_verbs", "Harmful Content — Make/Build Verbs",
     "Verbs used in harmful content generation requests",
     ["make","build","create","manufacture","synthesize","commit","perform",
      "carry out"], "O"),

    # ── Harmful Output ──
    ("weaponized_c2", "Weaponized Code — C2/Malware Terms",
     "Terms related to command & control servers and malware types",
     ["C2 server","C2 framework","C2 channel","C2 communication","command and control",
      "backdoor","remote access trojan","RAT server",
      "DDoS","botnet","flooder","stresser","bootkit","rootkit"], "O"),

    ("weaponized_mining", "Weaponized Code — Crypto Mining Terms",
     "Terms related to unauthorized cryptocurrency mining",
     ["cryptominer","cryptojack","miner","monero min"], "O"),

    # ── Test / Weak Credentials ──
    ("weak_passwords", "Weak / Test Passwords",
     "Commonly used weak or default passwords",
     ["password123","admin123","test123","P@ssw0rd","letmein","welcome","changeme",
      "passw0rd","qwerty","abc123","default","password1","pass123","temp123",
      "secret123","changeme123"], "SEC"),

    ("default_usernames", "Default / Test Usernames",
     "Common default or test usernames",
     ["admin","root","test","guest","sa"], "SEC"),

    # ── Credential / Secret Keywords ──
    ("secret_field_names", "Secret Field Names",
     "Common variable/field names for credentials",
     ["password","passwd","pwd","secret","api_key","api_secret","auth_token",
      "access_token","token","credential","jwt_secret","signing_secret","signing_key",
      "secret_key","aes_key","aes","hmac",
      "密码","密钥","凭证","令牌","api密钥","登录密码","数据库密码"], "I"),
]


def load_dictionaries(db):
    """Load existing dictionary code→id map."""
    from app.models.dictionary import Dictionary
    result = {}
    for d in db.query(Dictionary).all():
        result[d.code] = d.id
    return result


def create_dictionaries(db, cat_map):
    """Create dictionaries that don't exist yet. Returns code→id map."""
    from app.models.dictionary import Dictionary
    existing = load_dictionaries(db)
    created = {}

    for code, name, desc, entries, cat_name in DICTIONARIES:
        if code in existing:
            continue
        d = Dictionary(
            code=code, name=name, description=desc,
            entries=entries,
            category_id=cat_map.get(cat_name),
        )
        db.add(d)
        db.flush()
        created[code] = d.id
        print(f"  + dictionary {code} ({len(entries)} entries)")

    db.commit()
    return {**existing, **created}


def extract_alternation_keys(pattern_value):
    """Extract keyword-like alternation groups from a regex pattern.

    Returns list of (full_group_text, [keywords]) for groups that look like
    natural language word lists.
    """
    results = []
    # Find all (?:word1|word2|word3) groups
    for m in re.finditer(r'\(\?:([^()]+)\)', pattern_value):
        alts = [a.strip() for a in m.group(1).split('|')]
        # Filter to alternations that look like natural language keyword lists
        # (not code symbols, not IP octets, not UUIDs, not just numbers)
        clean = [a for a in alts if len(a) > 1 and not re.match(r'^[\d.\\]+$', a)]
        if len(clean) >= 2:
            results.append((m.group(0), clean, m.start(), m.end()))
    return results


def can_be_dictionary(alternation):
    """Check if an alternation group is safe to extract as a dictionary.

    A group is safe if its entries are natural language words, not code tokens
    with regex metacharacters.
    """
    # Check entries for regex metacharacters beyond simple \s
    for entry in alternation:
        # Allow: word characters, spaces, hyphens, underscores
        # Disallow: \d, \w, [^...], +, *, ?, ., ^, $
        cleaned = entry.replace(r'\s', ' ').replace(r'\-', '-').replace(r'\_', '_')
        remaining_meta = re.findall(r'[\\.[\]{}()+*?^$|]', cleaned)
        if remaining_meta:
            # Only complain about significant metacharacters
            bad_meta = [m for m in remaining_meta if m not in (' ', '-', '_')]
            if bad_meta:
                return False
    return True


def migrate_rule(db, rule, dict_map, cat_map):
    """Migrate one rule's detection_config to use dictionary refs where possible."""
    changed = False
    dc = rule.detection_config
    if isinstance(dc, str):
        dc = json.loads(dc)
    dc = dc or {}
    patterns = dc.get("patterns", [])

    new_patterns = []
    migrated = []

    for p in patterns:
        if p.get("type") != "regex":
            new_patterns.append(p)
            continue

        val = p.get("value", "")
        groups = extract_alternation_keys(val)

        if not groups:
            new_patterns.append(p)
            continue

        # Check if any group is dictionary-material
        for full_group, keys, start, end in groups:
            if not can_be_dictionary(keys):
                continue

            # Find the best matching dictionary
            matched_dict = None
            for code, name, desc, entries, cat_name in DICTIONARIES:
                if any(k in entries for k in keys[:3]):  # match on first few keys
                    matched_dict = code
                    break

            if not matched_dict:
                continue

            # If the ENTIRE pattern is just this alternation (with \b), replace entirely
            stripped = val.replace(full_group, "").replace(r"\b", "").strip()
            if not stripped:
                new_patterns.append({
                    "type": "dictionary",
                    "ref": matched_dict,
                    "confidence": p.get("confidence", 0.4),
                })
                migrated.append((rule.id, matched_dict))
                changed = True
                break  # replaced entire pattern
            else:
                # Keep the regex but add dictionary as additional pattern
                new_patterns.append(p)  # keep original regex
                # Also add dictionary ref for broader catch
                new_patterns.append({
                    "type": "dictionary",
                    "ref": matched_dict,
                    "confidence": p.get("confidence", 0.3),
                })
                migrated.append((rule.id, matched_dict, "partial"))
                changed = True
                break  # one dict ref per pattern is enough
        else:
            new_patterns.append(p)

    if changed:
        dc["patterns"] = new_patterns
        rule.detection_config = dc
        db.flush()
        print(f"  ~ {rule.id}: migrated {len(migrated)} patterns → {[m[1] for m in migrated]}")

    return changed


def main():
    from app.database import SessionLocal
    from app.models.rule_config import Rule as RuleModel
    from app.models.category import Category

    db = SessionLocal()
    cat_map = {c.name: c.id for c in db.query(Category).all()}

    # 1. Create dictionaries
    print("=== Creating dictionaries ===")
    dict_id_map = create_dictionaries(db, cat_map)
    print()

    # 2. Migrate rules
    print("=== Migrating rules ===")
    all_rules = db.query(RuleModel).order_by(RuleModel.id).all()
    migrated_count = 0
    total_potential = 0

    for r in all_rules:
        dc = r.detection_config
        if isinstance(dc, str):
            dc = json.loads(dc)
        dc = dc or {}
        patterns = dc.get("patterns", [])

        # Count NL keyword patterns
        has_nl = False
        for p in patterns:
            if p.get("type") == "regex":
                val = p.get("value", "")
                groups = extract_alternation_keys(val)
                for g, keys, s, e in groups:
                    if can_be_dictionary(keys):
                        has_nl = True
                        total_potential += 1

        if has_nl:
            if migrate_rule(db, r, dict_id_map, cat_map):
                migrated_count += 1

    db.commit()
    print(f"\n=== Summary ===")
    print(f"  Dictionaries created: {len(dict_id_map)}")
    print(f"  Rules migrated: {migrated_count}")
    print(f"  NL keyword patterns found (total): {total_potential}")
    db.close()


if __name__ == "__main__":
    main()
