# Rule Enable/Disable Full Verification Test Cases

**分类:** 规则启用/禁用全量测试  
**设计原则:** 模拟安全管理员日常操作场景，不做 SDK 内部实现假设

---

## A. 运行时启用/禁用 (I/O 规则)

### TC-ED-01: 安全管理员在页面上禁用一条输入规则

- **测试观点:** 某条 I-系列规则误报较多，安全管理员将其禁用；禁用后对应的检测应不再生效
- **测试步骤:**
  1. GET /v1/rules/I-01 → enabled=true
  2. 输入 I-01 能检出的敏感内容 → blocked=true
  3. PUT /v1/rules/I-01 {"enabled": false} → 返回 200
  4. 再次输入同样的内容 → blocked=false
  5. GET /v1/rules/I-01 → enabled=false
- **测试数据:** `"我的 GitHub token 是 ghp_abc123def456ghi789jkl012mno345pqr678stu"`
- **预期:** 禁用后不再阻断

### TC-ED-02: 安全管理员重新启用一条输入规则

- **测试观点:** 问题修复后管理员重新启用规则，恢复阻断能力
- **测试步骤:**
  1. PUT /v1/rules/I-01 {"enabled": true} → 200
  2. 输入 I-01 能检出的内容 → blocked=true
- **预期:** 重新启用后恢复阻断

### TC-ED-03: 禁用一条输出规则

- **测试观点:** 管理员禁用 O-02 后，输出不再被阻断
- **测试数据:** `"在 shell 里执行 rm -rf / 来清理"`
- **预期:** 禁用 O-02 → 不再阻断

### TC-ED-04: 同时禁用多条规则

- **测试观点:** 禁用 I-01 和 I-06 后只有这两条失效，其他规则不受影响
- **测试步骤:**
  1. 禁用 I-01 和 I-06
  2. 用 I-01 可检出的内容 → not blocked
  3. 用 I-06 可检出的内容 → not blocked
  4. 用 I-21 可检出的内容 → BLOCKED（I-21 未禁用）
- **预期:** 只有被禁用的规则受影响

### TC-ED-05: 禁用不存在的规则

- **测试观点:** 尝试禁用一个不存在的规则 ID 应返回 404
- **测试步骤:** PUT /v1/rules/INVALID-ID {"enabled": false}
- **预期:** 404 Not Found

---

## B. 运行时启用/禁用 (代码审查规则)

### TC-ED-06: 禁用一条代码审查规则

- **测试观点:** SEC-05 误报过多，管理员禁用后批量扫描不再检出 SQL 注入
- **测试步骤:**
  1. 创建含 SQL 注入的 .py 文件
  2. 扫描 → findings 中包含 SEC-05
  3. PUT /v1/rules/SEC-05 {"enabled": false}
  4. 再次扫描同一文件 → findings 中不包含 SEC-05
- **测试数据:** `cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")`
- **预期:** 禁用后不再检出

### TC-ED-07: 重新启用代码审查规则

- **测试观点:** 重新启用 SEC-05 后恢复检测
- **测试步骤:**
  1. PUT /v1/rules/SEC-05 {"enabled": true}
  2. 扫描含 SQL 注入的文件 → findings 包含 SEC-05
- **预期:** 恢复检测

### TC-ED-08: 禁用多条代码审查规则

- **测试观点:** 禁用 SEC-05 和 SEC-07，分别验证互不影响
- **预期:** 仅禁用的规则失效

---

## C. I/O 规则和代码审查规则独立操作

### TC-ED-09: 两种规则互不影响

- **测试观点:** 禁用 I 系列规则不影响 SEC 系列规则，反之亦然
- **测试步骤:**
  1. 禁用 I-01（输入规则）
  2. 禁用 SEC-05（代码审查规则）
  3. 输入 I-06 能检出的内容 → blocked=true（I-06 未禁用）
  4. 扫描含命令注入的文件 → SEC-07 检出（SEC-07 未禁用）
- **预期:** 两种规则独立管理

---

## D. 重启持久化

### TC-ED-10: 禁用状态重启后保持

- **测试观点:** 管理员禁用的规则重启容器后仍然禁用
- **测试步骤:**
  1. PUT /v1/rules/I-01 {"enabled": false}
  2. PUT /v1/rules/SEC-05 {"enabled": false}
  3. 重启 kasra-api 容器
  4. GET /v1/rules/I-01 → enabled=false
  5. GET /v1/rules/SEC-05 → enabled=false
  6. 输入 I-01 能检出的内容 → not blocked
  7. 扫描含 SQL 注入的文件 → SEC-05 未检出
- **预期:** 重启后禁用状态保持

### TC-ED-11: 启用状态重启后保持

- **测试观点:** 重新启用后重启容器仍为启用
- **测试步骤:**
  1. 禁用 I-01，重新启用，重启
  2. GET /v1/rules/I-01 → enabled=true
  3. 输入检出内容 → blocked=true
- **预期:** 启用状态保持

---

## E. 自定义规则 (U 系列)

### TC-ED-12: 创建、启用、禁用、删除自定义规则

- **测试观点:** 管理员通过 API 完成自定义规则的完整生命周期
- **测试步骤:**
  1. POST /v1/rules {"id": "U-01", "name": "阻止测试域名", ...} → 201
  2. GET /v1/rules/U-01 → enabled=true
  3. PUT /v1/rules/U-01 {"enabled": false} → 200, enabled=false
  4. PUT /v1/rules/U-01 {"enabled": true} → 200, enabled=true
  5. DELETE /v1/rules/U-01 → 204
  6. GET /v1/rules/U-01 → 404
- **预期:** U 系列规则生命周期完整

### TC-ED-13: 创建自定义规则时 ID 格式不正确

- **测试观点:** 非 U- 前缀的 ID 应被拒绝
- **测试步骤:** POST /v1/rules {"id": "X-01", ...}
- **预期:** 400/422

---

## F. 筛选验证

### TC-ED-14: enabled_only 筛选

- **测试观点:** 筛选所有已启用的规则
- **测试步骤:**
  1. 禁用 I-01
  2. GET /v1/rules?enabled_only=true → 返回的所有规则 enabled=true
  3. 列表中不包含 I-01
- **预期:** 筛选正确

### TC-ED-15: group 分组筛选

- **测试观点:** 按 input / output / code_review 分组筛选
- **测试步骤:**
  1. GET /v1/rules?group=input → 全部 I- 前缀
  2. GET /v1/rules?group=output → 全部 O- 前缀
  3. GET /v1/rules?group=code_review → 全部 SEC-/IAC- 前缀
- **预期:** 分组筛选正确

### TC-ED-16: 组合筛选

- **测试观点:** 同时使用 group + severity + enabled_only
- **测试步骤:** GET /v1/rules?group=input&severity=P0&enabled_only=true
- **预期:** 同时满足三个条件

---

## G. 分页验证

### TC-ED-17: 默认分页

- **测试观点:** 默认的 page_size 和 page 值
- **测试步骤:** GET /v1/rules
- **预期:** page=1, page_size=100, items 不为空

### TC-ED-18: 翻页不重复

- **测试观点:** 第 1 页和第 2 页的内容不重叠
- **测试步骤:** GET /v1/rules?page=1&page_size=50 和 page=2, 对比 ID
- **预期:** ID 无交集
