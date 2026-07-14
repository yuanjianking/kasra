# Database Table Storage Full Verification Test Cases

**分类:** 数据库表存储全量验证  
**设计原则:** 模拟真实业务数据写入，验证每个字段的正确性和跨表一致性

---

## A. audit_logs 表 — 检测事件记录

### TC-DB-01: 输入检测触发后审计日志完整记录

- **测试观点:** 一次输入检测触发了规则，audit_logs 中应生成一条完整记录
- **测试步骤:**
  1. POST /v1/scan/input {"content": "数据库密码是 admin123!@#", "user_id": "wangxiao"}
  2. 查询 audit_logs 表
- **预期字段:**
  | 字段 | 预期 |
  |------|------|
  | id | 自增整数 |
  | timestamp | 当前时间 ±5 秒 |
  | user_id | `wangxiao` |
  | rule_id | `I-06` |
  | severity | `P0` |
  | action | `block` |
  | direction | `input` |
  | content_snippet | 非空，包含部分原文 |
  | matched_text | 非空（密码类可能需要截断） |
  | match_count | >= 1 |
  | status | `pending` |

### TC-DB-02: 输出检测的审计日志

- **测试观点:** 输出检测的日志 direction 为 output
- **测试步骤:**
  1. POST /v1/scan/output {"content": "API Key: sk-proj-xxxx...", "user_id": "lisi"}
  2. 查询 audit_logs
- **预期:** direction = "output"

### TC-DB-03: 批量扫描的审计日志

- **测试观点:** 批量代码扫描的结果记录到 audit_logs，包含文件路径和行号
- **预期:** direction = "batch", file_path 和 line_number 有值

### TC-DB-04: 安全内容不产生审计日志

- **测试观点:** 没有触发规则的内容不应写审计日志
- **测试数据:** `"什么是快速排序？"`
- **预期:** 该请求不产生新的 audit_logs 记录

### TC-DB-05: 多次检测产生多条日志

- **测试观点:** 连续 3 次检测产生至少 3 条审计日志
- **测试步骤:** 同一 user_id 发送 3 条触发检测的内容
- **预期:** 该 user_id 的日志数 >= 3

### TC-DB-06: 时间戳自动生成

- **测试观点:** 时间戳在写入时自动设置为当前时间
- **测试步骤:** 记录请求前后的时间，验证日志时间戳在此范围内

---

## B. audit_chain 表 — 哈希链

### TC-DB-07: 检测事件生成链记录

- **测试观点:** 每次审计日志写入后，audit_chain 生成一条对应记录
- **预期:** batch_hash 是 64 位十六进制字符串（SHA-256），batch_count >= 1

### TC-DB-08: 链式连续性

- **测试观点:** 相邻两条链记录的前后哈希能对上
- **SQL:**
```sql
SELECT a1.batch_hash, a2.prev_hash
FROM audit_chain a1
JOIN audit_chain a2 ON a1.id = a2.id - 1;
```
- **预期:** 每条 a1.batch_hash = a2.prev_hash

### TC-DB-09: 创世块

- **测试观点:** 第一条链记录的 prev_hash 为 "0"
- **预期:** id=1 的 prev_hash = "0"

---

## C. rules 表 — 规则覆盖和自定义规则

### TC-DB-10: 切换规则生成覆盖记录

- **测试观点:** 禁用 I-01 后 rules 表创建一条覆盖记录
- **SQL:**
```sql
SELECT id, enabled, is_custom, source FROM rules WHERE id = 'I-01';
```
- **预期:** enabled=false, is_custom=false, source='sdk'

### TC-DB-11: 创建自定义规则

- **测试观点:** POST 创建 U-01 后数据完整写入
- **预期:** is_custom=true, source='user'

### TC-DB-12: 删除自定义规则

- **测试观点:** DELETE 后 rules 表中记录消失
- **预期:** SELECT 返回空

### TC-DB-13: 删除 SDK 规则覆盖记录

- **测试观点:** DELETE 覆盖记录后，规则恢复到默认启用
- **预期:** 删除后 GET /v1/rules/I-01 → enabled=true

---

## D. users 表 — 用户自动创建

### TC-DB-14: 新用户首次检测自动创建

- **测试观点:** 第一次从 user_id "张三" 发起检测，users 表自动创建记录
- **预期:** username='张三', role='user', is_active=true

### TC-DB-15: 同一用户不会重复创建

- **测试观点:** 同一 user_id 多次检测不会创建多条用户记录
- **预期:** COUNT = 1

### TC-DB-16: 种子数据

- **测试观点:** 启动时 users 表有 admin 用户
- **预期:** username='admin', role='admin', is_active=true

---

## E. user_behavior 表 — 每日活动

### TC-DB-17: 检测事件创建设日汇总

- **测试观点:** 某用户一天内触发了检测，user_behavior 创建当天汇总
- **预期:** total_requests >= 1, blocked_requests >= 1, rule_triggers 非空

### TC-DB-18: 多次事件累计

- **测试观点:** 同一用户同一天多次检测，计数累加
- **预期:** 5 次检测后 total_requests = 5

### TC-DB-19: 不同天不同记录

- **测试观点:** 跨天的请求分别计入不同日期的记录
- **预期:** 同一用户两天各一条记录

---

## F. 跨表完整性

### TC-DB-20: audit_logs 中的 rule_id 存在于 rules

- **SQL:**
```sql
SELECT DISTINCT al.rule_id FROM audit_logs al
LEFT JOIN rules r ON al.rule_id = r.id
WHERE r.id IS NULL;
```
- **预期:** 空结果（所有 rule_id 都有对应规则）

### TC-DB-21: 所有审计日志被链覆盖

- **SQL:**
```sql
SELECT MAX(id) FROM audit_logs;
SELECT MAX(last_log_id) FROM audit_chain;
```
- **预期:** MAX(audit_logs.id) <= MAX(last_log_id)

### TC-DB-22: user_behavior 关联 users

- **测试观点:** user_behavior 中的 user_id 在 users 表中存在
- **预期:** 空结果

### TC-DB-23: 5 张表都存在

- **测试观点:** 数据库中有全部必需的表
- **预期:** audit_logs, audit_chain, rules, users, user_behavior
