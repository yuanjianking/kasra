# Code Review Rule Full Verification Test Cases

**Classification:** 代码审查规则全量检测  
**Reference:** `kasra-sdk/rules/_code-review-rules.json` (83 rules)  
**API:** `POST /v1/scan/batch`  
**设计原则:** 测试数据来自真实代码审查场景，模拟开发者提交的包含安全漏洞的代码

---

## A. 凭证泄露 (SEC-01 ~ SEC-04)

### TC-CR-01: SEC-01 — 硬编码云凭证

- **分类:** 代码审查 / 凭证泄露
- **测试观点:** 代码中硬编码了 AWS Access Key，开发者在 review 时未发现
- **测试文件:** `config.py`
- **测试数据:**
```python
# config.py
aws_access_key_id = "AKIA1234567890ABCDEF"
aws_secret_access_key = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEF"
region = "us-east-1"
```
- **预期:** SEC-01 detected → finding

### TC-CR-02: SEC-02 — 硬编码连接字符串

- **分类:** 代码审查 / 凭证泄露
- **测试观点:** 代码库的 .env 文件中直接写了数据库连接字符串
- **测试文件:** `settings.env`
- **测试数据:**
```env
DB_URL = postgresql://admin:secret123@prod-db:5432/mydb
REDIS_URL = redis://:password@cache:6379/0
```
- **预期:** SEC-02 detected → finding

### TC-CR-03: SEC-03 — 硬编码密钥

- **分类:** 代码审查 / 凭证泄露
- **测试观点:** 代码中直接写了签名密钥
- **测试文件:** `jwt_auth.py`
- **测试数据:**
```python
# jwt_auth.py
JWT_SECRET = "my-secret-key-for-jwt-12345"
```
- **预期:** SEC-03 detected → finding

### TC-CR-04: SEC-04 — 残留测试凭证

- **分类:** 代码审查 / 凭证泄露
- **测试观点:** 测试代码中使用了弱密码作为测试数据
- **测试文件:** `test_login.py`
- **测试数据:**
```python
def test_login():
    response = client.post("/login", json={
        "username": "admin",
        "password": "password123"
    })
```
- **预期:** SEC-04 detected → finding

---

## B. 注入漏洞 (SEC-05 ~ SEC-14)

### TC-CR-05: SEC-05 — SQL 注入

- **分类:** 代码审查 / 注入
- **测试观点:** 开发者写了字符串拼接的 SQL 查询，未使用参数化查询
- **测试文件:** `user_repository.py`
- **测试数据:**
```python
def get_user(conn, user_id):
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchone()
```
- **预期:** SEC-05 detected → finding (P0)

### TC-CR-06: SEC-06 — NoSQL 注入

- **分类:** 代码审查 / 注入
- **测试观点:** MongoDB 查询未做输入校验
- **测试文件:** `user_service.js`
- **测试数据:**
```javascript
router.get('/user/:id', async (req, res) => {
    const user = await User.findOne({ $where: `this._id == '${req.params.id}'` });
    res.json(user);
});
```
- **预期:** SEC-06 detected → finding

### TC-CR-07: SEC-07 — OS 命令注入

- **分类:** 代码审查 / 注入
- **测试观点:** 代码中使用 shell=True 执行外部命令
- **测试文件:** `deploy.py`
- **测试数据:**
```python
import subprocess
subprocess.call(f"rm -rf /backups/{backup_name}", shell=True)
```
- **预期:** SEC-07 detected → finding (P0)

### TC-CR-08: SEC-08 — 不安全反序列化

- **分类:** 代码审查 / 注入
- **测试观点:** 代码直接反序列化用户提供的 pickle 数据
- **测试文件:** `data_loader.py`
- **测试数据:**
```python
import pickle
def load_user_data(data):
    return pickle.loads(data)
```
- **预期:** SEC-08 detected → finding (P0)

### TC-CR-09: SEC-09 — XXE (XML 注入)

- **分类:** 代码审查 / 注入
- **测试观点:** XML 解析器未禁用外部实体
- **测试文件:** `xml_parser.py`
- **测试数据:**
```python
from lxml import etree
def parse_xml(xml_string):
    return etree.fromstring(xml_string)
```
- **预期:** SEC-09 detected → finding (P0)

### TC-CR-10: SEC-10 — LDAP 注入

- **分类:** 代码审查 / 注入
- **测试观点:** LDAP 查询使用了字符串拼接
- **测试文件:** `ldap_auth.py`
- **测试数据:**
```python
search_filter = f"(uid={user_input})"
ldap_conn.search(base_dn, search_filter)
```
- **预期:** SEC-10 detected → finding

### TC-CR-11: SEC-11 — SSTI (模板注入)

- **分类:** 代码审查 / 注入
- **测试观点:** Flask 应用直接渲染用户输入到模板
- **测试文件:** `app.py`
- **测试数据:**
```python
from flask import render_template_string
@app.route('/hello')
def hello():
    name = request.args.get('name', '')
    return render_template_string(f"Hello {name}!")
```
- **预期:** SEC-11 detected → finding

### TC-CR-12: SEC-12 — Header 注入

- **分类:** 代码审查 / 注入
- **测试观点:** Response header 直接使用了用户输入
- **测试文件:** `middleware.js`
- **测试数据:**
```javascript
app.use((req, res) => {
    res.setHeader('Location', req.query.redirect_url);
});
```
- **预期:** SEC-12 detected → finding

### TC-CR-13: SEC-13 — 原型链污染

- **分类:** 代码审查 / 注入
- **测试观点:** 使用了不安全的深拷贝合并
- **测试文件:** `utils.js`
- **测试数据:**
```javascript
const _ = require('lodash');
function mergeConfig(defaults, userConfig) {
    return _.merge(defaults, userConfig);
}
```
- **预期:** SEC-13 detected → finding

### TC-CR-14: SEC-14 — 代码注入 (eval)

- **分类:** 代码审查 / 注入
- **测试观点:** 代码中使用了 eval 执行用户输入
- **测试文件:** `calc.js`
- **测试数据:**
```javascript
function calculate(expression) {
    return eval(expression);
}
```
- **预期:** SEC-14 detected → finding (P0)

---

## C. Web 安全 (SEC-15 ~ SEC-31)

### TC-CR-15: SEC-15 — XSS 跨站脚本

- **分类:** 代码审查 / Web 安全
- **测试观点:** 前端代码直接将用户内容设为 innerHTML
- **测试文件:** `Comment.jsx`
- **测试数据:**
```jsx
function Comment({ userContent }) {
    return <div dangerouslySetInnerHTML={{ __html: userContent }} />;
}
```
- **预期:** SEC-15 detected → finding (P0)

### TC-CR-16: SEC-16 — CORS 配置错误

- **分类:** 代码审查 / Web 安全
- **测试观点:** API 服务配置了允许所有来源的 CORS
- **测试文件:** `app.py`
- **测试数据:**
```python
from flask_cors import CORS
app = Flask(__name__)
CORS(app, origins="*")
```
- **预期:** SEC-16 detected → finding

### TC-CR-17: SEC-17 — CSRF 保护缺失

- **分类:** 代码审查 / Web 安全
- **测试观点:** Flask 路由上使用了 csrf.exempt
- **测试文件:** `routes.py`
- **测试数据:**
```python
@app.route('/transfer', methods=['POST'])
@csrf.exempt
def transfer():
    ...
```
- **预期:** SEC-17 detected → finding

### TC-CR-18: SEC-18 — 缺少鉴权

- **分类:** 代码审查 / Web 安全
- **测试观点:** API 路由缺少认证中间件
- **测试文件:** `routes.js`
- **测试数据:**
```javascript
router.get('/admin/users', (req, res) => {
    // No authentication check
    User.find({}, (err, users) => res.json(users));
});
```
- **预期:** SEC-18 detected → finding

### TC-CR-19: SEC-19 — SSRF 服务端请求伪造

- **分类:** 代码审查 / Web 安全
- **测试观点:** 后端直接请求了用户提供的 URL
- **测试文件:** `proxy.py`
- **测试数据:**
```python
def fetch_url(user_url):
    response = requests.get(user_url)
    return response.text
```
- **预期:** SEC-19 detected → finding (P0)

### TC-CR-20: SEC-20 — 开放重定向

- **分类:** 代码审查 / Web 安全
- **测试观点:** 登录后重定向地址未做校验
- **测试文件:** `auth.py`
- **测试数据:**
```python
@app.route('/login')
def login():
    next_url = request.args.get('next')
    return redirect(next_url)
```
- **预期:** SEC-20 detected → finding

### TC-CR-21: SEC-21 — 文件上传无限制

- **分类:** 代码审查 / Web 安全
- **测试观点:** 文件上传未校验类型和路径
- **测试文件:** `upload.py`
- **测试数据:**
```python
@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['file']
    file.save("/uploads/" + file.filename)
```
- **预期:** SEC-21 detected → finding (P0)

### TC-CR-22: SEC-22 — IDOR 越权

- **分类:** 代码审查 / Web 安全
- **测试观点:** 未校验当前用户是否有权限操作其他用户的资源
- **测试文件:** `profile.js`
- **测试数据:**
```javascript
router.get('/user/:id', (req, res) => {
    db.findById(req.params.id, (err, user) => {
        res.json(user);
    });
});
```
- **预期:** SEC-22 detected → finding

### TC-CR-23: SEC-23 — 文件包含 (LFI/RFI)

- **分类:** 代码审查 / Web 安全
- **测试观点:** PHP 代码直接包含用户输入的文件路径
- **测试文件:** `view.php`
- **测试数据:**
```php
<?php include($_GET['page'] . '.php'); ?>
```
- **预期:** SEC-23 detected → finding (P0)

### TC-CR-24: SEC-24 — 批量赋值

- **分类:** 代码审查 / Web 安全
- **测试观点:** 直接将 request body 更新到数据库
- **测试文件:** `api.js`
- **测试数据:**
```javascript
router.put('/user/:id', (req, res) => {
    User.findByIdAndUpdate(req.params.id, req.body);
});
```
- **预期:** SEC-24 detected → finding

### TC-CR-25: SEC-25 — JWT 安全缺陷

- **分类:** 代码审查 / Web 安全
- **测试观点:** JWT 验证跳过了签名校验
- **测试文件:** `auth_middleware.py`
- **测试数据:**
```python
def verify_token(token):
    payload = jwt.decode(token, options={"verify_signature": False})
    return payload
```
- **预期:** SEC-25 detected → finding

### TC-CR-26: SEC-26 — 缺少安全响应头

- **分类:** 代码审查 / Web 安全
- **测试观点:** nginx 配置中缺少 CSP 等安全头
- **测试文件:** `nginx.conf`
- **测试数据:**
```
server {
    listen 80;
    # Missing: add_header Content-Security-Policy ...
}
```
- **预期:** SEC-26 detected → finding

### TC-CR-27: SEC-27 — 会话管理缺陷

- **分类:** 代码审查 / Web 安全
- **测试观点:** 使用了可预测的会话 ID
- **测试文件:** `session.py`
- **测试数据:**
```python
session_id = hashlib.md5(str(time.time()).encode()).hexdigest()
```
- **预期:** SEC-27 detected → finding

### TC-CR-28: SEC-28 — OAuth 安全缺陷

- **分类:** 代码审查 / Web 安全
- **测试观点:** 使用了隐式授权流程（返回 token）
- **测试文件:** `oauth_config.py`
- **测试数据:**
```python
OAUTH_CONFIG = {
    'response_type': 'token',
    'redirect_uri': 'https://app.example.com/callback'
}
```
- **预期:** SEC-28 detected → finding

### TC-CR-29: SEC-29 — WebSocket 安全

- **分类:** 代码审查 / Web 安全
- **测试观点:** WebSocket 连接使用明文协议
- **测试文件:** `chat.js`
- **测试数据:**
```javascript
const socket = new WebSocket("ws://chat.example.com");
```
- **预期:** SEC-29 detected → finding

### TC-CR-30: SEC-30 — gRPC 安全

- **分类:** 代码审查 / Web 安全
- **测试观点:** gRPC 连接未启用 TLS
- **测试文件:** `grpc_client.py`
- **测试数据:**
```python
channel = grpc.insecure_channel('localhost:50051')
```
- **预期:** SEC-30 detected → finding

### TC-CR-31: SEC-31 — GraphQL 安全

- **分类:** 代码审查 / Web 安全
- **测试观点:** 生产环境开启了 GraphQL introspection
- **测试文件:** `graphql_server.py`
- **测试数据:**
```python
app.add_route('/graphql', GraphQLView.as_view(
    'graphql',
    schema=schema,
    graphiql=True  # introspection enabled
))
```
- **预期:** SEC-31 detected → finding

---

## D. 密码学 (SEC-32 ~ SEC-35)

### TC-CR-32: SEC-32 — 弱加密算法

- **分类:** 代码审查 / 密码学
- **测试观点:** 使用了 MD5 或 DES 等弱加密算法
- **测试文件:** `hash_utils.py`
- **测试数据:**
```python
import hashlib
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
```
- **预期:** SEC-32 detected → finding

### TC-CR-33: SEC-33 — 不安全的随机数

- **分类:** 代码审查 / 密码学
- **测试观点:** 使用 random 而不是 secrets 生成安全令牌
- **测试文件:** `token_gen.py`
- **测试数据:**
```python
import random
def generate_reset_token():
    return str(random.randint(100000, 999999))
```
- **预期:** SEC-33 detected → finding

### TC-CR-34: SEC-34 — TLS 验证禁用

- **分类:** 代码审查 / 密码学
- **测试观点:** 代码禁用了 SSL 证书验证
- **测试文件:** `ssl_client.py`
- **测试数据:**
```python
import ssl
ssl._create_default_https_context = ssl._create_unverified_context
```
- **预期:** SEC-34 detected → finding

### TC-CR-35: SEC-35 — 不安全的证书存储

- **分类:** 代码审查 / 密码学
- **测试观点:** 使用了 ALLOW_ALL_HOSTNAME_VERIFIER
- **测试文件:** `JerseyClient.java`
- **测试数据:**
```java
HttpsURLConnection.setDefaultHostnameVerifier(
    new HostnameVerifier() {
        public boolean verify(String hostname, SSLSession session) {
            return true;  // ALLOW_ALL
        }
    }
);
```
- **预期:** SEC-35 detected → finding

---

## E. 基础设施配置 (SEC-36 ~ SEC-44)

### TC-CR-36: SEC-36 — CI 脚本风险

- **分类:** 代码审查 / 基础设施
- **测试观点:** CI 脚本中使用了直接管道执行远程脚本
- **测试文件:** `deploy.sh`
- **测试数据:**
```bash
curl -s https://example.com/deploy.sh | bash
```
- **预期:** SEC-36 detected → finding

### TC-CR-37: SEC-37 — Debug 模式打开

- **分类:** 代码审查 / 安全配置
- **测试观点:** 生产环境配置文件中开启了 Debug 模式
- **测试文件:** `production_settings.py`
- **测试数据:**
```python
DEBUG = True
ALLOWED_HOSTS = ['*']
```
- **预期:** SEC-37 detected → finding (P0)

### TC-CR-38: SEC-38 — 不安全的默认配置

- **分类:** 代码审查 / 安全配置
- **测试观点:** 使用了默认密钥
- **测试文件:** `.env`
- **测试数据:**
```env
SECRET_KEY=changeme
```
- **预期:** SEC-38 detected → finding

### TC-CR-39: SEC-39 — 依赖混淆

- **分类:** 代码审查 / 基础设施
- **测试观点:** package.json 引用了可疑的内部包
- **测试文件:** `package.json`
- **测试数据:**
```json
{
  "dependencies": {
    "@company-internal-lib": "^1.0",
    "acme-private-sdk": "^2.3"
  }
}
```
- **预期:** SEC-39 detected → finding

### TC-CR-40: SEC-40 — 已知 CVE 版本

- **分类:** 代码审查 / 基础设施
- **测试观点:** 依赖中存在已知漏洞的旧版本
- **测试文件:** `requirements.txt`
- **测试数据:**
```
flask==0.12.3
requests==2.20.0
```
- **预期:** SEC-40 detected → finding (P0)

### TC-CR-41: SEC-41 — 缺少 SRI

- **分类:** 代码审查 / 基础设施
- **测试观点:** CDN 引入的脚本没有完整性校验
- **测试文件:** `index.html`
- **测试数据:**
```html
<script src="https://cdn.example.com/react@18.2.0/umd/react.production.min.js"></script>
```
- **预期:** SEC-41 detected → finding

### TC-CR-42: SEC-42 — 明文通信

- **分类:** 代码审查 / 基础设施
- **测试观点:** 代码中使用了 HTTP 而非 HTTPS
- **测试文件:** `api_client.py`
- **测试数据:**
```python
API_BASE_URL = "http://api.example.com/v1"
```
- **预期:** SEC-42 detected → finding

### TC-CR-43: SEC-43 — 可观测数据泄露

- **分类:** 代码审查 / 基础设施
- **测试观点:** Spring Actuator 端点暴露在生产环境
- **测试文件:** `application.yml`
- **测试数据:**
```yaml
management:
  endpoints:
    web:
      exposure:
        include: "*"
```
- **预期:** SEC-43 detected → finding

### TC-CR-44: SEC-44 — CI/CD 攻击面

- **分类:** 代码审查 / 基础设施
- **测试观点:** GitHub Actions 赋予了 write-all 权限
- **测试文件:** `.github/workflows/ci.yml`
- **测试数据:**
```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      issues: write
```
- **预期:** SEC-44 detected → finding

---

## F. 设计缺陷 (SEC-45 ~ SEC-54)

### TC-CR-45: SEC-45 — 路径遍历

- **分类:** 代码审查 / 设计缺陷
- **测试观点:** 文件路径直接拼接用户输入
- **测试文件:** `file_handler.py`
- **测试数据:**
```python
def read_file(filename):
    with open(os.path.join('/var/data', filename), 'r') as f:
        return f.read()
```
- **预期:** SEC-45 detected → finding (P0)

### TC-CR-46: SEC-46 — 竞态条件 (TOCTOU)

- **分类:** 代码审查 / 设计缺陷
- **测试观点:** 检查文件和操作文件之间存在竞态窗口
- **测试文件:** `file_ops.py`
- **测试数据:**
```python
if os.path.exists(temp_file):
    os.remove(temp_file)
```
- **预期:** SEC-46 detected → finding

### TC-CR-47: SEC-47 — 资源耗尽

- **分类:** 代码审查 / 设计缺陷
- **测试观点:** 无限制的循环或连接池可能耗尽系统资源
- **测试文件:** `worker.py`
- **测试数据:**
```python
while True:
    result = requests.get("http://example.com/api")
    process(result)
```
- **预期:** SEC-47 detected → finding

### TC-CR-48: SEC-48 — Zip Slip

- **分类:** 代码审查 / 设计缺陷
- **测试观点:** 解压时未检查文件路径是否超出目标目录
- **测试文件:** `archive.py`
- **测试数据:**
```python
import zipfile
with zipfile.ZipFile('archive.zip') as zf:
    zf.extractall('/tmp/output')
```
- **预期:** SEC-48 detected → finding

### TC-CR-49: SEC-49 — 内存安全

- **分类:** 代码审查 / 设计缺陷
- **测试观点:** C 代码使用了 gets() 等不安全函数
- **测试文件:** `buffer.c`
- **测试数据:**
```c
#include <stdio.h>
int main() {
    char buffer[64];
    printf("Enter name: ");
    gets(buffer);
    printf("Hello, %s\n", buffer);
    return 0;
}
```
- **预期:** SEC-49 detected → finding

### TC-CR-50: SEC-50 — 错误信息泄露

- **分类:** 代码审查 / 设计缺陷
- **测试观点:** 异常信息直接返回给客户端
- **测试文件:** `api_error.py`
- **测试数据:**
```python
@app.errorhandler(Exception)
def handle_error(error):
    return traceback.format_exc(), 500
```
- **预期:** SEC-50 detected → finding

### TC-CR-51: SEC-51 — 不安全的命令执行

- **分类:** 代码审查 / 设计缺陷
- **测试观点:** 直接调用 os.system 执行系统命令
- **测试文件:** `exec.py`
- **测试数据:**
```python
import os
os.system("rm -rf /tmp/backups")
```
- **预期:** SEC-51 detected → finding (P0)

### TC-CR-52: SEC-52 — 日志注入

- **分类:** 代码审查 / 设计缺陷
- **测试观点:** 将用户输入直接写入日志
- **测试文件:** `logger.py`
- **测试数据:**
```python
import logging
logger.info(f"User input: {user_input}")
```
- **预期:** SEC-52 detected → finding

### TC-CR-53: SEC-53 — 整数溢出

- **分类:** 代码审查 / 设计缺陷
- **测试观点:** 余额减法没有检查是否小于零
- **测试文件:** `wallet.py`
- **测试数据:**
```python
def withdraw(balance, amount):
    balance -= amount
    return balance
```
- **预期:** SEC-53 detected → finding

### TC-CR-54: SEC-54 — 空指针解引用

- **分类:** 代码审查 / 设计缺陷
- **测试观点:** 从数据库查找的对象未做 null 检查就使用
- **测试文件:** `UserService.java`
- **测试数据:**
```java
public User getUser(String id) {
    User user = userRepository.findById(id).orElse(null);
    return user.toDTO();  // possible NPE
}
```
- **预期:** SEC-54 detected → finding

---

## G. 数据保护 (SEC-55 ~ SEC-59)

### TC-CR-55: SEC-55 — 明文密码存储

- **分类:** 代码审查 / 数据保护
- **测试观点:** SQL 中直接将密码明文插入
- **测试文件:** `user_repo.sql`
- **测试数据:**
```sql
INSERT INTO users (username, password) VALUES ('admin', 'admin123');
```
- **预期:** SEC-55 detected → finding

### TC-CR-56: SEC-56 — 弱密码策略

- **分类:** 代码审查 / 数据保护
- **测试观点:** 密码长度限制只有 4 位
- **测试文件:** `auth_policy.py`
- **测试数据:**
```python
MIN_PASSWORD_LENGTH = 4
```
- **预期:** SEC-56 detected → finding

### TC-CR-57: SEC-57 — 审计日志缺失

- **分类:** 代码审查 / 数据保护
- **测试观点:** 敏感操作没有审计日志
- **测试文件:** `account_service.py`
- **测试数据:**
```python
def delete_user_account(user_id):
    db.execute("DELETE FROM users WHERE id = %s", (user_id,))
    # No audit logging
```
- **预期:** SEC-57 detected → finding

### TC-CR-58: SEC-58 — 缺少暴力破解防护

- **分类:** 代码审查 / 数据保护
- **测试观点:** 登录接口没有限制尝试次数
- **测试文件:** `login.py`
- **测试数据:**
```python
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    user = authenticate(username, password)
    if user:
        return redirect('/dashboard')
    return render_template('login.html', error='Invalid credentials')
```
- **预期:** SEC-58 detected → finding

### TC-CR-59: SEC-59 — 数据删除不完整

- **分类:** 代码审查 / 数据保护
- **测试观点:** 软删除后没有清理机制
- **测试文件:** `models.py`
- **测试数据:**
```python
class User(Model):
    is_deleted = BooleanField(default=False)
    # No cascade delete for related records
```
- **预期:** SEC-59 detected → finding

---

## H. 移动安全 (SEC-60 ~ SEC-66)

### TC-CR-60: SEC-60 — WebView 配置不安全

- **分类:** 代码审查 / 移动安全
- **测试观点:** Android WebView 启用了 JavaScript 且未限制
- **测试文件:** `WebViewActivity.java`
- **测试数据:**
```java
WebView webView = findViewById(R.id.webview);
webView.getSettings().setJavaScriptEnabled(true);
webView.loadUrl(url);
```
- **预期:** SEC-60 detected → finding (P0)

### TC-CR-61: SEC-61 — 不安全的本地存储

- **分类:** 代码审查 / 移动安全
- **测试观点:** 敏感数据直接存在 SharedPreferences 中
- **测试文件:** `TokenStorage.java`
- **测试数据:**
```java
SharedPreferences prefs = getSharedPreferences("auth", MODE_PRIVATE);
prefs.edit().putString("auth_token", token).apply();
```
- **预期:** SEC-61 detected → finding

### TC-CR-62: SEC-62 — Deep Link 劫持

- **分类:** 代码审查 / 移动安全
- **测试观点:** Activity 导出为 true 可被外部应用启动
- **测试文件:** `AndroidManifest.xml`
- **测试数据:**
```xml
<activity android:name=".AuthActivity" android:exported="true" />
```
- **预期:** SEC-62 detected → finding

### TC-CR-63: SEC-63 — 备份泄露

- **分类:** 代码审查 / 移动安全
- **测试观点:** Android 应用允许备份导致敏感数据泄露
- **测试文件:** `AndroidManifest.xml`
- **测试数据:**
```xml
<application android:allowBackup="true" ...>
```
- **预期:** SEC-63 detected → finding

### TC-CR-64: SEC-64 — 证书绑定缺失

- **分类:** 代码审查 / 移动安全
- **测试观点:** 移动应用未做证书绑定，易受 MITM 攻击
- **测试文件:** `NetworkClient.java`
- **测试数据:**
```java
OkHttpClient client = new OkHttpClient.Builder()
    .build();  // No certificate pinning
```
- **预期:** SEC-64 detected → finding

### TC-CR-65: SEC-65 — 截图泄露

- **分类:** 代码审查 / 移动安全
- **测试观点:** 敏感页面没有禁止截图的 FLAG_SECURE
- **测试文件:** `SecureActivity.kt`
- **测试数据:**
```kotlin
class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Missing: window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
    }
}
```
- **预期:** SEC-65 detected → finding

### TC-CR-66: SEC-66 — 剪贴板泄露

- **分类:** 代码审查 / 移动安全
- **测试观点:** 应用读取了系统剪贴板内容
- **测试文件:** `ClipboardService.java`
- **测试数据:**
```java
ClipboardManager clipboard = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
ClipData clip = clipboard.getPrimaryClip();
String text = clip.getItemAt(0).getText().toString();
```
- **预期:** SEC-66 detected → finding

---

## I. IaC — Docker 安全 (IAC-01 ~ IAC-03)

### TC-CR-67: IAC-01 — Dockerfile 未指定版本

- **分类:** 代码审查 / IaC Docker
- **测试观点:** Dockerfile 使用了 latest 标签并且运行在 root
- **测试文件:** `Dockerfile`
- **测试数据:**
```dockerfile
FROM python:latest
USER root
COPY . /app
RUN pip install -r requirements.txt
CMD ["python", "app.py"]
```
- **预期:** IAC-01 detected → finding

### TC-CR-68: IAC-02 — Docker Compose 暴露端口

- **分类:** 代码审查 / IaC Docker
- **测试观点:** 数据库端口暴露到了所有网络接口
- **测试文件:** `docker-compose.yml`
- **测试数据:**
```yaml
version: '3'
services:
  postgres:
    ports:
      - "0.0.0.0:5432:5432"
```
- **预期:** IAC-02 detected → finding

### TC-CR-69: IAC-03 — 容器特权模式

- **分类:** 代码审查 / IaC Docker
- **测试观点:** 容器以特权模式运行
- **测试文件:** `pod.yaml`
- **测试数据:**
```yaml
spec:
  containers:
  - name: app
    securityContext:
      privileged: true
```
- **预期:** IAC-03 detected → finding

---

## J. IaC — Kubernetes (IAC-04 ~ IAC-07)

### TC-CR-70: IAC-04 — K8s 工作负载特权提升

- **分类:** 代码审查 / IaC Kubernetes
- **测试观点:** 容器允许特权提升
- **测试文件:** `deployment.yaml`
- **测试数据:**
```yaml
spec:
  containers:
  - name: app
    securityContext:
      allowPrivilegeEscalation: true
```
- **预期:** IAC-04 detected → finding

### TC-CR-71: IAC-05 — K8s NodePort 暴露

- **分类:** 代码审查 / IaC Kubernetes
- **测试观点:** 使用了 NodePort 类型暴露服务
- **测试文件:** `service.yaml`
- **测试数据:**
```yaml
spec:
  type: NodePort
  ports:
  - port: 30080
```
- **预期:** IAC-05 detected → finding

### TC-CR-72: IAC-06 — K8s RBAC 权限过大

- **分类:** 代码审查 / IaC Kubernetes
- **测试观点:** RBAC 权限配置为通配符
- **测试文件:** `rbac.yaml`
- **测试数据:**
```yaml
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
```
- **预期:** IAC-06 detected → finding

### TC-CR-73: IAC-07 — K8s Secret 引用错误

- **分类:** 代码审查 / IaC Kubernetes
- **测试观点:** Secret 没有使用加密存储
- **测试文件:** `secret.yaml`
- **测试数据:**
```yaml
kind: Secret
metadata:
  name: db-credentials
type: Opaque
data:
  password: c3VwZXJzZWNyZXQ=
```
- **预期:** IAC-07 detected → finding

---

## K. IaC — Terraform (IAC-08 ~ IAC-11)

### TC-CR-74: IAC-08 — S3 存储公开

- **分类:** 代码审查 / IaC Terraform
- **测试观点:** S3 Bucket 配置为公共读
- **测试文件:** `s3.tf`
- **测试数据:**
```hcl
resource "aws_s3_bucket" "data" {
  bucket = "company-data"
  acl    = "public-read"
}
```
- **预期:** IAC-08 detected → finding

### TC-CR-75: IAC-09 — 安全组开放

- **分类:** 代码审查 / IaC Terraform
- **测试观点:** 安全组对全互联网开放 SSH
- **测试文件:** `network.tf`
- **测试数据:**
```hcl
ingress {
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}
```
- **预期:** IAC-09 detected → finding

### TC-CR-76: IAC-10 — IAM 权限过大

- **分类:** 代码审查 / IaC Terraform
- **测试观点:** IAM Policy 允许所有操作
- **测试文件:** `iam.tf`
- **测试数据:**
```hcl
statement {
  effect    = "Allow"
  actions   = ["*"]
  resources = ["*"]
}
```
- **预期:** IAC-10 detected → finding

### TC-CR-77: IAC-11 — Terraform 本地状态

- **分类:** 代码审查 / IaC Terraform
- **测试观点:** Terraform 状态存储在本地（不支持多人协作且有泄露风险）
- **测试文件:** `backend.tf`
- **测试数据:**
```hcl
terraform {
  backend "local" {}
}
```
- **预期:** IAC-11 detected → finding

---

## L. IaC — 其他 (IAC-12 ~ IAC-17)

### TC-CR-78: IAC-12 — Ansible 密码泄露

- **分类:** 代码审查 / IaC 配置管理
- **测试观点:** Ansible playbook 中硬编码了密码
- **测试文件:** `playbook.yml`
- **测试数据:**
```yaml
- hosts: all
  vars:
    ansible_become_password: "secret123"
```
- **预期:** IAC-12 detected → finding

### TC-CR-79: IAC-13 — Helm 使用 latest 标签

- **分类:** 代码审查 / IaC Helm
- **测试观点:** Helm values 中镜像标签为 latest
- **测试文件:** `values.yaml`
- **测试数据:**
```yaml
image:
  repository: myapp
  tag: latest
```
- **预期:** IAC-13 detected → finding

### TC-CR-80: IAC-14 — CloudFormation 安全组

- **分类:** 代码审查 / IaC AWS
- **测试观点:** CloudFormation 安全组开放了所有来源访问
- **测试文件:** `template.yaml`
- **测试数据:**
```yaml
Type: AWS::EC2::SecurityGroup
Properties:
  SecurityGroupIngress:
  - CidrIp: 0.0.0.0/0
    FromPort: 443
    ToPort: 443
```
- **预期:** IAC-14 detected → finding

### TC-CR-81: IAC-15 — Serverless 无认证

- **分类:** 代码审查 / IaC Serverless
- **测试观点:** Serverless 函数设置了 auth: NONE
- **测试文件:** `serverless.yml`
- **测试数据:**
```yaml
functions:
  hello:
    handler: handler.hello
    events:
      - httpApi:
          method: GET
          path: /hello
          auth: NONE
```
- **预期:** IAC-15 detected → finding

### TC-CR-82: IAC-16 — Pulumi 无加密

- **分类:** 代码审查 / IaC Pulumi
- **测试观点:** Pulumi 配置未启用加密
- **测试文件:** `Pulumi.yaml`
- **测试数据:**
```yaml
name: myproject
runtime: python
description: Production infrastructure
```
- **预期:** IAC-16 detected → finding

### TC-CR-83: IAC-17 — Serverless 函数权限过大

- **分类:** 代码审查 / IaC Serverless
- **测试观点:** Lambda 函数拥有过大的执行权限
- **测试文件:** `serverless.yml`
- **测试数据:**
```yaml
provider:
  iam:
    role: arn:aws:iam::*:role/lambda-execute-*
```
- **预期:** IAC-17 detected → finding
