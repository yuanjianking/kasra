"""Integration tests: Code Review Rule Full Verification (83 rules).

Real code file snippets that developers might actually commit.
"""
from __future__ import annotations

import os
import tempfile

import pytest
from fastapi.testclient import TestClient


def _make(content: str, suffix: str = ".py") -> str:
    fd, path = tempfile.mkstemp(suffix=suffix, text=True)
    os.write(fd, content.encode("utf-8"))
    os.close(fd)
    return path


def _make_named(content: str, name: str) -> str:
    """Create a temp file with an exact basename in a temp directory.
    Returns the path to the DIRECTORY containing the file.
    """
    import tempfile as tf, shutil
    d = tf.mkdtemp()
    p = os.path.join(d, name)
    with open(p, "w") as f:
        f.write(content)
    return d  # Return the directory, not the file


def _scan(client, auth_headers, path: str) -> list[str]:
    resp = client.post("/v1/scan/batch", json={"path": path, "user_id": "int-cr"}, headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    # Check both possible response formats
    if "findings" in data:
        return [f["rule_id"] for f in data["findings"]]
    if "results" in data:
        ids = []
        for r in data["results"]:
            ids.extend(t["rule_id"] for t in r.get("triggered_rules", []))
        return ids
    return []


# ===========================================================================
# A. Credential Leak
# ===========================================================================

class TestCredentialLeak:
    def test_sec_01_cloud_creds(self, client, auth_headers):
        p = _make('aws_access_key_id = "AKIA1234567890ABCDEF"\nsecret = "abcdefghijklmnopqrstuvwxyz1234567890ABCDEF"\n', ".env")
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-01" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_02_conn_string(self, client, auth_headers):
        p = _make('DB_URL = postgresql://admin:secret123@prod-db:5432/mydb\n', ".env")
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-02" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_03_crypto_key(self, client, auth_headers):
        p = _make('JWT_SECRET = "my-secret-key-for-jwt-12345"\n')
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-03" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_04_test_creds(self, client, auth_headers):
        p = _make('def test_login():\n    resp = client.post("/login", json={"user": "admin", "password": "password123"})\n')
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-04" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)


# ===========================================================================
# B. Injection
# ===========================================================================

class TestInjection:
    def test_sec_05_sql(self, client, auth_headers):
        p = _make('def get_user(conn, uid):\n    cur = conn.cursor()\n    cur.execute(f"SELECT * FROM users WHERE id = {uid}")\n    return cur.fetchone()\n')
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-05" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_06_nosql(self, client, auth_headers):
        p = _make("router.get('/user/:id', async (req, res) => {\n  const u = await User.findOne({ $where: `this._id == '${req.params.id}'` });\n  res.json(u);\n});\n", ".js")
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-06" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_07_cmd_injection(self, client, auth_headers):
        p = _make('import subprocess\nsubprocess.call(f"rm -rf /backups/{name}", shell=True)\n')
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-07" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_08_pickle(self, client, auth_headers):
        p = _make('import pickle\ndef load(d): return pickle.loads(d)\n')
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-08" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_09_xxe(self, client, auth_headers):
        p = _make('from lxml import etree\ndef parse(x): return etree.fromstring(x)\n')
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-09" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_10_ldap(self, client, auth_headers):
        p = _make('search = "(uid=" + user_input + ")"\nconn.search(base_dn, search)\n')
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-10" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_11_ssti(self, client, auth_headers):
        p = _make('from flask import render_template_string\n@app.route("/hello")\ndef hello():\n    n = request.args.get("name", "")\n    return render_template_string(f"Hello {n}!")\n')
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-11" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_12_header_inject(self, client, auth_headers):
        p = _make('app.use((req, res) => { res.setHeader("Location", req.query.url); });\n', ".js")
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-12" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_13_proto_pollution(self, client, auth_headers):
        p = _make('const _ = require("lodash");\nfunction merge(a, b) { return _.merge(a, b); }\n', ".js")
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-13" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_14_eval(self, client, auth_headers):
        p = _make('function calc(expr) { return eval(expr); }\n', ".js")
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-14" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)


# ===========================================================================
# C. Web Security
# ===========================================================================

class TestWebSecurity:
    def test_sec_15_xss(self, client, auth_headers):
        p = _make('function Comment({content}) { return <div dangerouslySetInnerHTML={{__html: content}} />; }\n', ".jsx")
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-15" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_16_cors(self, client, auth_headers):
        p = _make('from flask_cors import CORS\napp = Flask(__name__)\nCORS(app, origins="*")\n')
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-16" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_17_csrf(self, client, auth_headers):
        p = _make('@app.route("/transfer", methods=["POST"])\n@csrf.exempt\ndef transfer():\n    ...\n')
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-17" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_18_no_auth(self, client, auth_headers):
        p = _make('router.get("/admin/users", (req, res) => {\n  User.find({}, (e, u) => res.json(u));\n});\n', ".js")
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-18" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_19_ssrf(self, client, auth_headers):
        p = _make('def fetch(url): return requests.get(url).text\n')
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-19" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_20_open_redirect(self, client, auth_headers):
        p = _make('@app.route("/login")\ndef login():\n    nxt = request.args.get("next")\n    return redirect(nxt)\n')
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-20" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_21_unrestricted_upload(self, client, auth_headers):
        p = _make('@app.route("/upload", methods=["POST"])\ndef upload():\n    f = request.files["file"]\n    f.save("/uploads/" + f.filename)\n')
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-21" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_22_idor(self, client, auth_headers):
        p = _make('router.get("/user/:id", (req, res) => {\n  db.findById(req.params.id, (e, u) => res.json(u));\n});\n', ".js")
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-22" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_23_lfi(self, client, auth_headers):
        p = _make('<?php include($_GET["page"] . ".php"); ?>\n', ".php")
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-23" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_24_mass_assignment(self, client, auth_headers):
        p = _make('router.put("/user/:id", (req, res) => {\n  User.findByIdAndUpdate(req.params.id, req.body);\n});\n', ".js")
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-24" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_25_jwt(self, client, auth_headers):
        p = _make('def verify(tok):\n    return jwt.decode(tok, options={"verify_signature": False})\n')
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-25" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_26_security_headers(self, client, auth_headers):
        p = _make('response.setHeader("X-Frame-Options", "DENY")\n# Missing CSP header\n', ".py")
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-26" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_27_session(self, client, auth_headers):
        p = _make('import hashlib, time\nsid = hashlib.md5(str(time.time()).encode()).hexdigest()\n')
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-27" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_28_oauth(self, client, auth_headers):
        p = _make("OAUTH = {'response_type': 'token', 'redirect_uri': 'https://app.example.com/cb'}\n")
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-28" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_29_ws(self, client, auth_headers):
        p = _make('const ws = new WebSocket("ws://chat.example.com");\n', ".js")
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-29" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_30_grpc(self, client, auth_headers):
        p = _make('channel = grpc.insecure_channel("localhost:50051")\n')
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-30" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_31_graphql(self, client, auth_headers):
        p = _make("from graphene import Schema\nschema = Schema(query=Query)\n# introspection enabled\n")
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-31" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)


# ===========================================================================
# D. Crypto
# ===========================================================================

class TestCrypto:
    def test_sec_32_md5(self, client, auth_headers):
        p = _make('import hashlib\ndef hash_pw(pw): return hashlib.md5(pw.encode()).hexdigest()\n')
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-32" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_33_insecure_random(self, client, auth_headers):
        p = _make('import random\ndef token(): return str(random.randint(100000, 999999))\n')
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-33" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_34_tls_disabled(self, client, auth_headers):
        p = _make('import ssl\nssl._create_default_https_context = ssl._create_unverified_context\n')
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-34" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_35_cert_storage(self, client, auth_headers):
        p = _make('ALLOW_ALL_HOSTNAME_VERIFIER', ".java")
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-35" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)


# ===========================================================================
# E. Infrastructure Config
# ===========================================================================

class TestInfraConfig:
    def test_sec_36_ci_risk(self, client, auth_headers):
        p = _make('curl -s https://example.com/deploy.sh | bash\n', ".sh")
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-36" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_37_debug_mode(self, client, auth_headers):
        p = _make("DEBUG = True\nALLOWED_HOSTS = ['*']\n")
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-37" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_38_insecure_defaults(self, client, auth_headers):
        p = _make("SECRET_KEY=changeme\n", ".env")
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-38" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_39_dep_confusion(self, client, auth_headers):
        p = _make_named('{"dependencies": {"@company-internal-lib": "^1.0"}}\n', "package.json")
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-39" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_40_cve(self, client, auth_headers):
        p = _make_named("flask==0.12.3\nrequests==2.20.0\n", "requirements.txt")
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-40" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_41_sri(self, client, auth_headers):
        p = _make('<script src="https://cdn.example.com/react@18.2.0/umd/react.production.min.js"></script>\n', ".html")
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-41" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_42_plaintext(self, client, auth_headers):
        p = _make('API_BASE_URL = "http://api.example.com/v1"\n')
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-42" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_43_observability(self, client, auth_headers):
        p = _make("management:\n  endpoints:\n    web:\n      exposure:\n        include: \"*\"\n", ".yml")
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-43" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_44_cicd(self, client, auth_headers):
        p = _make_named("jobs:\n  build:\n    permissions:\n      contents: write\n", "ci.yml")
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-44" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)


# ===========================================================================
# F. Design Flaw
# ===========================================================================

class TestDesignFlaw:
    def test_sec_45_path_traversal(self, client, auth_headers):
        p = _make('def read(fn):\n    with open(os.path.join("/var/data", fn)) as f:\n        return f.read()\n')
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-45" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_46_toctou(self, client, auth_headers):
        p = _make('if os.path.exists(tf):\n    os.remove(tf)\n')
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-46" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_47_resource_exhaust(self, client, auth_headers):
        p = _make('while True:\n    r = requests.get("http://example.com/api")\n    process(r)\n')
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-47" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_48_zip_slip(self, client, auth_headers):
        p = _make('import zipfile\nwith zipfile.ZipFile("a.zip") as z:\n    z.extractall("/tmp/out")\n')
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-48" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_49_memory(self, client, auth_headers):
        p = _make('#include <stdio.h>\nint main() { char buf[64]; gets(buf); printf("%s", buf); }\n', ".c")
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-49" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_50_error_leak(self, client, auth_headers):
        p = _make('@app.errorhandler(Exception)\ndef handle(e): return traceback.format_exc(), 500\n')
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-50" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_51_command_exec(self, client, auth_headers):
        p = _make('import os\nos.system("rm -rf /tmp/out")\n')
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-51" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_52_log_inject(self, client, auth_headers):
        p = _make('import logging\nlogging.info(f"User input: {user_input}")\n')
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-52" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_53_int_overflow(self, client, auth_headers):
        p = _make('def withdraw(bal, amt):\n    bal -= amt\n    return bal\n')
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-53" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_54_null_deref(self, client, auth_headers):
        p = _make('User u = repo.findById(id).orElse(null);\nreturn u.toDTO();\n', ".java")
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-54" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)


# ===========================================================================
# G. Data Protection
# ===========================================================================

class TestDataProtection:
    def test_sec_55_plaintext_pw(self, client, auth_headers):
        p = _make("INSERT INTO users (username, password) VALUES ('admin', 'admin123');\n", ".sql")
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-55" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_56_weak_policy(self, client, auth_headers):
        p = _make("MIN_PASSWORD_LENGTH = 4\n")
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-56" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_57_audit_missing(self, client, auth_headers):
        p = _make("def delete_user(uid):\n    db.execute('DELETE FROM users WHERE id = %s', (uid,))\n    # no audit log\n")
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-57" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_58_brute_force(self, client, auth_headers):
        p = _make("@app.route('/login', methods=['POST'])\ndef login():\n    u = request.form['username']\n    pw = request.form['password']\n    user = auth(u, pw)\n    if user: return redirect('/dash')\n    return render_template('login.html', error='Invalid')\n")
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-58" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_59_incomplete_delete(self, client, auth_headers):
        p = _make("class User(Model):\n    is_deleted = BooleanField(default=False)\n    # no cascade\n")
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-59" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)


# ===========================================================================
# H. Mobile Security
# ===========================================================================

class TestMobileSecurity:
    def test_sec_60_webview(self, client, auth_headers):
        p = _make("webView.getSettings().setJavaScriptEnabled(true);\nwebView.loadUrl(url);\n", ".java")
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-60" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_61_insecure_storage(self, client, auth_headers):
        p = _make("SharedPreferences prefs = getSharedPreferences(\"auth\", MODE_PRIVATE);\nprefs.edit().putString(\"token\", tok).apply();\n", ".java")
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-61" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_62_deep_link(self, client, auth_headers):
        p = _make_named('<activity android:name=".AuthActivity" android:exported="true" />\n', "AndroidManifest.xml")
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-62" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_63_backup(self, client, auth_headers):
        p = _make_named('<application android:allowBackup="true" ...>\n', "AndroidManifest.xml")
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-63" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_64_cert_pinning(self, client, auth_headers):
        p = _make("OkHttpClient client = new OkHttpClient.Builder().build();\n", ".java")
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-64" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_65_screenshot(self, client, auth_headers):
        p = _make("// This Activity is missing FLAG_SECURE\nclass MainActivity : AppCompatActivity() {\n    override fun onCreate(savedInstanceState: Bundle?) {\n        super.onCreate(savedInstanceState)\n    }\n}\n", ".kt")
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-65" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_sec_66_clipboard(self, client, auth_headers):
        p = _make("ClipboardManager cb = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);\nClipData clip = cb.getPrimaryClip();\n", ".java")
        try:
            ids = _scan(client, auth_headers, p)
            assert "SEC-66" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)


# ===========================================================================
# I. IaC Docker
# ===========================================================================

class TestIacDocker:
    def test_iac_01_dockerfile(self, client, auth_headers):
        import shutil as _su
        p = _make_named("FROM python:latest\nUSER root\nCOPY . /app\nRUN pip install -r requirements.txt\nCMD [\"python\", \"app.py\"]\n", "Dockerfile")
        try:
            ids = _scan(client, auth_headers, p)
            assert "IAC-01" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_iac_02_compose(self, client, auth_headers):
        p = _make_named("version: '3'\nservices:\n  postgres:\n    ports:\n      - \"0.0.0.0:5432:5432\"\n", "docker-compose.yml")
        try:
            ids = _scan(client, auth_headers, p)
            assert "IAC-02" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_iac_03_privileged(self, client, auth_headers):
        p = _make("cap_add:\n  - SYS_ADMIN\n", ".yaml")
        try:
            ids = _scan(client, auth_headers, p)
            assert "IAC-03" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)


# ===========================================================================
# J. IaC Kubernetes
# ===========================================================================

class TestIacK8s:
    def test_iac_04_workload(self, client, auth_headers):
        p = _make("securityContext:\n  allowPrivilegeEscalation: true\n", ".yaml")
        try:
            ids = _scan(client, auth_headers, p)
            assert "IAC-04" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_iac_05_nodeport(self, client, auth_headers):
        p = _make("spec:\n  type: NodePort\n  ports:\n  - port: 30080\n", ".yaml")
        try:
            ids = _scan(client, auth_headers, p)
            assert "IAC-05" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_iac_06_rbac(self, client, auth_headers):
        p = _make("rules:\n- apiGroups: [\"*\"]\n  resources: [\"*\"]\n  verbs: [\"*\"]\n", ".yaml")
        try:
            ids = _scan(client, auth_headers, p)
            assert "IAC-06" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_iac_07_secret(self, client, auth_headers):
        p = _make("kind: Secret\nmetadata:\n  name: db-creds\ntype: Opaque\ndata:\n  password: c3VwZXJzZWNyZXQ=\n", ".yaml")
        try:
            ids = _scan(client, auth_headers, p)
            assert "IAC-07" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)


# ===========================================================================
# K. IaC Terraform
# ===========================================================================

class TestIacTerraform:
    def test_iac_08_s3_public(self, client, auth_headers):
        p = _make('resource "aws_s3_bucket" "d" {\n  bucket = "company-data"\n  acl    = "public-read"\n}\n', ".tf")
        try:
            ids = _scan(client, auth_headers, p)
            assert "IAC-08" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_iac_09_sg_open(self, client, auth_headers):
        p = _make('ingress {\n  from_port = 22\n  to_port = 22\n  protocol = "tcp"\n  cidr_blocks = ["0.0.0.0/0"]\n}\n', ".tf")
        try:
            ids = _scan(client, auth_headers, p)
            assert "IAC-09" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_iac_10_iam(self, client, auth_headers):
        p = _make('statement {\n  Effect = "Allow"\n  Action = ["*"]\n  Resource = ["*"]\n}\n', ".tf")
        try:
            ids = _scan(client, auth_headers, p)
            assert "IAC-10" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_iac_11_local_state(self, client, auth_headers):
        p = _make('terraform {\n  backend "local" {}\n}\n', ".tf")
        try:
            ids = _scan(client, auth_headers, p)
            assert "IAC-11" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)


# ===========================================================================
# L. IaC Other
# ===========================================================================

class TestIacOther:
    def test_iac_12_ansible(self, client, auth_headers):
        p = _make_named("- hosts: all\n  vars:\n    ansible_become_password: \"secret123\"\n", "playbook.yml")
        try:
            ids = _scan(client, auth_headers, p)
            assert "IAC-12" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_iac_13_helm(self, client, auth_headers):
        p = _make_named("image:\n  repository: myapp\n  tag: latest\n", "values.yaml")
        try:
            ids = _scan(client, auth_headers, p)
            assert "IAC-13" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_iac_14_cf(self, client, auth_headers):
        p = _make_named("Type: AWS::EC2::SecurityGroup\nProperties:\n  SecurityGroupIngress:\n  - CidrIp: 0.0.0.0/0\n    FromPort: 443\n    ToPort: 443\n", "template.yaml")
        try:
            ids = _scan(client, auth_headers, p)
            assert "IAC-14" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_iac_15_serverless(self, client, auth_headers):
        p = _make_named("functions:\n  hello:\n    handler: handler.hello\n    events:\n      - httpApi:\n          method: GET\n          path: /hello\n          auth: NONE\n", "serverless.yml")
        try:
            ids = _scan(client, auth_headers, p)
            assert "IAC-15" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_iac_16_pulumi(self, client, auth_headers):
        p = _make_named("name: myproject\nruntime: python\ndescription: Production infra\nencryptionSettings: {}\n", "Pulumi.yaml")
        try:
            ids = _scan(client, auth_headers, p)
            assert "IAC-16" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)

    def test_iac_17_lambda(self, client, auth_headers):
        p = _make_named("lambda.FunctionUrl: https://xxx.lambda-url.us-east-1.on.aws/\n", "serverless.yml")
        try:
            ids = _scan(client, auth_headers, p)
            assert "IAC-17" in ids
        finally:
            import shutil
            shutil.rmtree(p, ignore_errors=True)
