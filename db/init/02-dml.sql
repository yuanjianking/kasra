-- ============================================================================
-- Kasra — DML: Initial seed data (PostgreSQL)
-- ============================================================================
-- Run on first deployment to populate base data
-- Execution order: must run after 01-ddl.sql
-- ============================================================================

-- ── 1. Create default admin user ─────────────────────────────────────────────
-- Password: admin123 (bcrypt hash, demo only — must change in production)
INSERT INTO users (username, email, api_key_hash, role, is_active)
SELECT 'admin', 'admin@kasra.security', '$2b$12$LJ3m4ys3Lk0TSwHnbfOMiOXPm1Qlq5GzQq5GzQq5GzQq5GzQq5G', 'admin', TRUE
WHERE NOT EXISTS (SELECT 1 FROM users WHERE username = 'admin');

INSERT INTO users (username, email, role, is_active)
SELECT 'demo-user', 'demo@example.com', 'user', TRUE
WHERE NOT EXISTS (SELECT 1 FROM users WHERE username = 'demo-user');


-- ── 2. Register SDK built-in rule snapshots ──────────────────────────────────
-- These rules are auto-loaded by the SDK; snapshots here are for UI display and override
INSERT INTO rules (id, name, description, category, severity, action, enabled, is_custom, source)
SELECT * FROM (VALUES
    -- I-Series: Input detection (credential leak)
    ('I-01', 'GitHub Token', 'Detect GitHub Personal Access Token (ghp_/gho_/ghu_/ghs_/ghr_)', 'credential_leak', 'P0', 'block', TRUE, FALSE, 'sdk'),
    ('I-02', 'OpenAI API Key', 'Detect OpenAI API Key (sk-...)', 'credential_leak', 'P0', 'block', TRUE, FALSE, 'sdk'),
    ('I-03', 'Anthropic API Key', 'Detect Anthropic API Key (sk-ant-...)', 'credential_leak', 'P0', 'block', TRUE, FALSE, 'sdk'),
    ('I-04', 'AWS Access Key', 'Detect AWS Access Key ID (AKIA...)', 'credential_leak', 'P0', 'block', TRUE, FALSE, 'sdk'),
    ('I-05', 'Generic Password/Secret', 'Detect generic passwords and secret patterns', 'credential_leak', 'P0', 'block', TRUE, FALSE, 'sdk'),
    ('I-06', 'Private Key/PEM Certificate', 'Detect PEM format private keys and certificates', 'credential_leak', 'P0', 'block', TRUE, FALSE, 'sdk'),

    -- I-Series: PII detection
    ('I-08', 'China Phone Number', 'Detect mainland China mobile phone numbers', 'pii', 'P1', 'redact', TRUE, FALSE, 'sdk'),
    ('I-09', 'China National ID', 'Detect mainland China national ID numbers', 'pii', 'P1', 'redact', TRUE, FALSE, 'sdk'),
    ('I-10', 'Email Address', 'Detect email addresses', 'pii', 'P1', 'redact', TRUE, FALSE, 'sdk'),

    -- I-Series: Injection attacks
    ('I-11', 'Prompt Injection Attack', 'Detect prompt injection attack patterns', 'injection', 'P0', 'block', TRUE, FALSE, 'sdk'),
    ('I-12', 'Jailbreak/Role-Play Attack', 'Detect jailbreak and role-play attack attempts', 'injection', 'P0', 'block', TRUE, FALSE, 'sdk'),

    -- O-Series: Output detection (code security)
    ('O-01', 'Dangerous Function Call', 'Detect dangerous function calls like eval/exec', 'code_security', 'P0', 'warn', TRUE, FALSE, 'sdk'),
    ('O-02', 'Dangerous Shell Command', 'Detect dangerous shell commands like rm -rf /', 'code_security', 'P0', 'block', TRUE, FALSE, 'sdk'),
    ('O-03', 'Credential Leak', 'Detect credential leaks in AI output', 'credential_leak', 'P0', 'block', TRUE, FALSE, 'sdk'),
    ('O-04', 'SQL Injection', 'Detect non-parameterized SQL queries', 'code_security', 'P2', 'warn', TRUE, FALSE, 'sdk'),

    -- SEC series: Code review
    ('SEC-01', 'Hardcoded Secret', 'Detect hardcoded secrets in code', 'credential_leak', 'P0', 'warn', TRUE, FALSE, 'sdk'),
    ('SEC-05', 'SQL Injection', 'Detect SQL injection vulnerabilities', 'injection', 'P0', 'warn', TRUE, FALSE, 'sdk'),
    ('SEC-06', 'Path Traversal', 'Detect path traversal vulnerabilities', 'injection', 'P0', 'warn', TRUE, FALSE, 'sdk'),
    ('SEC-12', 'XSS Risk', 'Detect cross-site scripting risks', 'injection', 'P0', 'warn', TRUE, FALSE, 'sdk'),

    -- IAC series: Infrastructure as Code
    ('IAC-01', 'Dockerfile Security', 'Detect Dockerfile security configuration issues', 'iac', 'P1', 'warn', TRUE, FALSE, 'sdk'),
    ('IAC-02', 'K8s Security Config', 'Detect Kubernetes security configuration issues', 'iac', 'P1', 'warn', TRUE, FALSE, 'sdk'),

    -- ARCH series: Architecture security
    ('ARCH-01', 'Circular Dependency', 'Detect microservice circular dependencies', 'architecture', 'P2', 'warn', TRUE, FALSE, 'sdk'),

    -- B series: Behavior detection
    ('B-01', 'Late Night Anomaly', 'Detect high request volume during late-night hours (0-6am)', 'behavior', 'P1', 'warn', TRUE, FALSE, 'sdk'),
    ('B-02', 'Repeated Rule Trigger', 'Detect same user triggering the same rule repeatedly in a short time', 'behavior', 'P1', 'warn', TRUE, FALSE, 'sdk'),
    ('B-03', 'Jailbreak Attempt', 'Detect continuous jailbreak/injection attempts', 'behavior', 'P0', 'block', TRUE, FALSE, 'sdk'),

    -- C series: Compliance
    ('C-01', 'PII Compliance', 'Detect GDPR/personal information protection law PII leaks', 'compliance', 'P1', 'warn', TRUE, FALSE, 'sdk'),
    ('C-02', 'Open Source License Compliance', 'Detect GPL/AGPL license compliance issues', 'compliance', 'P1', 'warn', TRUE, FALSE, 'sdk')
) AS v(id, name, description, category, severity, action, enabled, is_custom, source)
WHERE NOT EXISTS (SELECT 1 FROM rules WHERE rules.id = v.id);


-- ── 3. Create default dashboard view configuration ──────────────────────────
-- Stored via JSONB metadata since there is no dedicated dashboard_config table yet


-- ── 4. Insert sample audit logs ─────────────────────────────────────────────
-- For development and demo only; not executed in production
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM audit_logs LIMIT 1) THEN
        INSERT INTO audit_logs (timestamp, user_id, session_id, rule_id, rule_name, severity, action, direction, matched_text, match_count, status) VALUES
            (NOW() - INTERVAL '2 hours', 'demo-user', 'sess_001', 'I-05', 'Generic Password/Secret', 'P0', 'block', 'input', 'password=admin123', 1, 'resolved'),
            (NOW() - INTERVAL '1 hour',  'demo-user', 'sess_002', 'O-01', 'Dangerous Function Call', 'P0', 'warn', 'output', 'eval(request.body)', 1, 'pending'),
            (NOW() - INTERVAL '30 min',  'demo-user', 'sess_003', 'I-11', 'Prompt Injection Attack', 'P0', 'block', 'input', 'ignore all previous instructions', 1, 'pending'),
            (NOW() - INTERVAL '15 min',  'admin',     'sess_004', 'SEC-05', 'SQL Injection', 'P0', 'warn', 'batch', 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")', 1, 'fp'),
            (NOW() - INTERVAL '5 min',   'demo-user', 'sess_001', 'B-01', 'Late Night Anomaly', 'P1', 'warn', 'behavior', NULL, 0, 'pending'),
            (NOW(),                      'demo-user', 'sess_005', 'O-02', 'Dangerous Shell Command', 'P0', 'block', 'output', 'subprocess.call("rm -rf /", shell=True)', 1, 'pending');
    END IF;
END $$;
