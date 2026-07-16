-- ============================================================================
-- Kasra — DDL: Database table structure definitions (PostgreSQL)
-- ============================================================================
-- Compatible with: PostgreSQL 16+
-- Character set: UTF-8
-- ============================================================================

-- Ensure the correct schema is used
SET search_path TO public;

-- ── Audit log table ─────────────────────────────────────────────────────────
-- Immutable record of every detection event; one row per triggered rule
CREATE TABLE IF NOT EXISTS audit_logs (
    id              BIGSERIAL PRIMARY KEY,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_id         VARCHAR(128),
    session_id      VARCHAR(128),
    request_id      VARCHAR(128),

    -- Rule info
    rule_id         VARCHAR(32) NOT NULL,
    rule_name       VARCHAR(256) NOT NULL,
    category        VARCHAR(64),
    severity        VARCHAR(4) NOT NULL CHECK (severity IN ('P0', 'P1', 'P2')),
    action          VARCHAR(16) NOT NULL CHECK (action IN ('block', 'warn', 'redact', 'clean', 'truncate', 'soft_allow', 'dynamic')),

    -- Detection context
    direction       VARCHAR(16) NOT NULL CHECK (direction IN ('input', 'output', 'batch', 'behavior')),
    content_snippet TEXT,
    matched_text    TEXT,
    file_path       VARCHAR(1024),
    line_number     INTEGER,
    match_count     INTEGER NOT NULL DEFAULT 0,

    -- Status & metadata
    status          VARCHAR(16) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'resolved', 'fp')),
    metadata        JSONB DEFAULT '{}'::jsonb,

    -- Compliance flag
    gdpr_relevant   BOOLEAN NOT NULL DEFAULT FALSE,

    -- Creation time (immutable)
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Audit log indexes (query optimization)
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp     ON audit_logs (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id       ON audit_logs (user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_session_id    ON audit_logs (session_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_rule_id       ON audit_logs (rule_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_severity      ON audit_logs (severity);
CREATE INDEX IF NOT EXISTS idx_audit_logs_direction     ON audit_logs (direction);
CREATE INDEX IF NOT EXISTS idx_audit_logs_status        ON audit_logs (status);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_date     ON audit_logs (user_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_rule_date     ON audit_logs (rule_id, timestamp DESC);


-- ── Rule categories (master table) ──────────────────────────────────────────
-- I = Input Detection, O = Output Detection, SEC = Code Security, IAC = Infrastructure as Code
CREATE TABLE IF NOT EXISTS categories (
    id              SERIAL PRIMARY KEY,
    name            VARCHAR(50) NOT NULL UNIQUE,
    label           VARCHAR(100) NOT NULL,
    description     TEXT,
    color           VARCHAR(7) DEFAULT '#6366f1',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- ── Dictionaries (keyword lists referenced by rules) ───────────────────────
CREATE TABLE IF NOT EXISTS dictionaries (
    id              SERIAL PRIMARY KEY,
    code            VARCHAR(128) UNIQUE NOT NULL,  -- gdpr_health, prompt_injection
    name            VARCHAR(256) NOT NULL,
    description     TEXT,
    entries         TEXT[] NOT NULL DEFAULT '{}',
    category_id     INTEGER REFERENCES categories(id) ON DELETE SET NULL,
    is_active       BOOLEAN DEFAULT true,
    version         INTEGER DEFAULT 1,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- ── Detection pattern types (master table) ──────────────────────────────────
-- regex, keyword, dictionary, yaml_path, dockerfile, keyvalue
CREATE TABLE IF NOT EXISTS pattern_types (
    id              SERIAL PRIMARY KEY,
    name            VARCHAR(50) NOT NULL UNIQUE,
    label           VARCHAR(100) NOT NULL,
    description     TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- ── Rule configuration table ─────────────────────────────────────────────────
-- SDK built-in rule definitions (seeded from JSON bundles via import)
-- Custom user rules go in custom_rules table
CREATE TABLE IF NOT EXISTS rules (
    id              VARCHAR(50) PRIMARY KEY,          -- I-01, SEC-06
    name            VARCHAR(256) NOT NULL,
    description     TEXT,
    severity        VARCHAR(4) NOT NULL DEFAULT 'P2' CHECK (severity IN ('P0', 'P1', 'P2')),
    action          VARCHAR(16) NOT NULL DEFAULT 'warn' CHECK (action IN ('block', 'warn', 'redact', 'clean', 'truncate', 'soft_allow', 'dynamic')),

    -- Classification
    category_id     INTEGER REFERENCES categories(id),
    rule_type       VARCHAR(20) NOT NULL DEFAULT 'io',  -- io | code_review | behavior
    applicable_stages JSONB NOT NULL DEFAULT '[]'::jsonb,

    -- Detection config (JSON: mode, patterns, target_files)
    detection_config JSONB NOT NULL DEFAULT '{}'::jsonb,

    -- Metadata
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    source          VARCHAR(64) DEFAULT 'sdk',          -- sdk / user
    bundle_series   VARCHAR(20),                        -- I, O, SEC, IAC
    sdk_version     INTEGER DEFAULT 1,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rules_severity   ON rules (severity);
CREATE INDEX IF NOT EXISTS idx_rules_category   ON rules (category_id);
CREATE INDEX IF NOT EXISTS idx_rules_enabled    ON rules (enabled);
CREATE INDEX IF NOT EXISTS idx_rules_type       ON rules (rule_type);

-- ── Custom rules table ───────────────────────────────────────────────────────
-- User-defined detection rules with full detection config
CREATE TABLE IF NOT EXISTS custom_rules (
    id              VARCHAR(32) PRIMARY KEY,          -- U-01, U-02, ...
    name            VARCHAR(256) NOT NULL,
    description     TEXT,
    severity        VARCHAR(4) NOT NULL DEFAULT 'P2',  -- P0 / P1 / P2
    action          VARCHAR(16) NOT NULL DEFAULT 'warn', -- block / warn / redact / clean

    -- Classification
    category_id     INTEGER REFERENCES categories(id),
    rule_type       VARCHAR(20) NOT NULL DEFAULT 'io',  -- io | code_review | behavior
    applicable_stages JSONB NOT NULL DEFAULT '[]'::jsonb,
    target_files    JSONB,                              -- ["**/*.py"] for code review

    -- Detection method
    pattern_type_id INTEGER REFERENCES pattern_types(id),
    pattern_type    VARCHAR(32) NOT NULL DEFAULT 'regex',   -- regex / keyword (legacy)
    pattern_value   TEXT NOT NULL DEFAULT '',
    pattern_confidence VARCHAR(10) DEFAULT '0.8',
    detection_config JSONB,                                -- full JSON for advanced editing

    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    created_by      VARCHAR(100),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_custom_rules_enabled ON custom_rules (enabled);

COMMENT ON TABLE  custom_rules IS 'Custom rules — user-defined detection rules';
COMMENT ON COLUMN custom_rules.pattern_type IS 'Detection pattern type: regex / keyword';
COMMENT ON COLUMN custom_rules.applicable_stages IS 'Pipeline stages: ["input"], ["output"], ["batch"]';
COMMENT ON COLUMN custom_rules.target_files IS 'Glob patterns for code review rules';


-- ── User behavior table ─────────────────────────────────────────────────────
-- Daily activity summary, used for B-series behavior anomaly detection
CREATE TABLE IF NOT EXISTS user_behavior (
    user_id         VARCHAR(128) NOT NULL,
    date            DATE NOT NULL,
    total_requests  INTEGER NOT NULL DEFAULT 0,
    blocked_requests INTEGER NOT NULL DEFAULT 0,
    warned_requests INTEGER NOT NULL DEFAULT 0,
    first_request   TIME,
    last_request    TIME,
    rule_triggers   JSONB DEFAULT '{}'::jsonb,         -- {"I-01": 3, "SEC-06": 1}
    anomaly_score   INTEGER NOT NULL DEFAULT 0 CHECK (anomaly_score BETWEEN 0 AND 100),
    ai_adoption_rate INTEGER CHECK (ai_adoption_rate BETWEEN 0 AND 100),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, date)
);

CREATE INDEX IF NOT EXISTS idx_user_behavior_score ON user_behavior (anomaly_score DESC);
CREATE INDEX IF NOT EXISTS idx_user_behavior_date   ON user_behavior (date DESC);


-- ── Users table ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id              BIGSERIAL PRIMARY KEY,
    username        VARCHAR(128) NOT NULL UNIQUE,
    email           VARCHAR(256),
    api_key_hash    VARCHAR(256),
    role            VARCHAR(32) NOT NULL DEFAULT 'user' CHECK (role IN ('admin', 'user', 'readonly')),
    team            VARCHAR(128),
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users (username);
CREATE INDEX IF NOT EXISTS idx_users_role     ON users (role);
CREATE INDEX IF NOT EXISTS idx_users_team     ON users (team);


-- ── Audit log partitioning (optional — for large-scale deployments) ──────────
-- When the table exceeds 100 million rows, enable monthly partitioning
-- CREATE TABLE IF NOT EXISTS audit_logs_y2026m07 PARTITION OF audit_logs
--     FOR VALUES FROM ('2026-07-01') TO ('2026-08-01');
-- Create a new partition automatically at the start of each month.


-- ── Audit chain table (tamper-proof verification) ────────────────────────────
-- Uses a hash chain (Merkle tree) to guarantee audit log integrity
CREATE TABLE IF NOT EXISTS audit_chain (
    id              BIGSERIAL PRIMARY KEY,
    last_log_id     BIGINT NOT NULL REFERENCES audit_logs(id),
    batch_hash      VARCHAR(64) NOT NULL,               -- SHA-256 of (prev_hash || batch_json)
    prev_hash       VARCHAR(64) NOT NULL,               -- Hash of the previous block
    batch_count     INTEGER NOT NULL,                   -- Number of log entries in this batch
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_chain_last_log ON audit_chain (last_log_id);
CREATE INDEX IF NOT EXISTS idx_audit_chain_created  ON audit_chain (created_at DESC);


-- ── Schema metadata table (migration version tracking) ──────────────────────
CREATE TABLE IF NOT EXISTS meta (
    key             VARCHAR(64) PRIMARY KEY,
    value           TEXT
);

INSERT INTO meta (key, value) VALUES ('schema_version', '2')
ON CONFLICT (key) DO NOTHING;


-- ── Database-level constraints ───────────────────────────────────────────────
-- Ensure timestamps are reasonable
ALTER TABLE audit_logs ADD CONSTRAINT chk_audit_timestamp
    CHECK (timestamp <= NOW() + INTERVAL '1 hour');

-- Ensure match_count > 0 when matched_text is not null
ALTER TABLE audit_logs ADD CONSTRAINT chk_match_consistency
    CHECK ((matched_text IS NULL) OR (match_count > 0));


-- ── Comments (metadata) ──────────────────────────────────────────────────────
COMMENT ON TABLE  audit_logs      IS 'Audit log — immutable record of every detection event';
COMMENT ON COLUMN audit_logs.id   IS 'Auto-increment primary key';
COMMENT ON COLUMN audit_logs.rule_id IS 'Rule ID, e.g. I-01, SEC-06';
COMMENT ON COLUMN audit_logs.direction IS 'Detection direction: input/output/batch/behavior';
COMMENT ON COLUMN audit_logs.status    IS 'Processing status: pending/resolved/fp (false positive)';
COMMENT ON COLUMN audit_logs.gdpr_relevant IS 'Whether GDPR compliance is relevant';

COMMENT ON TABLE  categories      IS 'Rule categories master: I, O, SEC, IAC, BEHAVIOR';
COMMENT ON TABLE  pattern_types   IS 'Detection pattern types master: regex, keyword, yaml_path, ...';

COMMENT ON TABLE  dictionaries    IS 'Keyword dictionaries referenced by rules via type=dictionary ref';
COMMENT ON COLUMN dictionaries.code IS 'Unique code referenced in rule detection_config';
COMMENT ON COLUMN dictionaries.entries IS 'PostgreSQL TEXT[] array of keywords';

COMMENT ON TABLE  rules           IS 'SDK built-in rules — seeded from JSON bundles';
COMMENT ON COLUMN rules.id        IS 'Rule ID: I-01 ~ I-57, O-01 ~ O-53, SEC-01 ~ SEC-83';
COMMENT ON COLUMN rules.category_id IS 'FK to categories table';
COMMENT ON COLUMN rules.rule_type IS 'io / code_review / behavior';
COMMENT ON COLUMN rules.bundle_series IS 'Source bundle series: I, O, SEC, IAC';

COMMENT ON TABLE  user_behavior     IS 'User behavior — daily activity summary';
COMMENT ON COLUMN user_behavior.anomaly_score IS 'Anomaly score 0-100, higher = more suspicious';

COMMENT ON TABLE  audit_chain       IS 'Audit chain — hash chain ensuring audit log tamper-proof integrity';
COMMENT ON COLUMN audit_chain.batch_hash  IS 'SHA-256 hash of the current batch';
COMMENT ON COLUMN audit_chain.prev_hash   IS 'Hash of the previous batch, forming a linked chain';
