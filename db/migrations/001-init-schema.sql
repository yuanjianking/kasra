-- ============================================================================
-- Migration 001: Initial schema table creation
-- ============================================================================
-- Compatible with: PostgreSQL 16+ / SQLite 3
-- Rollback: see 001-rollback.sql
-- ============================================================================

-- ── audit_logs ──
CREATE TABLE IF NOT EXISTS audit_logs (
    id              BIGSERIAL PRIMARY KEY,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_id         VARCHAR(128),
    session_id      VARCHAR(128),
    request_id      VARCHAR(128),
    rule_id         VARCHAR(32) NOT NULL,
    rule_name       VARCHAR(256) NOT NULL,
    category        VARCHAR(64),
    severity        VARCHAR(4) NOT NULL,
    action          VARCHAR(16) NOT NULL,
    direction       VARCHAR(16) NOT NULL,
    content_snippet TEXT,
    matched_text    TEXT,
    file_path       VARCHAR(1024),
    line_number     INTEGER,
    match_count     INTEGER NOT NULL DEFAULT 0,
    status          VARCHAR(16) NOT NULL DEFAULT 'pending',
    metadata        JSONB DEFAULT '{}'::jsonb,
    gdpr_relevant   BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_ts ON audit_logs (timestamp DESC);

-- ── rules ──
CREATE TABLE IF NOT EXISTS rules (
    id              VARCHAR(32) PRIMARY KEY,
    name            VARCHAR(256) NOT NULL,
    description     TEXT,
    category        VARCHAR(64),
    severity        VARCHAR(4) NOT NULL DEFAULT 'P2',
    action          VARCHAR(16) NOT NULL DEFAULT 'warn',
    pattern         TEXT,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    is_custom       BOOLEAN NOT NULL DEFAULT FALSE,
    source          VARCHAR(64) DEFAULT 'sdk',
    metadata        JSONB DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── custom_rules ──
CREATE TABLE IF NOT EXISTS custom_rules (
    id              VARCHAR(32) PRIMARY KEY,          -- U-01, U-02, ...
    name            VARCHAR(256) NOT NULL,
    description     TEXT,
    category        VARCHAR(64),                       -- custom, credential_leak, pii, ...
    severity        VARCHAR(4) NOT NULL DEFAULT 'P2',  -- P0 / P1 / P2
    action          VARCHAR(16) NOT NULL DEFAULT 'warn', -- block / warn / redact / clean

    -- Detection method
    pattern_type    VARCHAR(32) NOT NULL DEFAULT 'regex',   -- regex / keyword
    pattern_value   TEXT NOT NULL DEFAULT '',               -- the regex or keyword text
    pattern_confidence VARCHAR(10) DEFAULT '0.8',

    -- Rule classification
    applicable_stages JSONB NOT NULL DEFAULT '[]'::jsonb,  -- ["input"], ["output"], ["batch"]
    target_files    JSONB,                                   -- ["**/*.py"] for code review

    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_custom_rules_enabled ON custom_rules (enabled);

-- ── user_behavior ──
CREATE TABLE IF NOT EXISTS user_behavior (
    user_id         VARCHAR(128) NOT NULL,
    date            DATE NOT NULL,
    total_requests  INTEGER NOT NULL DEFAULT 0,
    blocked_requests INTEGER NOT NULL DEFAULT 0,
    warned_requests INTEGER NOT NULL DEFAULT 0,
    first_request   TIME,
    last_request    TIME,
    rule_triggers   JSONB DEFAULT '{}'::jsonb,
    anomaly_score   INTEGER NOT NULL DEFAULT 0,
    ai_adoption_rate INTEGER,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, date)
);

-- ── users ──
CREATE TABLE IF NOT EXISTS users (
    id              BIGSERIAL PRIMARY KEY,
    username        VARCHAR(128) NOT NULL UNIQUE,
    email           VARCHAR(256),
    api_key_hash    VARCHAR(256),
    role            VARCHAR(32) NOT NULL DEFAULT 'user',
    team            VARCHAR(128),
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
