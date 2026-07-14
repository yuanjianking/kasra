-- ============================================================================
-- Migration 002: Add categories and pattern_types master tables, update rules/custom_rules
-- ============================================================================
-- Compatible with: PostgreSQL 16+ / SQLite 3
-- ============================================================================

-- ── 1. Create categories table ──
CREATE TABLE IF NOT EXISTS categories (
    id              SERIAL PRIMARY KEY,
    name            VARCHAR(50) NOT NULL UNIQUE,
    label           VARCHAR(100) NOT NULL,
    description     TEXT,
    color           VARCHAR(7) DEFAULT '#6366f1',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── 2. Create pattern_types table ──
CREATE TABLE IF NOT EXISTS pattern_types (
    id              SERIAL PRIMARY KEY,
    name            VARCHAR(50) NOT NULL UNIQUE,
    label           VARCHAR(100) NOT NULL,
    description     TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── 3. Update rules table ──
ALTER TABLE rules ADD COLUMN IF NOT EXISTS category_id INTEGER REFERENCES categories(id);
ALTER TABLE rules ADD COLUMN IF NOT EXISTS rule_type VARCHAR(20) NOT NULL DEFAULT 'io';
ALTER TABLE rules ADD COLUMN IF NOT EXISTS applicable_stages JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE rules ADD COLUMN IF NOT EXISTS detection_config JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE rules ADD COLUMN IF NOT EXISTS bundle_series VARCHAR(20);
ALTER TABLE rules ADD COLUMN IF NOT EXISTS sdk_version INTEGER DEFAULT 1;

-- Migrate old rules.category to category_id
UPDATE rules SET category_id = c.id
FROM categories c
WHERE rules.category = c.name AND rules.category_id IS NULL;

-- ── 4. Update custom_rules table ──
ALTER TABLE custom_rules ADD COLUMN IF NOT EXISTS category_id INTEGER REFERENCES categories(id);
ALTER TABLE custom_rules ADD COLUMN IF NOT EXISTS rule_type VARCHAR(20) NOT NULL DEFAULT 'io';
ALTER TABLE custom_rules ADD COLUMN IF NOT EXISTS pattern_type_id INTEGER REFERENCES pattern_types(id);
ALTER TABLE custom_rules ADD COLUMN IF NOT EXISTS detection_config JSONB;
ALTER TABLE custom_rules ADD COLUMN IF NOT EXISTS created_by VARCHAR(100);

-- ── 5. Drop obsolete columns ──
ALTER TABLE rules DROP COLUMN IF EXISTS is_custom;
ALTER TABLE rules DROP COLUMN IF EXISTS pattern;
ALTER TABLE rules DROP COLUMN IF EXISTS metadata;

-- ── 6. Drop old custom_rules.category column if exists ──
-- (safe to run, column may not exist)
ALTER TABLE custom_rules DROP COLUMN IF EXISTS category;

-- ── 7. Add schema version tracking table ──
CREATE TABLE IF NOT EXISTS meta (
    key     VARCHAR(64) PRIMARY KEY,
    value   TEXT
);

INSERT INTO meta (key, value) VALUES ('schema_version', '2')
ON CONFLICT (key) DO NOTHING;


-- ── 8. Seed master data ──
INSERT INTO categories (name, label, description, color)
SELECT * FROM (VALUES
    ('I', 'Input Detection', 'Rules that detect security issues in user input', '#ef4444'),
    ('O', 'Output Detection', 'Rules that detect security issues in AI output', '#f97316'),
    ('SEC', 'Code Security', 'Code review rules for security vulnerabilities', '#8b5cf6'),
    ('IAC', 'Infrastructure as Code', 'Rules for Docker, K8s, and IaC misconfigurations', '#06b6d4'),
    ('BEHAVIOR', 'Behavior Monitoring', 'Rules for detecting anomalous user/agent behavior', '#ec4899')
) AS v(name, label, description, color)
WHERE NOT EXISTS (SELECT 1 FROM categories WHERE categories.name = v.name);

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
