-- ============================================================================
-- Rollback 001: Revert initial schema
-- ============================================================================
-- Warning: This will delete ALL data!
-- ============================================================================

DROP TABLE IF EXISTS audit_logs CASCADE;
DROP TABLE IF EXISTS rules CASCADE;
DROP TABLE IF EXISTS user_behavior CASCADE;
DROP TABLE IF EXISTS users CASCADE;
DROP TABLE IF EXISTS audit_chain CASCADE;
