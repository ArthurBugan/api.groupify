-- Remove the provider column and indexes
DROP INDEX IF EXISTS idx_sessions_user_provider;
DROP INDEX IF EXISTS idx_sessions_provider;
ALTER TABLE sessions DROP COLUMN IF EXISTS provider;