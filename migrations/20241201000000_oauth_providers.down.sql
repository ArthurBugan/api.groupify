-- Remove the provider column and indexes
DROP INDEX IF EXISTS idx_sessions_user_provider;
DROP INDEX IF EXISTS idx_sessions_provider;

-- Drop the composite primary key on user_id and provider
ALTER TABLE sessions DROP CONSTRAINT sessions_pkey;
ALTER TABLE sessions DROP COLUMN IF EXISTS original_email;

ALTER TABLE sessions DROP COLUMN IF EXISTS provider;