-- Add provider column to sessions table to support multiple OAuth providers
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS provider VARCHAR(50) DEFAULT 'google';

-- Create index for better performance
CREATE INDEX IF NOT EXISTS idx_sessions_provider ON sessions(provider);
CREATE INDEX IF NOT EXISTS idx_sessions_user_provider ON sessions(user_id, provider);

-- Update existing sessions to have 'google' as provider
-- UPDATE sessions SET provider = 'google' WHERE provider IS NULL; 