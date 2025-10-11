-- Add provider column to sessions table to support multiple OAuth providers
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS provider VARCHAR(50) DEFAULT 'google';
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS original_email VARCHAR(255);

-- Add new primary key on user_id and provider
-- ALTER TABLE sessions ADD PRIMARY KEY IF NOT EXISTS (user_id, provider);