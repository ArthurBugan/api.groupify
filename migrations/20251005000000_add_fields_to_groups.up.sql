ALTER TABLE groups
ADD COLUMN IF NOT EXISTS description TEXT,
ADD COLUMN IF NOT EXISTS category TEXT,
ADD COLUMN IF NOT EXISTS nesting_level INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS display_order FLOAT8 DEFAULT 0,
ADD COLUMN IF NOT EXISTS parent_id TEXT REFERENCES groups(id);

-- Add index for better performance on display_order queries
CREATE INDEX IF NOT EXISTS idx_groups_display_order ON groups(display_order);