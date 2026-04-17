-- Add enable_groupshelf column to groups
ALTER TABLE groups
ADD COLUMN IF NOT EXISTS enable_groupshelf BOOLEAN DEFAULT false;

CREATE INDEX IF NOT EXISTS idx_groups_enable_groupshelf ON groups(enable_groupshelf);