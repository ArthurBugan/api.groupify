ALTER TABLE groups
DROP COLUMN IF EXISTS description,
DROP COLUMN IF EXISTS category,
DROP COLUMN IF EXISTS parent_id,
DROP COLUMN IF EXISTS nesting_level,
DROP COLUMN IF EXISTS display_order;

-- Drop the index for display_order
DROP INDEX IF EXISTS idx_groups_display_order;

ALTER TABLE channels
DROP COLUMN IF EXISTS url;