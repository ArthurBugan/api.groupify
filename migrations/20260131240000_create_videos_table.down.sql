-- Drop videos table and related objects
DROP TRIGGER IF EXISTS trigger_videos_updated_at ON videos;
DROP FUNCTION IF EXISTS update_videos_updated_at();
DROP TABLE IF EXISTS videos;
