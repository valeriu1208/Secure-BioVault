CREATE TABLE IF NOT EXISTS file_deletion_notices (
    notice_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    file_id UUID NOT NULL,
    original_filename TEXT NOT NULL,
    deleted_by_id UUID REFERENCES users(user_id) ON DELETE SET NULL,
    deleted_by_username TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    dismissed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_file_deletion_notices_user_unread
    ON file_deletion_notices (user_id, created_at DESC)
    WHERE dismissed_at IS NULL;