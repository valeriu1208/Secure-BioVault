-- Access tokens are now stateless Ed25519 JWTs validated without a database
-- lookup. Only opaque refresh tokens are persisted (SHA-256 hashed) so that
-- sessions can still be revoked on logout or account deactivation.
-- Existing sessions are dropped: users must sign in again after this migration.

BEGIN;

DROP TABLE IF EXISTS auth_sessions CASCADE;

CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_hash CHAR(64) PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS refresh_tokens_user_id_idx ON refresh_tokens(user_id);

COMMIT;
