-- Mandatory TOTP MFA: columns added to init.sql in the MFA feature, backfilled
-- here for databases created before it. Idempotent.

ALTER TABLE credentials ADD COLUMN IF NOT EXISTS totp_secret TEXT NULL;
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE;
