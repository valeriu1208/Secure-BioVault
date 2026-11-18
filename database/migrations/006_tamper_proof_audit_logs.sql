-- Tamper-evident HMAC-SHA256 hash chaining + append-only trigger on access_logs. Idempotent.

ALTER TABLE access_logs
    ADD COLUMN IF NOT EXISTS prev_hash CHAR(64) NOT NULL DEFAULT repeat('0', 64);

ALTER TABLE access_logs
    ADD COLUMN IF NOT EXISTS current_hash CHAR(64) NOT NULL DEFAULT repeat('0', 64);

ALTER TABLE access_logs ALTER COLUMN prev_hash DROP DEFAULT;
ALTER TABLE access_logs ALTER COLUMN current_hash DROP DEFAULT;

CREATE OR REPLACE FUNCTION prevent_access_logs_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'access_logs is append-only: % operations are forbidden', TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_access_logs_append_only ON access_logs;

CREATE TRIGGER trg_access_logs_append_only
BEFORE UPDATE OR DELETE ON access_logs
FOR EACH ROW
EXECUTE FUNCTION prevent_access_logs_mutation();
