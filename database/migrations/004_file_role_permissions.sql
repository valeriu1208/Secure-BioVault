-- Per-file role-based read permissions (DOCTOR / RESEARCHER). Idempotent.

CREATE TABLE IF NOT EXISTS file_role_permissions (
    permission_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    file_id UUID NOT NULL REFERENCES files(file_id) ON DELETE CASCADE,
    role_name VARCHAR(50) NOT NULL REFERENCES roles(role_name) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT file_role_permissions_file_role_uq UNIQUE(file_id, role_name)
);
