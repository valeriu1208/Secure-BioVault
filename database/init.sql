-- Database Initialization

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Clean exisitng tables
DROP TABLE IF EXISTS access_logs CASCADE;
DROP TABLE IF EXISTS consents CASCADE;
DROP TABLE IF EXISTS files CASCADE;
DROP TABLE IF EXISTS patient_profiles CASCADE;
DROP TABLE IF EXISTS auth_sessions CASCADE;
DROP TABLE IF EXISTS credentials CASCADE;
DROP TABLE IF EXISTS users CASCADE;
DROP TABLE IF EXISTS roles CASCADE;


-- Create tables
CREATE TABLE roles (
    role_id SERIAL PRIMARY KEY,
    role_name VARCHAR(50) UNIQUE NOT NULL
);

INSERT INTO roles (role_name) VALUES
('PATIENT'),
('DOCTOR'),
('ADMIN'),
('RESEARCHER');

CREATE TABLE users (
    user_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(100) NOT NULL,
    email VARCHAR(255) NOT NULL, -- encrypted field
    email_hash VARCHAR(64) UNIQUE NOT NULL, -- for user search
    role_id INT NOT NULL REFERENCES roles(role_id) ON DELETE RESTRICT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX users_username_uq ON users(username);

CREATE TABLE credentials (
    user_id UUID PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
    password_hash VARCHAR(255) NOT NULL,
    last_password_change TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE patient_profiles (
    profile_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID UNIQUE NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    encrypted_first_name TEXT NOT NULL,
    encrypted_last_name TEXT NOT NULL,
    encrypted_dni TEXT NOT NULL,
    encrypted_ssn TEXT,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Consents for ABAC/OPA
CREATE TABLE consents (
    consent_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    patient_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    granted_to_user_id UUID REFERENCES users(user_id) ON DELETE CASCADE,
    granted_to_role VARCHAR(50),
    allowed_purpose VARCHAR(100) NOT NULL,
    is_granted BOOLEAN DEFAULT TRUE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Files using Envelope Encryption AES-256-GCM
CREATE TABLE files (
    file_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    owner_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    original_filename VARCHAR(255) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    file_type VARCHAR(50) NOT NULL,              -- 'VCF', 'FASTA', 'PDF', 'JSON'
    sensitivity_category VARCHAR(50) DEFAULT 'HIGHLY_CONFIDENTIAL',
    storage_path VARCHAR(512),                   -- Null when the encrypted content is stored in this row
    encrypted_dek TEXT NOT NULL,                 -- Wrapped per-file key, including its wrapping nonce
    iv_nonce TEXT NOT NULL,                      -- AES-GCM nonce for the encrypted content
    content BYTEA,                               -- Encrypted PDF bytes
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE auth_sessions (
    token_hash CHAR(64) PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX auth_sessions_user_id_idx ON auth_sessions(user_id);

CREATE TABLE access_logs (
    log_id BIGSERIAL PRIMARY KEY,
    user_id UUID REFERENCES users(user_id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,                -- 'FILE_READ', 'LOGIN_ATTEMPT'
    resource_id UUID,
    decision VARCHAR(20) NOT NULL,               -- 'ALLOWED' or 'DENIED'
    reason VARCHAR(255),
    ip_address VARCHAR(45),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Requests to change role
CREATE TABLE IF NOT EXISTS role_requests (
    req_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    req_role VARCHAR(50) NOT NULL,
    justification TEXT NOT NULL,
    status VARCHAR(20) DEFAULT 'PENDING',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

WITH new_admin AS(
    INSERT INTO users (user_id, username, email, email_hash, role_id, is_active) VALUES (
        '8204e6b7-36d7-4d65-ab3f-9db8e789fa69',
        'admin',
        'BhuikCIgqbtxraVbb7RmhW84xRAjtErNcloYPoeDcfKI37v2CECzLaMQ7C3S6gKoHKUxEQ==', -- email encrypted
        '8b8b09339e0ebddffb3d7ab710a30b5e9c9ffb8b2eefd092fb1faabfbe8f1a8c', -- SHA-256 of admin@securebiovault.com
        (SELECT role_id FROM roles WHERE role_name = 'ADMIN'),
        TRUE
    )
    RETURNING user_id
)
INSERT INTO credentials (user_id, password_hash)
    (SELECT user_id, '$argon2id$v=19$m=65536,t=3,p=4$yALj6jnDv/1woclUeB/L/g$J7S+N+Ioxij2q5sY46kQW4ha1Ro7MFkO2ergfJpDOFM' FROM new_admin
)
