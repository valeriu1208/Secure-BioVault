# BioVault - Database

This directory contains the database initialization scripts, schema definitions, and some management utilities for the **BioVault** platform.

* **`init.sql`**: Main Data Definition Language (DDL) script containing table structures, relationships, extensions (`uuid-ossp`, `pgcrypto`), and initial system roles.
* **`Makefile`**: Task automation file in the project root to simplify setup, resets, and console connections.
urity 

## Security Features

* **CVE-2026-6471 Compliance**: Uses `postgres:16.4-alpine` base image containing security patches against PostGREShell SMB Remote Code Execution.
* **Network Isolation**: Bound strictly to `127.0.0.1:5432` to prevent external network exposure while enabling local development.

## Database Schema Overview

The database design incorporates privacy, security, and access control features required by the project:

1. **`roles`** and **`users`**: Define user roles, identities, and active status.
2. **`credentials`**: Stores Argon2id password hashes separately from user records.
3. **`patient_profiles`**: Holds encrypted PII fields.
4. **`consents`**: Stores consent attributes for future policy rules. The initial Rego policy currently grants file access only to the owner.
5. **`files`**: Stores file metadata, AES-GCM ciphertext, wrapped per-file data keys, and nonces.
6. **`auth_sessions`**: Stores hashes of JWT IDs and their expiration times.
7. **`access_logs`**: Schema for access decisions and audit events.

### Database Commands (`Makefile`)

All commands should be executed from within the database directory. Check 'make help' to see them.
