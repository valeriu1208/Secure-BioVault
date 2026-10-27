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

1. **`roles`**: Defines system roles (`PATIENT`, `DOCTOR`, `ADMIN`, `RESEARCHER`).
2. **`users`**: Core user accounts table storing user UUIDs, emails, roles, and status flags.
3. **`user_credentials`**: Isolated 1:1 table storing Argon2id password hashes for security separation.
4. **`patient_profiles`**: Stores Personally Identifiable Information (PII) encrypted at rest (Field-Level Encryption / FLE).
5. **`consents`**: Captures patient permissions, allowed scopes, and expiration dates for evaluation by the Open Policy Agent (OPA / ABAC) engine.
6. **`biomedical_files`**: Stores file metadata and Envelope Encryption fields (encrypted DEK and AES-GCM IV/nonce).
7. **`access_logs`**: Audit trail capturing user access requests, OPA decisions (`ALLOWED`/`DENIED`), and timestamps.

### Database Commands (`Makefile`)

All commands should be executed from within the database directory. Check 'make help' to see them.
