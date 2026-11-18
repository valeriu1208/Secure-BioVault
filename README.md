# Secure BioVault

Secure BioVault uses FastAPI, Streamlit, and PostgreSQL.

## Run with Docker Compose

You need Docker (with Compose v2), `make`, `openssl`, Python 3 and
[mkcert](https://github.com/FiloSottile/mkcert). All commands run from the
repository root.

### 1. Generate secrets (once per machine)

```sh
make key
```

This creates `.env` (database name, user and password, `FILE_ENCRYPTION_KEY`,
`FIELD_ENCRYPTION_KEY`) and the Ed25519 JWT signing keys in the git-ignored
`secrets/` directory. It refuses to overwrite existing credentials.

Back up `.env` and `secrets/`. Never re-run `make key` (or `make clean`) on a
setup that already has data: the database volume keeps its original password,
and files and emails encrypted with the old keys can no longer be decrypted.
Do not commit or share the private signing key.

### 2. Generate an HTTPS certificate (once per developer)

The app is served over HTTPS by a Caddy reverse proxy. Each developer
generates their own certificate with mkcert, which adds a local certificate
authority to that machine's trust store so browsers show a valid padlock.
Certificates are only trusted on the machine that created them, so do not
share them. They are written to the git-ignored `secrets/tls/` directory.

Install mkcert:

- macOS: `brew install mkcert nss`
- Windows: `choco install mkcert` or `scoop install mkcert`
- Linux: mkcert and `libnss3-tools` from your package manager, or the mkcert
  binary from its GitHub releases

Then generate the certificate (`mkcert -install` may ask for your password):

```sh
make tls                       # macOS / Linux (same as scripts/gen-tls-cert.sh)
```

```powershell
powershell -ExecutionPolicy Bypass -File scripts\gen-tls-cert.ps1   # Windows
```

Add extra hostnames or IPs as arguments, e.g. `scripts/gen-tls-cert.sh 192.168.1.20`.
Pass `--force` (`-Force` on Windows) to replace an existing certificate.
Restart your browser afterwards so it picks up the new certificate authority.

### 3. Start the app

```sh
docker compose up --build
```

Startup order: `db` (PostgreSQL) becomes healthy, then `db-migrate` applies
every migration in `database/migrations/`, then `backend`, `frontend` and the
HTTPS `proxy` start. The migrations are idempotent, so they run safely on
every start.

| URL | What it is |
|---|---|
| <https://localhost> | The web app (Streamlit) |
| <https://localhost:8443/docs> | Interactive API documentation |
| <https://localhost:8443> | The API itself (JSON only) |

<http://localhost> redirects to HTTPS. The frontend and backend containers are
not published on the host directly, so the old <http://localhost:8501> and
<http://localhost:8000> addresses no longer work (Streamlit still prints 8501
in its logs; that is the container-internal port).

Register an account in the UI and sign in. The first login shows a QR code:
scan it with an authenticator app (Google Authenticator, Authy, ...) and enter
the 6-digit code. Every later login asks for a code.

A default `admin` account is created on a fresh database. If you do not know
its password, set a new one with `make fix_password` (it prints the SQL to run).

Stop the services with `Ctrl+C`, or `docker compose down` in another terminal.
Data persists in the `postgres_api_data` volume.

### 4. Updating an existing setup

After pulling changes, always restart with a rebuild:

```sh
docker compose up --build
```

`database/init.sql` only runs when the database volume is **created for the
first time**. Changes to it never reach an existing database. Every schema
change must therefore also be added as a new idempotent file in
`database/migrations/` (e.g. `ALTER TABLE ... ADD COLUMN IF NOT EXISTS ...`)
and listed in the `db-migrate` service in `compose.yaml`. `db-migrate` then
applies it on the next start.

To apply migrations by hand without restarting everything:

```sh
docker compose run --rm db-migrate
```

The `NOTICE: ... already exists, skipping` lines in its output are normal.

### 5. Troubleshooting

**`column ... does not exist` / `relation ... does not exist` (500 errors).**
The database was created before that column or table was added, and the
migration has not run. Run `docker compose run --rm db-migrate`. If it still
fails, the schema change is missing a migration file: add one as described
above.

**`db-migrate` fails with `password authentication failed`.** `.env` was
changed (or `make key` re-run) after the database volume was created; the
volume still has the original password. Keep the data by setting the role
password to the current `.env` value:

```sh
docker compose exec db psql -U biovault_user -d biovault_db
```

At the `psql` prompt run `\password biovault_user`, enter the current
`POSTGRES_PASSWORD` from `.env`, then `\q`, and start again with
`docker compose up --build`. If `make key` was re-run, also restore the old
`FILE_ENCRYPTION_KEY` and `FIELD_ENCRYPTION_KEY` from your backup, or existing
files and emails cannot be decrypted.

**Login says `Credenciales incorrectas` for an account that exists.** The
password is wrong, or the account was deactivated by an admin.

**The browser warns that the certificate is not trusted.** Run `make tls`
(or the Windows script) on that machine and restart the browser. On Firefox,
install `nss` before running it.

**`proxy` exits with `open /certs/cert.pem: no such file or directory`.** The
certificate was not generated yet: see step 2.

**Start from a completely empty database.** This deletes all users and files:

```sh
docker compose down -v
docker compose up --build
```

To inspect the database directly:

```sh
docker compose exec db psql -U biovault_user -d biovault_db
```

## 6. Security overview

Passwords are stored as Argon2id hashes. Uploaded PDFs use
AES-256-GCM envelope encryption: each file gets a random data-encryption key,
which is wrapped by the 32-byte `FILE_ENCRYPTION_KEY`. Rego access decisions
are evaluated by OPA. The initial policy allows owners and denies other users;
OPA failures fail closed. Update `policies/biovault.rego` and, when a rule needs
additional attributes, the OPA input in `backend/main.py` to add future rules.

## 7. Authentication: OAuth 2.0 / OpenID Connect tokens with asymmetric JWTs

The first-party Streamlit frontend signs in at `POST /auth/token` with the
OAuth 2.0 password grant (username, password and mandatory TOTP code).
Errors follow RFC 6749: a wrong password, TOTP code or refresh token returns
`400 {"error": "invalid_grant"}`; when a TOTP code is still needed the endpoint
returns `403` with `error` `mfa_setup_required` (plus the QR provisioning URL)
or `mfa_required`. Token responses are sent with `Cache-Control: no-store`.

- **Access tokens** are Ed25519-signed JWTs (`alg: EdDSA`, `typ: at+jwt`) that
  carry `sub`, `preferred_username` and `role`. They live 15 minutes and are
  validated statelessly (signature, `iss`, `aud`, `exp`) with the public key
  only: no database lookup per request. Any service can verify them with the
  key published at `/.well-known/jwks.json`.
- **ID tokens** (OpenID Connect) are returned at login: `aud` = the frontend
  client, `auth_time`, `amr: ["pwd", "otp"]` and an optional `nonce`. They are
  rejected as API bearer tokens.
- **Refresh tokens** are opaque random values, stored only as SHA-256 hashes in
  the `refresh_tokens` table (12 h lifetime). `grant_type=refresh_token` at
  `/auth/token` rotates them (single use). This is the only point where the
  user's active status and current role are re-read from the database.
- **Revocation** (`POST /auth/revoke`, RFC 7009): logout and account
  deactivation delete the refresh tokens, so an already-issued access token
  remains valid for at most 15 minutes. This is the deliberate trade-off of
  stateless validation.

Discovery is published at `/.well-known/openid-configuration` and user claims
at `/userinfo`. The issuer is `OIDC_ISSUER` (default `http://localhost:8000`; Docker Compose
sets it to `https://localhost:8443`).
Limitation: OpenID Connect itself defines browser-redirect flows (authorization
code + PKCE); the password grant is used here because the frontend is a
first-party client of the same system.

After upgrading, sign in again: migration `002` drops the old sessions.

## 8. Mock backend

For UI-only testing, run `docker compose -f compose.mock.yaml up --build`.
The mock backend stores users and files in memory and does not provide real
authentication, encryption, or PostgreSQL persistence. Do not use real
passwords or sensitive documents with it.

## 9. Run locally

For local development, start PostgreSQL and OPA with
`docker compose up -d db opa`.
Load the `.env` values into your shell and set the local database URL:

```sh
set -a
. ./.env
set +a
export DATABASE_URL="postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@localhost:5432/${POSTGRES_DB}"
export JWT_PRIVATE_KEY_PATH="../secrets/jwt_private.pem"
export JWT_PUBLIC_KEY_PATH="../secrets/jwt_public.pem"
export OPA_URL="http://localhost:8181"
docker compose run --rm db-migrate
```

Then install dependencies and start the API from `backend/`:

```sh
cd backend
python -m pip install -r requirements.txt
uvicorn main:app --reload
```

Start the frontend from `frontend/` in another terminal:

```sh
python -m pip install -r requirements.txt
streamlit run app.py
```

When running locally, the frontend defaults to `http://localhost:8000` for the
API. Set `BACKEND_URL` to override it.

OPA policy unit tests are in `policies/biovault_test.rego` and can be run with
`docker compose run --rm opa test /policies`.
