# Secure BioVault

Secure BioVault uses FastAPI, Streamlit, and PostgreSQL.

## Run with Docker Compose

On a fresh setup, run `make key` from the repository root to generate the
database password, 32-byte file-encryption key, and Ed25519 signing key pair.
It creates `.env` and the ignored `secrets/` directory and refuses to overwrite
existing credentials. Keep backups of these values; changing the database
password does not change the password in an existing database volume, and
changing the encryption key prevents decrypting files encrypted with its
previous value. Do not commit or share the private signing key.

Alternatively, create `.env` using the generated values below, then create the
JWT key files:

```sh
python3 -c "import base64, secrets; print('POSTGRES_PASSWORD=' + secrets.token_hex(24)); print('FILE_ENCRYPTION_KEY=' + base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"
mkdir -p secrets
openssl genpkey -algorithm Ed25519 -out secrets/jwt_private.pem
openssl pkey -in secrets/jwt_private.pem -pubout -out secrets/jwt_public.pem
chmod 600 secrets/jwt_private.pem
```

```text
POSTGRES_DB=biovault_db
POSTGRES_USER=biovault_user
POSTGRES_PASSWORD=paste-the-generated-password-here
FILE_ENCRYPTION_KEY=paste-the-generated-key-here
```

Keep this key secret and back it up securely. Files cannot be decrypted if the
key is lost. Then start the app:

```sh
docker compose up --build
```

Open the frontend at <http://localhost:8501>. The API is at
<http://localhost:8000>, with an OpenAPI page at <http://localhost:8000/docs>.
The backend waits for PostgreSQL and applies the idempotent API schema migration
before starting. Register an account in the UI, sign in, and upload PDFs.

Stop the services with `Ctrl+C`, or run `docker compose down` in another
terminal. PostgreSQL data persists in the `postgres_api_data` volume. This
separate volume leaves any older `postgres_data` volume untouched. Do not use
`docker compose down -v` unless you intentionally want to delete the new
database data.

If `db-migrate` reports password authentication failure after changing
`.env`, the database volume still has its original role password. To preserve
the database, open a local `psql` session in the running database container:

```sh
docker compose exec db psql -U biovault_user -d biovault_db
```

At the `psql` prompt, run `\password biovault_user` and enter the current
`POSTGRES_PASSWORD` value from `.env` when prompted, then run `\q`. Retry the
migration and startup:

```sh
docker compose run --rm db-migrate
docker compose up --build -d
```

Do not run `make key` to fix this error. If it has already been run on an
existing setup, restore the previous `FILE_ENCRYPTION_KEY` from a backup before
starting the backend, or previously encrypted files may no longer be readable.

Passwords are stored as Argon2id hashes. OAuth2 access tokens are signed using
Ed25519 and validated by the API; their token IDs are hashed in PostgreSQL so
the existing session-expiry checks remain in force. Uploaded PDFs use
AES-256-GCM envelope encryption: each file gets a random data-encryption key,
which is wrapped by the 32-byte `FILE_ENCRYPTION_KEY`. Rego access decisions
are evaluated by OPA. The initial policy allows owners and denies other users;
OPA failures fail closed. Update `policies/biovault.rego` and, when a rule needs
additional attributes, the OPA input in `backend/main.py` to add future rules.
The Ed25519 public key is published at `/.well-known/jwks.json`.
After upgrading, sign in again: previously issued opaque session tokens are
not accepted as JWTs. The existing password-form token endpoint is retained
for frontend compatibility; for public clients, use an authorization-code
flow with PKCE or an external OAuth/OIDC provider.

## Mock backend

For UI-only testing, run `docker compose -f compose.mock.yaml up --build`.
The mock backend stores users and files in memory and does not provide real
authentication, encryption, or PostgreSQL persistence. Do not use real
passwords or sensitive documents with it.

## Run locally

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
