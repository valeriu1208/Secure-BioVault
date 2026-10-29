# Secure BioVault

Secure BioVault uses FastAPI, Streamlit, and PostgreSQL.

## Run with Docker Compose

Generate a database password and a 32-byte file-encryption key:

```sh
make key
```

or

Create a `.env` file in the repository root with these values, using the
generated password and key:

```sh
python3 -c "import base64, secrets; print('POSTGRES_PASSWORD=' + secrets.token_hex(24)); print('FILE_ENCRYPTION_KEY=' + base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"
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

Passwords are stored as Argon2 hashes. Session tokens are random bearer tokens
whose hashes are stored in PostgreSQL. Uploaded PDFs are encrypted with
AES-256-GCM using a per-file key; that key is wrapped by `FILE_ENCRYPTION_KEY`.

## Mock backend

For UI-only testing, run `docker compose -f compose.mock.yaml up --build`.
The mock backend stores users and files in memory and does not provide real
authentication, encryption, or PostgreSQL persistence. Do not use real
passwords or sensitive documents with it.

## Run locally

For local development, start PostgreSQL with `docker compose up -d db`.
Load the `.env` values into your shell and set the local database URL:

```sh
set -a
. ./.env
set +a
export DATABASE_URL="postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@localhost:5432/${POSTGRES_DB}"
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
