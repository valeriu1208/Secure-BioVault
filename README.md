# Secure BioVault

Secure BioVault uses FastAPI for the backend API and Streamlit for the frontend.

## Run with Docker Compose

To run the UI with the in-memory mock backend and the PostgreSQL database, run
this from the repository root:

```sh
docker compose -f compose.mock.yaml up --build
```

Open the Streamlit frontend at <http://localhost:8501>. The mock API is also
available at <http://localhost:8000>, and PostgreSQL is available locally on
port 5432. Register a user in the UI, then sign in.

Stop the services with `Ctrl+C`, or run `docker compose -f compose.mock.yaml down`
in another terminal. PostgreSQL data is kept in a named volume; remove it only
when you intentionally want to erase the database with
`docker compose -f compose.mock.yaml down -v`.

The mock backend stores users and files in memory, loses them when stopped, and
does not provide real authentication or encryption. It does not connect to
PostgreSQL, so only database data persists. Do not use real passwords or
sensitive documents with the mock. The regular `compose.yaml` starts the
initial FastAPI backend and PostgreSQL database; the backend currently only
implements health-check routes, so it is not yet integrated with the frontend's
vault features.

## Run locally

Start the API from `backend/`:

```sh
python -m pip install -r requirements.txt
uvicorn main:app --reload
```

Start the frontend from `frontend/` in another terminal:

```sh
python -m pip install -r requirements.txt
streamlit run app.py
```

When running locally, the frontend defaults to `http://localhost:8000` for the
API. Set `API_BASE_URL` to override it.
