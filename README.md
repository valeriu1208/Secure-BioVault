# Secure BioVault

Secure BioVault uses FastAPI for the backend API and Streamlit for the frontend.

## Run with Docker Compose

From the repository root, start both services:

```sh
docker compose up --build
```

Open the Streamlit frontend at <http://localhost:8501>. The API is available at
<http://localhost:8000>, with its health check at <http://localhost:8000/health>.
The frontend connects to the backend using the Compose service name `backend`.

Stop the services with `Ctrl+C`, or run `docker compose down` in another
terminal.

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
