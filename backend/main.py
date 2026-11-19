import logging
import os
from contextlib import asynccontextmanager
from typing import Any
from urllib.error import URLError
from urllib.request import urlopen

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import Response
from psycopg import Connection, Error as PsycopgError
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool, PoolTimeout

from audit import derive_audit_hmac_key
from config import load_encryption_key, load_field_encryption_key, load_jwt_keys
from database import get_db_connection
from routers import admin, auth, doctor, files, users

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DATABASE_URL must be set")

    app.state.file_encryption_key = load_encryption_key()
    app.state.field_encryption_key = load_field_encryption_key()
    app.state.audit_hmac_key = derive_audit_hmac_key(app.state.field_encryption_key)
    app.state.jwt_private_key, app.state.jwt_public_key = load_jwt_keys()
    app.state.opa_url = os.environ.get("OPA_URL", "http://localhost:8181").rstrip("/")
    with (
        ConnectionPool(
            conninfo=database_url,
            min_size=1,
            max_size=10,
            kwargs={"row_factory": dict_row},
        ) as pool,
        ConnectionPool(
            conninfo=database_url,
            min_size=1,
            max_size=4,
            kwargs={"row_factory": dict_row},
        ) as audit_pool,
    ):
        app.state.db_pool = pool
        app.state.audit_db_pool = audit_pool
        yield


app = FastAPI(title="Secure BioVault API", lifespan=lifespan)


@app.middleware("http")
async def no_store_token_responses(request: Request, call_next: Any) -> Response:
    """RFC 6749 section 5.1: token responses MUST NOT be cached (success or error)."""
    response = await call_next(request)
    if request.url.path == "/auth/token":
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
    return response


@app.get("/")
def read_root() -> dict[str, str]:
    return {"message": "Secure BioVault API is running"}


@app.get("/health")
def health_check(
    request: Request,
    connection: Connection[Any] = Depends(get_db_connection),
) -> dict[str, str]:
    try:
        connection.execute("SELECT 1")
        with urlopen(f"{request.app.state.opa_url}/health", timeout=2):
            pass
    except (PsycopgError, PoolTimeout) as exc:
        logger.warning("Database health check failed: %s", exc)
        raise HTTPException(status_code=503, detail="Database unavailable") from exc
    except (URLError, TimeoutError, OSError) as exc:
        logger.warning("OPA health check failed: %s", exc)
        raise HTTPException(status_code=503, detail="Authorization service unavailable") from exc
    return {"status": "ok", "database": "ok", "authorization": "ok"}


app.include_router(auth.router)
app.include_router(users.router)
app.include_router(files.router)
app.include_router(doctor.router)
app.include_router(admin.router)