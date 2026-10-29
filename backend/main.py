import base64
import binascii
import hashlib
import logging
import os
import secrets
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import Response
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from psycopg import Connection, Error as PsycopgError
from psycopg.errors import UniqueViolation
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool, PoolTimeout
from pwdlib import PasswordHash
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)
password_hash = PasswordHash.recommended()
oauth2 = OAuth2PasswordBearer(tokenUrl="/auth/token")
MAX_FILE_SIZE = 25 * 1024 * 1024
SESSION_LIFETIME = timedelta(hours=12)


def load_encryption_key() -> bytes:
    value = os.environ.get("FILE_ENCRYPTION_KEY")
    if not value:
        raise RuntimeError("FILE_ENCRYPTION_KEY must be set to a base64-encoded 32-byte key")
    try:
        key = base64.b64decode(value, altchars=b"-_", validate=True)
    except binascii.Error as exc:
        raise RuntimeError("FILE_ENCRYPTION_KEY must be valid base64") from exc
    if len(key) != 32:
        raise RuntimeError("FILE_ENCRYPTION_KEY must decode to exactly 32 bytes")
    return key


@asynccontextmanager
async def lifespan(app: FastAPI):
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DATABASE_URL must be set")

    app.state.file_encryption_key = load_encryption_key()
    with ConnectionPool(
        conninfo=database_url,
        min_size=1,
        max_size=10,
        kwargs={"row_factory": dict_row},
    ) as pool:
        app.state.db_pool = pool
        yield


app = FastAPI(title="Secure BioVault API", lifespan=lifespan)


class RegisterIn(BaseModel):
    username: str = Field(min_length=3, max_length=100)
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=12, max_length=256)


def get_db_connection(request: Request) -> Iterator[Connection[Any]]:
    pool: ConnectionPool = request.app.state.db_pool
    with pool.connection() as connection:
        yield connection


def current_user(
    token: str = Depends(oauth2),
    connection: Connection[Any] = Depends(get_db_connection),
) -> dict[str, Any]:
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    user = connection.execute(
        """
        SELECT u.user_id, u.username, u.email
        FROM auth_sessions AS s
        JOIN users AS u ON u.user_id = s.user_id
        WHERE s.token_hash = %s
          AND s.expires_at > CURRENT_TIMESTAMP
          AND u.is_active = TRUE
        """,
        (token_hash,),
    ).fetchone()
    if user is None:
        raise HTTPException(status_code=401, detail="Token inválido o caducado")
    return user


def encrypt_file(content: bytes, file_id: uuid.UUID, master_key: bytes) -> tuple[bytes, str, str]:
    data_key = secrets.token_bytes(32)
    data_nonce = secrets.token_bytes(12)
    encrypted_content = AESGCM(data_key).encrypt(data_nonce, content, file_id.bytes)

    wrapping_nonce = secrets.token_bytes(12)
    wrapped_key = AESGCM(master_key).encrypt(wrapping_nonce, data_key, file_id.bytes)
    encrypted_dek = base64.urlsafe_b64encode(wrapping_nonce + wrapped_key).decode("ascii")
    iv_nonce = base64.urlsafe_b64encode(data_nonce).decode("ascii")
    return encrypted_content, encrypted_dek, iv_nonce


def decrypt_file(
    content: bytes,
    encrypted_dek: str,
    iv_nonce: str,
    file_id: uuid.UUID,
    master_key: bytes,
) -> bytes:
    wrapped_key = base64.b64decode(encrypted_dek, altchars=b"-_", validate=True)
    wrapping_nonce, encrypted_key = wrapped_key[:12], wrapped_key[12:]
    data_key = AESGCM(master_key).decrypt(wrapping_nonce, encrypted_key, file_id.bytes)
    data_nonce = base64.b64decode(iv_nonce, altchars=b"-_", validate=True)
    return AESGCM(data_key).decrypt(data_nonce, content, file_id.bytes)


@app.get("/")
def read_root() -> dict[str, str]:
    return {"message": "Secure BioVault API is running"}


@app.get("/health")
def health_check(connection: Connection[Any] = Depends(get_db_connection)) -> dict[str, str]:
    try:
        connection.execute("SELECT 1")
    except (PsycopgError, PoolTimeout) as exc:
        logger.warning("Database health check failed: %s", exc)
        raise HTTPException(status_code=503, detail="Database unavailable") from exc
    return {"status": "ok", "database": "ok"}


@app.post("/auth/register", status_code=201)
def register(
    body: RegisterIn,
    connection: Connection[Any] = Depends(get_db_connection),
) -> dict[str, str]:
    try:
        with connection.transaction():
            user = connection.execute(
                """
                INSERT INTO users (username, email, role_id)
                SELECT %s, %s, role_id
                FROM roles
                WHERE role_name = 'PATIENT'
                RETURNING user_id
                """,
                (body.username, body.email),
            ).fetchone()
            if user is None:
                raise HTTPException(status_code=503, detail="Patient role is not configured")
            connection.execute(
                "INSERT INTO credentials (user_id, password_hash) VALUES (%s, %s)",
                (user["user_id"], password_hash.hash(body.password)),
            )
    except UniqueViolation as exc:
        raise HTTPException(
            status_code=409,
            detail="El usuario o el email ya están registrados",
        ) from exc
    return {"username": body.username, "email": body.email}


@app.post("/auth/token")
def token(
    form: OAuth2PasswordRequestForm = Depends(),
    connection: Connection[Any] = Depends(get_db_connection),
) -> dict[str, str]:
    user = connection.execute(
        """
        SELECT u.user_id, c.password_hash
        FROM users AS u
        JOIN credentials AS c ON c.user_id = u.user_id
        WHERE u.username = %s AND u.is_active = TRUE
        """,
        (form.username,),
    ).fetchone()
    if user is None or not password_hash.verify(form.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")

    access_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(access_token.encode("utf-8")).hexdigest()
    expires_at = datetime.now(timezone.utc) + SESSION_LIFETIME
    connection.execute(
        "INSERT INTO auth_sessions (token_hash, user_id, expires_at) VALUES (%s, %s, %s)",
        (token_hash, user["user_id"], expires_at),
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me")
def me(user: dict[str, Any] = Depends(current_user)) -> dict[str, str]:
    return {"username": user["username"], "email": user["email"]}


@app.get("/files")
def list_files(
    user: dict[str, Any] = Depends(current_user),
    connection: Connection[Any] = Depends(get_db_connection),
) -> list[dict[str, Any]]:
    return connection.execute(
        """
        SELECT file_id AS id, original_filename AS filename, description, created_at
        FROM files
        WHERE owner_id = %s
        ORDER BY created_at DESC
        """,
        (user["user_id"],),
    ).fetchall()


@app.post("/files", status_code=201)
async def upload(
    request: Request,
    file: UploadFile = File(...),
    description: str = Form(""),
    user: dict[str, Any] = Depends(current_user),
    connection: Connection[Any] = Depends(get_db_connection),
) -> dict[str, str]:
    content = await file.read(MAX_FILE_SIZE + 1)
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail="El fichero supera 25 MB")
    if not content.startswith(b"%PDF-"):
        raise HTTPException(status_code=400, detail="El fichero no parece un PDF válido")

    file_id = uuid.uuid4()
    encrypted_content, encrypted_dek, iv_nonce = encrypt_file(
        content,
        file_id,
        request.app.state.file_encryption_key,
    )
    filename = file.filename or "upload.pdf"
    connection.execute(
        """
        INSERT INTO files (
            file_id, owner_id, original_filename, description, file_type,
            storage_path, encrypted_dek, iv_nonce, content
        )
        VALUES (%s, %s, %s, %s, 'PDF', NULL, %s, %s, %s)
        """,
        (
            file_id,
            user["user_id"],
            filename,
            description,
            encrypted_dek,
            iv_nonce,
            encrypted_content,
        ),
    )
    return {"id": str(file_id), "filename": filename}


@app.get("/files/{file_id}")
def download(
    request: Request,
    file_id: uuid.UUID,
    user: dict[str, Any] = Depends(current_user),
    connection: Connection[Any] = Depends(get_db_connection),
) -> Response:
    record = connection.execute(
        """
        SELECT content, encrypted_dek, iv_nonce
        FROM files
        WHERE file_id = %s AND owner_id = %s
        """,
        (file_id, user["user_id"]),
    ).fetchone()
    if record is None:
        raise HTTPException(status_code=404, detail="Documento no encontrado")
    if record["content"] is None:
        raise HTTPException(
            status_code=410,
            detail="El archivo fue creado antes de habilitar el almacenamiento en base de datos",
        )
    try:
        content = decrypt_file(
            record["content"],
            record["encrypted_dek"],
            record["iv_nonce"],
            file_id,
            request.app.state.file_encryption_key,
        )
    except (InvalidTag, ValueError, binascii.Error) as exc:
        logger.exception("Stored file integrity check failed for %s", file_id)
        raise HTTPException(status_code=500, detail="Stored file integrity check failed") from exc
    return Response(content, media_type="application/pdf")


@app.delete("/files/{file_id}", status_code=204)
def delete_file(
    file_id: uuid.UUID,
    user: dict[str, Any] = Depends(current_user),
    connection: Connection[Any] = Depends(get_db_connection),
) -> None:
    deleted = connection.execute(
        "DELETE FROM files WHERE file_id = %s AND owner_id = %s RETURNING file_id",
        (file_id, user["user_id"]),
    ).fetchone()
    if deleted is None:
        raise HTTPException(status_code=404, detail="Documento no encontrado")
