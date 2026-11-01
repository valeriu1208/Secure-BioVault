import base64
import binascii
import hashlib
import json
import logging
import os
import secrets
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator
from urllib.error import URLError
from urllib.request import Request as URLRequest, urlopen

import jwt
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)
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
JWT_ISSUER = "secure-biovault"
JWT_AUDIENCE = "secure-biovault-api"
JWT_KEY_ID = "ed25519-v1"
OPA_DECISION_PATH = "/v1/data/biovault/authz/allow"


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


def load_field_encryption_key() -> bytes:
    value = os.environ.get("FIELD_ENCRYPTION_KEY")
    if not value:
        raise RuntimeError("FIELD_ENCRYPTION_KEY must be set to a base64-encoded 32-byte key")
    try:
        key = base64.b64decode(value, altchars=b"-_", validate=True)
    except binascii.Error as exc:
        raise RuntimeError("FIELD_ENCRYPTION_KEY must be valid base64") from exc
    if len(key) != 32:
        raise RuntimeError("FIELD_ENCRYPTION_KEY must decode to exactly 32 bytes")
    return key


def load_jwt_keys() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    private_path = os.environ.get("JWT_PRIVATE_KEY_PATH")
    public_path = os.environ.get("JWT_PUBLIC_KEY_PATH")
    if not private_path or not public_path:
        raise RuntimeError("JWT_PRIVATE_KEY_PATH and JWT_PUBLIC_KEY_PATH must be set")

    try:
        with open(private_path, "rb") as private_file:
            private_key = load_pem_private_key(private_file.read(), password=None)
        with open(public_path, "rb") as public_file:
            public_key = load_pem_public_key(public_file.read())
    except (OSError, ValueError) as exc:
        raise RuntimeError("Unable to load JWT signing keys") from exc

    if not isinstance(private_key, Ed25519PrivateKey) or not isinstance(
        public_key, Ed25519PublicKey
    ):
        raise RuntimeError("JWT signing keys must use Ed25519")
    if private_key.public_key().public_bytes_raw() != public_key.public_bytes_raw():
        raise RuntimeError("JWT signing and verification keys do not match")
    return private_key, public_key


@asynccontextmanager
async def lifespan(app: FastAPI):
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DATABASE_URL must be set")

    app.state.file_encryption_key = load_encryption_key()
    app.state.field_encryption_key = load_field_encryption_key()
    app.state.jwt_private_key, app.state.jwt_public_key = load_jwt_keys()
    app.state.opa_url = os.environ.get("OPA_URL", "http://localhost:8181").rstrip("/")
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

class RoleUpdateIn(BaseModel):
    new_role: str = Field(pattern="^(PATIENT|DOCTOR|ADMIN|RESEARCHER)$")

class RoleRequestIn(BaseModel):
    req_role: str = Field(pattern="^(DOCTOR|RESEARCHER)$")
    justification: str = Field(max_length=500)

class ResolveRequestIn(BaseModel):
    status: str = Field(pattern="^(APPROVED|REJECTED)$")

class DeleteAccountIn(BaseModel):
    password: str = Field(min_length=1)

class UpdateUserActiveStatusIn(BaseModel):
    is_active: bool

def get_db_connection(request: Request) -> Iterator[Connection[Any]]:
    pool: ConnectionPool = request.app.state.db_pool
    with pool.connection() as connection:
        yield connection


def current_user(
    request: Request,
    token: str = Depends(oauth2),
    connection: Connection[Any] = Depends(get_db_connection),
) -> dict[str, Any]:
    try:
        claims = jwt.decode(
            token,
            request.app.state.jwt_public_key,
            algorithms=["EdDSA"],
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER,
            options={"require": ["aud", "exp", "iat", "iss", "jti", "sub"]},
        )
        user_id = uuid.UUID(claims["sub"])
        token_hash = hashlib.sha256(claims["jti"].encode("utf-8")).hexdigest()
    except (jwt.InvalidTokenError, ValueError, KeyError, TypeError) as exc:
        raise HTTPException(status_code=401, detail="Token inválido o caducado") from exc

    user = connection.execute(
        """
        SELECT u.user_id, u.username, u.email, r.role_name
        FROM auth_sessions AS s
        JOIN users AS u ON u.user_id = s.user_id
        JOIN roles AS r ON r.role_id = u.role_id
        WHERE s.token_hash = %s
          AND s.user_id = %s
          AND s.expires_at > CURRENT_TIMESTAMP
          AND u.is_active = TRUE
        """,
        (token_hash, user_id),
    ).fetchone()
    if user is None or user["user_id"] != user_id:
        raise HTTPException(status_code=401, detail="Token inválido o caducado")
    return user


def issue_access_token(user_id: uuid.UUID, private_key: Ed25519PrivateKey) -> tuple[str, str]:
    now = datetime.now(timezone.utc)
    token_id = secrets.token_urlsafe(32)
    claims = {
        "sub": str(user_id),
        "jti": token_id,
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": now,
        "exp": now + SESSION_LIFETIME,
    }
    return (
        jwt.encode(claims, private_key, algorithm="EdDSA", headers={"kid": JWT_KEY_ID}),
        token_id,
    )


def parse_opa_decision(decision: Any) -> bool | None:
    if not isinstance(decision, dict):
        return None
    result = decision.get("result")
    if isinstance(result, bool):
        return result
    if isinstance(result, dict):
        allow = result.get("allow")
        if isinstance(allow, bool):
            return allow
    return None


def public_jwk(public_key: Ed25519PublicKey) -> dict[str, str]:
    public_key_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    encoded_key = base64.urlsafe_b64encode(public_key_bytes).rstrip(b"=").decode("ascii")
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": encoded_key,
        "use": "sig",
        "alg": "EdDSA",
        "kid": JWT_KEY_ID,
    }


def authorize_file_access(
    request: Request,
    user: dict[str, Any],
    action: str,
    owner_id: uuid.UUID,
    connection: Connection[Any], # DB connection to access permisions
    *,
    denial_status_code: int = 403,
) -> None:
    allowed_users = []
    allowed_roles = []
    consents = connection.execute(
        """
        SELECT granted_to_user_id, granted_to_role
        FROM consents
        WHERE patient_id = %s AND is_granted = TRUE AND expires_at > CURRENT_TIMESTAMP
        """,
        (owner_id,)
    ).fetchall()

    for c in consents:
        if c["granted_to_user_id"]:
            allowed_users.append(str(c["granted_to_user_id"]))
        if c["granted_to_role"]:
            allowed_roles.append(c["granted_to_role"])

    input_document = {
        "input": {
            "subject": {
                "id": str(user["user_id"]),
                "role": user["role_name"],
            },
            "action": action,
            "resource": {
                "type": "file",
                "owner_id": str(owner_id),
                "allowed_users": allowed_users,
                "allowed_roles": allowed_roles,
            },
        }
    }
    opa_request = URLRequest(
        f"{request.app.state.opa_url}{OPA_DECISION_PATH}",
        data=json.dumps(input_document).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(opa_request, timeout=2) as response:
            decision = json.loads(response.read())
    except (URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        logger.warning("OPA authorization request failed: %s", exc)
        raise HTTPException(status_code=503, detail="Authorization service unavailable") from exc

    allow = parse_opa_decision(decision)
    if not isinstance(allow, bool):
        logger.error("OPA returned an invalid authorization decision")
        raise HTTPException(status_code=503, detail="Authorization service unavailable")
    if not allow:
        raise HTTPException(
            status_code=denial_status_code,
            detail="No autorizado para acceder a este documento",
        )


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


def encrypt_field(text: str, key: bytes) -> str:
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(nonce, text.encode("utf-8"), None)
    return base64.b64encode(nonce + ciphertext).decode("ascii")


def decrypt_field(enc_text: str, key: bytes) -> str:
    try:
        data = base64.b64decode(enc_text)
        nonce, ciphertext = data[:12], data[12:]
        return AESGCM(key).decrypt(nonce, ciphertext, None).decode("utf-8")
    except Exception:
        return "[DATOS CORRUPTOS]"


# Creates hash for DB lookup (via user email)
def get_blind_index(text: str) -> str:
    return hashlib.sha256(text.lower().strip().encode("utf-8")).hexdigest()


@app.get("/")
def read_root() -> dict[str, str]:
    return {"message": "Secure BioVault API is running"}


@app.get("/.well-known/jwks.json")
def jwks(request: Request) -> dict[str, list[dict[str, str]]]:
    return {"keys": [public_jwk(request.app.state.jwt_public_key)]}


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


@app.post("/auth/register", status_code=201)
def register(
    request: Request,
    body: RegisterIn,
    connection: Connection[Any] = Depends(get_db_connection),
) -> dict[str, str]:
    try:
        # field-level enc & blind index (hash)
        enc_email = encrypt_field(body.email, request.app.state.field_encryption_key)
        email_hash = get_blind_index(body.email)

        with connection.transaction():
            user = connection.execute(
                """
                INSERT INTO users (username, email, email_hash, role_id)
                SELECT %s, %s, %s, role_id
                FROM roles
                WHERE role_name = 'PATIENT'
                RETURNING user_id
                """,
                (body.username, enc_email, email_hash),
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
    request: Request,
    form: OAuth2PasswordRequestForm = Depends(),
    connection: Connection[Any] = Depends(get_db_connection),
) -> dict[str, Any]:
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

    access_token, token_id = issue_access_token(user["user_id"], request.app.state.jwt_private_key)
    token_hash = hashlib.sha256(token_id.encode("utf-8")).hexdigest()
    expires_at = datetime.now(timezone.utc) + SESSION_LIFETIME
    connection.execute(
        "INSERT INTO auth_sessions (token_hash, user_id, expires_at) VALUES (%s, %s, %s)",
        (token_hash, user["user_id"], expires_at),
    )
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": int(SESSION_LIFETIME.total_seconds()),
    }


@app.get("/users/me")
def me(request: Request, user: dict[str, Any] = Depends(current_user)) -> dict[str, str]:
    dec_email = decrypt_field(user["email"], request.app.state.field_encryption_key)
    return {"username": user["username"], "email": dec_email, "role": user["role_name"]}


@app.get("/files")
def list_files(
    request: Request,
    user: dict[str, Any] = Depends(current_user),
    connection: Connection[Any] = Depends(get_db_connection),
) -> list[dict[str, Any]]:
    authorize_file_access(request, user, "list", user["user_id"], connection)
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
    authorize_file_access(request, user, "create", user["user_id"], connection)
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
        SELECT owner_id, content, encrypted_dek, iv_nonce
        FROM files
        WHERE file_id = %s
        """,
        (file_id,),
    ).fetchone()
    if record is None:
        raise HTTPException(status_code=404, detail="Documento no encontrado")
    authorize_file_access(
        request,
        user,
        "read",
        record["owner_id"],
        connection,
        denial_status_code=404,
    )
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
    request: Request,
    file_id: uuid.UUID,
    user: dict[str, Any] = Depends(current_user),
    connection: Connection[Any] = Depends(get_db_connection),
) -> None:
    record = connection.execute(
        "SELECT owner_id FROM files WHERE file_id = %s",
        (file_id,),
    ).fetchone()
    if record is None:
        raise HTTPException(status_code=404, detail="Documento no encontrado")
    authorize_file_access(
        request,
        user,
        "delete",
        record["owner_id"],
        connection,
        denial_status_code=404,
    )
    deleted = connection.execute(
        "DELETE FROM files WHERE file_id = %s AND owner_id = %s RETURNING file_id",
        (file_id, record["owner_id"]),
    ).fetchone()
    if deleted is None:
        raise HTTPException(status_code=404, detail="Documento no encontrado")


@app.post("/auth/logout", status_code=204)
def logout(
    request: Request,
    token: str = Depends(oauth2),
    connection: Connection[Any] = Depends(get_db_connection),
) -> None:
    try:
        claims = jwt.decode(
            token,
            request.app.state.jwt_public_key,
            algorithms=["EdDSA"],
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER,
            options={"verify_exp": False, "require": ["jti"]}
        )
        token_hash = hashlib.sha256(claims["jti"].encode("utf-8")).hexdigest()
        
        connection.execute(
            "DELETE FROM auth_sessions WHERE token_hash = %s", 
            (token_hash,)
        )
    except jwt.InvalidTokenError:
        pass


@app.get("/admin/users")
def list_all_users(
    request: Request,
    user: dict[str, Any] = Depends(current_user),
    connection: Connection[Any] = Depends(get_db_connection),
) -> list[dict[str, Any]]:
    if user["role_name"] != "ADMIN":
        raise HTTPException(status_code=403, detail="Requiere privilegios de administrador")
    
    users_db = connection.execute(
        """
        SELECT u.user_id, u.username, u.email, r.role_name, u.is_active
        FROM users u
        JOIN roles r ON u.role_id = r.role_id
        ORDER BY u.created_at DESC
        """
    ).fetchall()

    for u in users_db:
        u['email'] = decrypt_field(u['email'], request.app.state.field_encryption_key)
    return users_db


@app.patch("/admin/users/{target_user_id}/role")
def update_user_role(  
    request: Request,
    target_user_id: uuid.UUID,
    body: RoleUpdateIn,
    user: dict[str, Any] = Depends(current_user),
    connection: Connection[Any] = Depends(get_db_connection),
) -> dict[str, str]:
    # Delegar la verificación de permisos a OPA
    authorize_file_access(
        request,
        user,
        "change_role",
        resource=str(target_user_id),
        connection=connection,
        denial_status_code=403
    )

    role_record = connection.execute(
        "SELECT role_id FROM roles WHERE role_name = %s", 
        (body.new_role,)
    ).fetchone()

    if not role_record:
        raise HTTPException(status_code=400, detail="Rol inválido")

    updated = connection.execute(
        "UPDATE users SET role_id = %s WHERE user_id = %s RETURNING user_id",
        (role_record["role_id"], target_user_id)
    ).fetchone()

    if not updated:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    return {"message": f"Rol actualizado a {body.new_role}"}


@app.get("/doctor/patients")
def search_patients(
    request: Request,
    query: str = "",
    user: dict[str, Any] = Depends(current_user),
    connection: Connection[Any] = Depends(get_db_connection),
) -> list[dict[str, Any]]:
    if user["role_name"] not in ("DOCTOR", "RESEARCHER", "ADMIN"):
        raise HTTPException(status_code=403, detail="Acceso denegado")

    sql = """
        SELECT u.user_id, u.username, u.email
        FROM users u
        JOIN roles r ON u.role_id = r.role_id
        WHERE r.role_name = 'PATIENT'
    """
    params = []
    if query: # partial name or email hash
        email_hash = get_blind_index(query)
        sql += " AND (u.username ILIKE %s OR u.email_hash = %s)"
        params.extend([f"%{query}%", email_hash])
    
    patients = connection.execute(sql, params).fetchall()
    # decrypt email field
    for p in patients:
        p['email'] = decrypt_field(p['email'], request.app.state.field_encryption_key)
    return patients


@app.get("/doctor/patients/{patient_id}/files")
def list_patient_files_for_doctor(
    patient_id: uuid.UUID,
    request: Request,
    user: dict[str, Any] = Depends(current_user),
    connection: Connection[Any] = Depends(get_db_connection),
) -> list[dict[str, Any]]:
    if user["role_name"] != "ADMIN":
        try:
            authorize_file_access(request, user, "list", patient_id, connection)
        except HTTPException:
            raise
        except Exception as exc:
            logger.error("Error authorizing file access: %s", exc)
            raise HTTPException(status_code=403, detail="No se pudo verificar el consentimiento del paciente")

    return connection.execute(
        """
        SELECT file_id AS id, original_filename AS filename, description, created_at
        FROM files
        WHERE owner_id = %s
        ORDER BY created_at DESC
        """,
        (patient_id,),
    ).fetchall()


@app.delete("/users/me")
def delete_user(
    body: DeleteAccountIn,
    user: dict[str, Any] = Depends(current_user),
    connection: Connection[Any] = Depends(get_db_connection),
)-> dict[str, str]:
    user_id = user["user_id"]
    record = connection.execute(
        "SELECT password_hash FROM credentials WHERE user_id = %s",
        (user_id,),
    ).fetchone()
    if record is None or not password_hash.verify(body.password, record["password_hash"]):
        raise HTTPException(status_code=401, detail="Contraseña incorrecta")
    with connection.transaction():
        connection.execute("UPDATE users SET is_active = FALSE WHERE user_id = %s", (user_id,))
        connection.execute("DELETE FROM auth_sessions WHERE user_id = %s", (user_id,))
    return {"message": "Usuario desactivado correctamente"}


@app.delete("/admin/users/{target_user_id}")
def delete_user_by_admin(
    target_user_id: uuid.UUID,
    user: dict[str, Any] = Depends(current_user),
    connection: Connection[Any] = Depends(get_db_connection),
)-> dict[str, str]:
    if user["role_name"] != "ADMIN":
        raise HTTPException(status_code=403, detail="Requiere privilegios de administrador")
    
    with connection.transaction():
        target = connection.execute("SELECT user_id FROM users WHERE user_id = %s", (target_user_id,)).fetchone()
        if not target:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        connection.execute("UPDATE users SET is_active = FALSE WHERE user_id = %s", (target_user_id,))
        connection.execute("DELETE FROM auth_sessions WHERE user_id = %s", (target_user_id,))

    return {"message": "Usuario desactivado correctamente por el administrador"}


@app.patch("/admin/users/{target_user_id}/active")
def update_user_active_status(
    target_user_id: uuid.UUID,
    body: UpdateUserActiveStatusIn,
    user: dict[str, Any] = Depends(current_user),
    connection: Connection[Any] = Depends(get_db_connection),
) -> dict[str, str]:
    if user["role_name"] != "ADMIN":
        raise HTTPException(status_code=403, detail="Requiere privilegios de administrador")

    with connection.transaction():
        target = connection.execute("SELECT user_id FROM users WHERE user_id = %s", (target_user_id,)).fetchone()
        if not target:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        connection.execute("UPDATE users SET is_active = %s WHERE user_id = %s", (body.is_active, target_user_id))
        if not body.is_active:
            connection.execute("DELETE FROM auth_sessions WHERE user_id = %s", (target_user_id,))

    return {"message": "Estado de cuenta actualizado correctamente por el administrador"}


@app.post("/users/me/role-request", status_code=201)
def create_role_request(
    body: RoleRequestIn,
    user: dict[str, Any] = Depends(current_user),
    connection: Connection[Any] = Depends(get_db_connection),
) -> dict[str, str]:
    # Avoid spamming
    pending = connection.execute(
        "SELECT 1 FROM role_requests WHERE user_id = %s AND status = 'PENDING'",
        (user['user_id'],)
    ).fetchone()
    if pending:
        raise HTTPException(status_code=400, detail="Ya tienes una solicitud de cambio de rol pendiente.")

    connection.execute(
        "INSERT INTO role_requests (user_id, req_role, justification) VALUES (%s, %s, %s)",
        (user['user_id'], body.req_role, body.justification)
    )
    return {"message": "Solicitud enviada con éxito"}

@app.get("/admin/role-requests")
def list_role_requests(
    request: Request,
    user: dict[str, Any] = Depends(current_user),
    connection: Connection[Any] = Depends(get_db_connection),
) -> list[dict[str, Any]]:
    if user['role_name'] != "ADMIN":
        raise HTTPException(status_code=403, detail="Se requieren privilegios de administrador")

    requests_db = connection.execute(
        """
        SELECT r.req_id, u.username, u.email, r.req_role, r.justification, r.created_at
        FROM role_requests r
        JOIN users u ON r.user_id = u.user_id
        WHERE r.status = 'PENDING'
        ORDER BY r.created_at ASC
        """
    ).fetchall()

    # Decrypt emails (for admin's view only)
    for r in requests_db:
        r['email'] = decrypt_field(r['email'], request.app.state.field_encryption_key)
    return requests_db

@app.patch("/admin/role-requests/{request_id}")
def resolve_role_request(
    request_id: uuid.UUID,
    body: ResolveRequestIn,
    user: dict[str, Any] = Depends(current_user),
    connection: Connection[Any] = Depends(get_db_connection),
) -> dict[str, str]:
    if user['role_name'] != "ADMIN":
        raise HTTPException(status_code=403, detail="Se requieren privilegios de administrador")

    with connection.transaction():
        req = connection.execute(
            "SELECT user_id, req_role FROM role_requests WHERE req_id = %s AND status = 'PENDING'",
            (request_id,)
        ).fetchone()

        if not req:
            raise HTTPException(status_code=404, detail="Solicitud no encontrada o ya resuelta")

        connection.execute("UPDATE role_requests SET status = %s WHERE req_id = %s", (body.status, request_id))
        if body.status == "APPROVED":
            role_record = connection.execute("SELECT role_id FROM roles WHERE role_name = %s", (req['req_role'],)).fetchone()
            connection.execute("UPDATE users SET role_id = %s WHERE user_id = %s", (role_record['role_id'], req['user_id']))

    return {"message": f"Solicitud {body.status.lower()}"}
