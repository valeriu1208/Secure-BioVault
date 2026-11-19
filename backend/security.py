import base64
import hashlib
import secrets
import uuid
from datetime import datetime, timezone
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi import HTTPException
from psycopg import Connection
from pwdlib import PasswordHash

from config import (
    ACCESS_TOKEN_LIFETIME,
    JWT_AUDIENCE,
    JWT_ISSUER,
    JWT_KEY_ID,
    OIDC_CLIENT_ID,
    REFRESH_TOKEN_LIFETIME,
    VALID_ROLES,
)

password_hash = PasswordHash.recommended()


def verify_access_token(token: str, public_key: Ed25519PublicKey) -> dict[str, Any]:
    """Validate an access token using only the public key (no database lookup)."""
    try:
        claims = jwt.decode(
            token,
            public_key,
            algorithms=["EdDSA"],
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER,
            options={
                "require": ["aud", "exp", "iat", "iss", "jti", "sub", "role", "preferred_username"]
            },
        )
        if jwt.get_unverified_header(token).get("typ") != "at+jwt":
            raise jwt.InvalidTokenError("Not an access token")
        user_id = uuid.UUID(claims["sub"])
        role = claims["role"]
        username = claims["preferred_username"]
        if role not in VALID_ROLES or not isinstance(username, str):
            raise jwt.InvalidTokenError("Invalid role or username claim")
    except (jwt.InvalidTokenError, ValueError, KeyError, TypeError) as exc:
        raise HTTPException(
            status_code=401,
            detail="Token inválido o caducado",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    return {"user_id": user_id, "username": username, "role_name": role}


def issue_access_token(
    user_id: uuid.UUID,
    username: str,
    role: str,
    private_key: Ed25519PrivateKey,
) -> str:
    now = datetime.now(timezone.utc)
    claims = {
        "sub": str(user_id),
        "preferred_username": username,
        "role": role,
        "jti": secrets.token_urlsafe(16),
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": now,
        "exp": now + ACCESS_TOKEN_LIFETIME,
    }
    return jwt.encode(
        claims,
        private_key,
        algorithm="EdDSA",
        headers={"kid": JWT_KEY_ID, "typ": "at+jwt"},
    )


def issue_id_token(
    user_id: uuid.UUID, username: str, private_key: Ed25519PrivateKey, nonce: str | None = None
) -> str:
    """OpenID Connect ID token: tells the client who authenticated and how."""
    now = datetime.now(timezone.utc)
    claims: dict[str, Any] = {
        "iss": JWT_ISSUER,
        "sub": str(user_id),
        "aud": OIDC_CLIENT_ID,
        "iat": now,
        "exp": now + ACCESS_TOKEN_LIFETIME,
        "auth_time": int(now.timestamp()),
        "amr": ["pwd", "otp"],
        "preferred_username": username,
    }
    if nonce:
        claims["nonce"] = nonce
    return jwt.encode(
        claims, private_key, algorithm="EdDSA", headers={"kid": JWT_KEY_ID, "typ": "JWT"}
    )


def hash_refresh_token(refresh_token: str) -> str:
    return hashlib.sha256(refresh_token.encode("utf-8")).hexdigest()


def issue_token_pair(
    connection: Connection[Any],
    user_id: uuid.UUID,
    username: str,
    role: str,
    private_key: Ed25519PrivateKey,
) -> dict[str, Any]:
    """Create a stateless access token plus a stored, single-use refresh token."""
    refresh_token = secrets.token_urlsafe(48)
    connection.execute(
        "INSERT INTO refresh_tokens (token_hash, user_id, expires_at) VALUES (%s, %s, %s)",
        (
            hash_refresh_token(refresh_token),
            user_id,
            datetime.now(timezone.utc) + REFRESH_TOKEN_LIFETIME,
        ),
    )
    return {
        "access_token": issue_access_token(user_id, username, role, private_key),
        "token_type": "bearer",
        "expires_in": int(ACCESS_TOKEN_LIFETIME.total_seconds()),
        "refresh_token": refresh_token,
        "refresh_expires_in": int(REFRESH_TOKEN_LIFETIME.total_seconds()),
    }


def revoke_refresh_tokens(connection: Connection[Any], user_id: uuid.UUID) -> None:
    connection.execute("DELETE FROM refresh_tokens WHERE user_id = %s", (user_id,))


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


def get_blind_index(text: str) -> str:
    return hashlib.sha256(text.lower().strip().encode("utf-8")).hexdigest()