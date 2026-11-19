import base64
import binascii
import os
from datetime import timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)

MAX_FILE_SIZE = 25 * 1024 * 1024

ACCESS_TOKEN_LIFETIME = timedelta(minutes=15)
REFRESH_TOKEN_LIFETIME = timedelta(hours=12)
JWT_ISSUER = os.environ.get("OIDC_ISSUER", "http://localhost:8000").rstrip("/")
OIDC_CLIENT_ID = "biovault-frontend"
JWT_AUDIENCE = "secure-biovault-api"
JWT_KEY_ID = "ed25519-v1"

OPA_DECISION_PATH = "/v1/data/biovault/authz/allow"

VALID_ROLES = frozenset({"PATIENT", "DOCTOR", "RESEARCHER", "ADMIN"})


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