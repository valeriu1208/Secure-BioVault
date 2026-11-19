from datetime import datetime, timezone
from typing import Any

import pyotp
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from psycopg import Connection
from psycopg.errors import UniqueViolation

from audit import record_audit_log
from database import get_db_connection
from schemas import RegisterIn
from security import (
    decrypt_field,
    encrypt_field,
    get_blind_index,
    hash_refresh_token,
    issue_id_token,
    issue_token_pair,
    password_hash,
)

router = APIRouter(tags=["Auth"])


def oauth_error(error: str, description: str) -> JSONResponse:
    """RFC 6749 section 5.2 error response."""
    return JSONResponse({"error": error, "error_description": description}, status_code=400)


@router.post("/auth/register", status_code=201)
def register(
    request: Request,
    body: RegisterIn,
    connection: Connection[Any] = Depends(get_db_connection),
) -> dict[str, str]:
    try:
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


def refresh_grant(
    request: Request, refresh_token: str | None, connection: Connection[Any]
) -> Any:
    """Exchange a refresh token for a new token pair (refresh-token rotation)."""
    with connection.transaction():
        row = connection.execute(
            """
            DELETE FROM refresh_tokens
            WHERE token_hash = %s
            RETURNING user_id, expires_at
            """,
            (hash_refresh_token(refresh_token or ""),),
        ).fetchone()
        if row is None or row["expires_at"] <= datetime.now(timezone.utc):
            return oauth_error("invalid_grant", "Invalid or expired refresh token")

        user = connection.execute(
            """
            SELECT u.user_id, u.username, r.role_name
            FROM users AS u
            JOIN roles AS r ON r.role_id = u.role_id
            WHERE u.user_id = %s AND u.is_active = TRUE
            """,
            (row["user_id"],),
        ).fetchone()
        if user is None:
            return oauth_error("invalid_grant", "User is not active")

        return issue_token_pair(
            connection,
            user["user_id"],
            user["username"],
            user["role_name"],
            request.app.state.jwt_private_key,
        )


@router.post("/auth/token")
def token(
    request: Request,
    grant_type: str = Form(default="password"),
    username: str | None = Form(default=None),
    password: str | None = Form(default=None),
    totp_code: str | None = Form(default=None),
    nonce: str | None = Form(default=None, max_length=512),
    refresh_token: str | None = Form(default=None),
    connection: Connection[Any] = Depends(get_db_connection),
) -> Any:
    """OAuth 2.0 token endpoint: password grant (+ TOTP) or refresh_token grant."""
    if grant_type == "refresh_token":
        return refresh_grant(request, refresh_token, connection)
    if grant_type != "password":
        return oauth_error("unsupported_grant_type", "Use password or refresh_token")
    if not username or not password:
        return oauth_error("invalid_request", "username and password are required")

    with connection.transaction():
        user = connection.execute(
            """
            SELECT u.user_id, u.username, u.email, r.role_name,
                   c.password_hash, c.mfa_enabled, c.totp_secret
            FROM users AS u
            JOIN credentials AS c ON c.user_id = u.user_id
            JOIN roles AS r ON r.role_id = u.role_id
            WHERE u.username = %s AND u.is_active = TRUE
            """,
            (username,),
        ).fetchone()

        if user is None or not password_hash.verify(password, user["password_hash"]):
            record_audit_log(
                request,
                user_id=user["user_id"] if user else None,
                action="LOGIN_ATTEMPT",
                decision="DENIED",
                reason=f"Invalid credentials for username = {username}",
            )
            return oauth_error("invalid_grant", "Credenciales incorrectas")

        key = request.app.state.field_encryption_key

        if not user["mfa_enabled"]:
            if not user["totp_secret"]:
                secret = pyotp.random_base32()
                enc_secret = encrypt_field(secret, key)
                connection.execute(
                    "UPDATE credentials SET totp_secret = %s WHERE user_id = %s",
                    (enc_secret, user["user_id"]),
                )
            else:
                secret = decrypt_field(user["totp_secret"], key)

            if not totp_code:
                dec_email = decrypt_field(user["email"], key)
                otpauth_url = pyotp.TOTP(secret).provisioning_uri(
                    name=dec_email, issuer_name="SecureBioVault"
                )
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "mfa_setup_required",
                        "error_description": "Scan the QR code and send totp_code",
                        "code": "MFA_SETUP_REQUIRED",
                        "otpauth_url": otpauth_url,
                        "secret": secret,
                    },
                )

            if not pyotp.TOTP(secret).verify(totp_code.strip(), valid_window=1):
                record_audit_log(
                    request,
                    user_id=user["user_id"],
                    action="LOGIN_ATTEMPT",
                    decision="DENIED",
                    reason="Invalid TOTP code",
                )
                return oauth_error("invalid_grant", "Código de verificación inválido")

            connection.execute(
                "UPDATE credentials SET mfa_enabled = TRUE WHERE user_id = %s",
                (user["user_id"],),
            )
        else:
            if not totp_code:
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "mfa_required",
                        "error_description": "Send totp_code from the authenticator app",
                        "code": "MFA_REQUIRED",
                    },
                )

            secret = decrypt_field(user["totp_secret"], key)
            if not pyotp.TOTP(secret).verify(totp_code.strip(), valid_window=1):
                record_audit_log(
                    request,
                    user_id=user["user_id"],
                    action="LOGIN_ATTEMPT",
                    decision="DENIED",
                    reason="Invalid TOTP code",
                )
                return oauth_error("invalid_grant", "Código de verificación incorrecto o caducado")

        tokens = issue_token_pair(
            connection,
            user["user_id"],
            user["username"],
            user["role_name"],
            request.app.state.jwt_private_key,
        )
    tokens["id_token"] = issue_id_token(
        user["user_id"], user["username"], request.app.state.jwt_private_key, nonce
    )
    record_audit_log(
        request,
        user_id=user["user_id"],
        action="LOGIN_ATTEMPT",
        decision="ALLOWED",
        reason="Password and TOTP verified",
    )
    return tokens


@router.post("/auth/revoke")
def revoke(
    token: str = Form(...),
    token_type_hint: str | None = Form(default=None),
    connection: Connection[Any] = Depends(get_db_connection),
) -> Response:
    """RFC 7009 token revocation (logout): deletes the refresh token."""
    connection.execute(
        "DELETE FROM refresh_tokens WHERE token_hash = %s", (hash_refresh_token(token),)
    )
    return Response(status_code=200)