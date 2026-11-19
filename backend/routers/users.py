import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from psycopg import Connection

from database import get_db_connection
from dependencies import current_user
from schemas import DeleteAccountIn, RoleRequestIn
from security import decrypt_field, password_hash, revoke_refresh_tokens

router = APIRouter(tags=["Users"])


@router.get("/users/me")
def me(
    request: Request,
    user: dict[str, Any] = Depends(current_user),
    connection: Connection[Any] = Depends(get_db_connection),
) -> dict[str, str]:
    record = connection.execute(
        "SELECT email FROM users WHERE user_id = %s", (user["user_id"],)
    ).fetchone()
    if record is None:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    dec_email = decrypt_field(record["email"], request.app.state.field_encryption_key)
    return {"username": user["username"], "email": dec_email, "role": user["role_name"]}


@router.get("/users/professionals")
def list_professionals(
    user: dict[str, Any] = Depends(current_user),
    connection: Connection[Any] = Depends(get_db_connection),
):
    return connection.execute(
        """
        SELECT u.user_id, u.username, u.email, r.role_name
        FROM users u
        JOIN roles r ON u.role_id = r.role_id
        WHERE r.role_name IN ('DOCTOR', 'RESEARCHER')
        ORDER BY u.username ASC
        """
    ).fetchall()


@router.get("/users/me/deletion-notices")
def list_my_deletion_notices(
    user: dict[str, Any] = Depends(current_user),
    connection: Connection[Any] = Depends(get_db_connection),
) -> list[dict[str, Any]]:
    rows = connection.execute(
        """
        SELECT notice_id, file_id, original_filename, deleted_by_username, reason, created_at
        FROM file_deletion_notices
        WHERE user_id = %s AND dismissed_at IS NULL
        ORDER BY created_at DESC
        """,
        (user["user_id"],),
    ).fetchall()
    return [
        {
            "notice_id": str(r["notice_id"]),
            "file_id": str(r["file_id"]),
            "original_filename": r["original_filename"],
            "deleted_by_username": r["deleted_by_username"],
            "reason": r["reason"],
            "created_at": r["created_at"].isoformat(),
        }
        for r in rows
    ]


@router.post("/users/me/deletion-notices/{notice_id}/dismiss", status_code=204)
def dismiss_deletion_notice(
    notice_id: uuid.UUID,
    user: dict[str, Any] = Depends(current_user),
    connection: Connection[Any] = Depends(get_db_connection),
) -> None:
    updated = connection.execute(
        """
        UPDATE file_deletion_notices
        SET dismissed_at = NOW()
        WHERE notice_id = %s AND user_id = %s AND dismissed_at IS NULL
        RETURNING notice_id
        """,
        (notice_id, user["user_id"]),
    ).fetchone()
    if updated is None:
        raise HTTPException(status_code=404, detail="Notificación no encontrada")


@router.delete("/users/me")
def delete_user(
    body: DeleteAccountIn,
    user: dict[str, Any] = Depends(current_user),
    connection: Connection[Any] = Depends(get_db_connection),
) -> dict[str, str]:
    user_id = user["user_id"]
    record = connection.execute(
        "SELECT password_hash FROM credentials WHERE user_id = %s",
        (user_id,),
    ).fetchone()
    if record is None or not password_hash.verify(body.password, record["password_hash"]):
        raise HTTPException(status_code=401, detail="Contraseña incorrecta")
    with connection.transaction():
        connection.execute("UPDATE users SET is_active = FALSE WHERE user_id = %s", (user_id,))
        revoke_refresh_tokens(connection, user_id)
    return {"message": "Usuario desactivado correctamente"}


@router.post("/users/me/role-request", status_code=201)
def create_role_request(
    body: RoleRequestIn,
    user: dict[str, Any] = Depends(current_user),
    connection: Connection[Any] = Depends(get_db_connection),
) -> dict[str, str]:
    pending = connection.execute(
        "SELECT 1 FROM role_requests WHERE user_id = %s AND status = 'PENDING'",
        (user["user_id"],),
    ).fetchone()
    if pending:
        raise HTTPException(status_code=400, detail="Ya tienes una solicitud de cambio de rol pendiente.")

    connection.execute(
        "INSERT INTO role_requests (user_id, req_role, justification) VALUES (%s, %s, %s)",
        (user["user_id"], body.req_role, body.justification),
    )
    return {"message": "Solicitud enviada con éxito"}