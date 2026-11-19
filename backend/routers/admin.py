import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from psycopg import Connection

from audit import record_audit_log, verify_audit_chain
from database import get_db_connection
from dependencies import current_user
from opa import authorize_file_access
from schemas import ResolveRequestIn, RoleUpdateIn, UpdateUserActiveStatusIn
from security import decrypt_field, revoke_refresh_tokens

router = APIRouter(tags=["Admin"])


@router.get("/admin/users")
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
        u["email"] = decrypt_field(u["email"], request.app.state.field_encryption_key)
    return users_db


@router.patch("/admin/users/{target_user_id}/role")
def update_user_role(
    request: Request,
    target_user_id: uuid.UUID,
    body: RoleUpdateIn,
    user: dict[str, Any] = Depends(current_user),
    connection: Connection[Any] = Depends(get_db_connection),
) -> dict[str, str]:
    authorize_file_access(
        request,
        user,
        "change_role",
        target_id=target_user_id,
        connection=connection,
        denial_status_code=403,
    )

    role_record = connection.execute(
        "SELECT role_id FROM roles WHERE role_name = %s",
        (body.new_role,),
    ).fetchone()

    if not role_record:
        raise HTTPException(status_code=400, detail="Rol inválido")

    updated = connection.execute(
        "UPDATE users SET role_id = %s WHERE user_id = %s RETURNING user_id",
        (role_record["role_id"], target_user_id),
    ).fetchone()

    if not updated:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    return {"message": f"Rol actualizado a {body.new_role}"}


@router.get("/admin/files")
def list_all_files_metadata(
    user: dict[str, Any] = Depends(current_user),
    connection: Connection[Any] = Depends(get_db_connection),
) -> list[dict[str, Any]]:
    if user["role_name"] != "ADMIN":
        raise HTTPException(status_code=403, detail="Requiere privilegios de administrador")

    return connection.execute(
        """
        SELECT f.file_id, f.original_filename, f.description, f.file_type,
               f.created_at, u.user_id AS owner_id, u.username AS owner_username
        FROM files AS f
        JOIN users AS u ON u.user_id = f.owner_id
        ORDER BY f.created_at DESC
        """
    ).fetchall()


@router.delete("/admin/users/{target_user_id}")
def delete_user_by_admin(
    target_user_id: uuid.UUID,
    user: dict[str, Any] = Depends(current_user),
    connection: Connection[Any] = Depends(get_db_connection),
) -> dict[str, str]:
    if user["role_name"] != "ADMIN":
        raise HTTPException(status_code=403, detail="Requiere privilegios de administrador")

    with connection.transaction():
        target = connection.execute(
            "SELECT user_id FROM users WHERE user_id = %s", (target_user_id,)
        ).fetchone()
        if not target:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        connection.execute("UPDATE users SET is_active = FALSE WHERE user_id = %s", (target_user_id,))
        revoke_refresh_tokens(connection, target_user_id)

    return {"message": "Usuario desactivado correctamente por el administrador"}


@router.patch("/admin/users/{target_user_id}/active")
def update_user_active_status(
    target_user_id: uuid.UUID,
    body: UpdateUserActiveStatusIn,
    user: dict[str, Any] = Depends(current_user),
    connection: Connection[Any] = Depends(get_db_connection),
) -> dict[str, str]:
    if user["role_name"] != "ADMIN":
        raise HTTPException(status_code=403, detail="Requiere privilegios de administrador")

    with connection.transaction():
        target = connection.execute(
            "SELECT user_id FROM users WHERE user_id = %s", (target_user_id,)
        ).fetchone()
        if not target:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        connection.execute(
            "UPDATE users SET is_active = %s WHERE user_id = %s", (body.is_active, target_user_id)
        )
        if not body.is_active:
            revoke_refresh_tokens(connection, target_user_id)

    return {"message": "Estado de cuenta actualizado correctamente por el administrador"}


@router.get("/admin/role-requests")
def list_role_requests(
    request: Request,
    user: dict[str, Any] = Depends(current_user),
    connection: Connection[Any] = Depends(get_db_connection),
) -> list[dict[str, Any]]:
    if user["role_name"] != "ADMIN":
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

    for r in requests_db:
        r["email"] = decrypt_field(r["email"], request.app.state.field_encryption_key)
    return requests_db


@router.patch("/admin/role-requests/{request_id}")
def resolve_role_request(
    request: Request,
    request_id: uuid.UUID,
    body: ResolveRequestIn,
    user: dict[str, Any] = Depends(current_user),
    connection: Connection[Any] = Depends(get_db_connection),
) -> dict[str, str]:
    if user["role_name"] != "ADMIN":
        raise HTTPException(status_code=403, detail="Se requieren privilegios de administrador")

    with connection.transaction():
        req = connection.execute(
            "SELECT user_id, req_role FROM role_requests WHERE req_id = %s AND status = 'PENDING'",
            (request_id,),
        ).fetchone()

        if not req:
            raise HTTPException(status_code=404, detail="Solicitud no encontrada o ya resuelta")

        connection.execute(
            "UPDATE role_requests SET status = %s WHERE req_id = %s", (body.status, request_id)
        )
        if body.status == "APPROVED":
            role_record = connection.execute(
                "SELECT role_id FROM roles WHERE role_name = %s", (req["req_role"],)
            ).fetchone()
            connection.execute(
                "UPDATE users SET role_id = %s WHERE user_id = %s",
                (role_record["role_id"], req["user_id"]),
            )

    record_audit_log(
        request,
        user_id=user["user_id"],
        action="ROLE_REQUEST_RESOLVE",
        resource_id=req["user_id"],
        decision=body.status,
        reason=f"Requested role {req['req_role']}",
    )
    return {"message": f"Solicitud {body.status.lower()}"}


@router.get("/admin/audit-logs")
def list_audit_logs(
    limit: int = 100,
    user: dict[str, Any] = Depends(current_user),
    connection: Connection[Any] = Depends(get_db_connection),
) -> list[dict[str, Any]]:
    if user["role_name"] != "ADMIN":
        raise HTTPException(status_code=403, detail="Se requieren privilegios de administrador")

    safe_limit = max(1, min(limit, 500))
    return connection.execute(
        """
        SELECT l.log_id, l.user_id, u.username, l.action, l.resource_id,
               l.decision, l.reason, l.ip_address, l.timestamp,
               l.prev_hash, l.current_hash
        FROM access_logs AS l
        LEFT JOIN users AS u ON u.user_id = l.user_id
        ORDER BY l.log_id DESC
        LIMIT %s
        """,
        (safe_limit,),
    ).fetchall()


@router.get("/admin/audit-logs/verify")
def verify_audit_logs(
    request: Request,
    user: dict[str, Any] = Depends(current_user),
    connection: Connection[Any] = Depends(get_db_connection),
) -> dict[str, Any]:
    if user["role_name"] != "ADMIN":
        raise HTTPException(status_code=403, detail="Se requieren privilegios de administrador")

    rows = connection.execute(
        """
        SELECT log_id, user_id, action, resource_id, decision,
               reason, ip_address, timestamp, prev_hash, current_hash
        FROM access_logs
        ORDER BY log_id ASC
        """
    ).fetchall()
    return verify_audit_chain(rows, request.app.state.audit_hmac_key)