import binascii
import logging
import uuid
from typing import Any

from cryptography.exceptions import InvalidTag
from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import Response
from psycopg import Connection

from audit import record_audit_log
from config import MAX_FILE_SIZE
from database import get_db_connection
from dependencies import current_user
from opa import authorize_file_access
from schemas import (
    FileAccessRequestIn,
    GrantFileAccessIn,
    GrantFileRoleAccessIn,
    RequestStatusUpdate,
)
from security import decrypt_file, encrypt_file

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Files"])


@router.get("/files")
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


@router.post("/files", status_code=201)
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


@router.get("/files/{file_id}")
def download(
    request: Request,
    file_id: uuid.UUID,
    user: dict[str, Any] = Depends(current_user),
    connection: Connection[Any] = Depends(get_db_connection),
) -> Response:
    if user["role_name"] == "ADMIN":
        record_audit_log(
            request,
            user_id=user["user_id"],
            action="FILE_READ",
            resource_id=file_id,
            decision="DENIED",
            reason="Admins are not allowed to download medical files",
        )
        raise HTTPException(
            status_code=403,
            detail="Admins no pueden descargar fichero médicos",
        )

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
        file_id,
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
        record_audit_log(
            request,
            user_id=user["user_id"],
            action="FILE_READ",
            resource_id=file_id,
            decision="DENIED",
            reason="Stored file integrity check failed",
        )
        raise HTTPException(status_code=500, detail="Stored file integrity check failed") from exc
    return Response(content, media_type="application/pdf")


@router.post("/files/{file_id}/access-requests")
def create_file_access_request(
    file_id: uuid.UUID,
    payload: FileAccessRequestIn,
    user: dict[str, Any] = Depends(current_user),
    connection: Connection[Any] = Depends(get_db_connection),
) -> dict[str, str]:
    if user["role_name"] not in ("DOCTOR", "RESEARCHER"):
        raise HTTPException(status_code=403, detail="Solo médicos e investigadores pueden solicitar acceso")

    file_record = connection.execute(
        "SELECT owner_id FROM files WHERE file_id = %s", (file_id,)
    ).fetchone()
    if not file_record:
        raise HTTPException(status_code=404, detail="Fichero no encontrado")
    if file_record["owner_id"] == user["user_id"]:
        raise HTTPException(status_code=400, detail="No puedes solicitar acceso a tu propio fichero")

    connection.execute(
        """
        INSERT INTO file_access_requests (file_id, requester_id, owner_id, status, reason)
        VALUES (%s, %s, %s, 'PENDING', %s)
        """,
        (file_id, user["user_id"], file_record["owner_id"], payload.reason),
    )
    return {"message": "Solicitud de acceso enviada al propietario"}


@router.get("/access-requests/incoming")
def get_incoming_access_requests(
    user: dict[str, Any] = Depends(current_user),
    connection: Connection[Any] = Depends(get_db_connection),
):
    return connection.execute(
        """
        SELECT ar.id, ar.file_id, ar.requester_id, ar.reason, ar.created_at,
               u.username AS requester_name, u.email AS requester_email,
               f.original_filename AS filename
        FROM file_access_requests ar
        JOIN users u ON ar.requester_id = u.user_id
        JOIN files f ON ar.file_id = f.file_id
        WHERE ar.owner_id = %s AND ar.status = 'PENDING'
        ORDER BY ar.created_at DESC
        """,
        (user["user_id"],),
    ).fetchall()


@router.patch("/access-requests/{request_id}")
def respond_access_request(
    request_id: uuid.UUID,
    payload: RequestStatusUpdate,
    user: dict[str, Any] = Depends(current_user),
    connection: Connection[Any] = Depends(get_db_connection),
) -> dict[str, str]:
    req = connection.execute(
        "SELECT file_id, requester_id FROM file_access_requests WHERE id = %s AND owner_id = %s",
        (request_id, user["user_id"]),
    ).fetchone()

    if not req:
        raise HTTPException(status_code=404, detail="Solicitud no encontrada")

    if payload.status not in ["APPROVED", "DENIED"]:
        raise HTTPException(status_code=400, detail="Estado no válido")

    connection.execute(
        "UPDATE file_access_requests SET status = %s WHERE id = %s",
        (payload.status, request_id),
    )

    if payload.status == "APPROVED":
        connection.execute(
            """
            INSERT INTO file_permissions (file_id, user_id)
            VALUES (%s, %s)
            ON CONFLICT DO NOTHING
            """,
            (req["file_id"], req["requester_id"]),
        )

    return {"message": f"Solicitud {payload.status.lower()}"}


@router.post("/files/{file_id}/permissions")
def grant_file_access(
    request: Request,
    file_id: uuid.UUID,
    payload: GrantFileAccessIn,
    user: dict[str, Any] = Depends(current_user),
    connection: Connection[Any] = Depends(get_db_connection),
) -> dict[str, str]:
    file_record = connection.execute(
        "SELECT owner_id FROM files WHERE file_id = %s", (file_id,)
    ).fetchone()
    if not file_record:
        raise HTTPException(status_code=404, detail="Fichero no encontrado")

    target_user = connection.execute(
        """
        SELECT u.user_id
        FROM users AS u
        JOIN roles AS r ON r.role_id = u.role_id
        WHERE u.user_id = %s
          AND u.is_active = TRUE
          AND r.role_name IN ('DOCTOR', 'RESEARCHER')
        """,
        (payload.target_user_id,),
    ).fetchone()
    if target_user is None:
        raise HTTPException(status_code=404, detail="Profesional activo no encontrado")

    authorize_file_access(
        request,
        user,
        "write",
        file_record["owner_id"],
        connection,
    )

    connection.execute(
        """
        INSERT INTO file_permissions (file_id, user_id)
        VALUES (%s, %s)
        ON CONFLICT DO NOTHING
        """,
        (file_id, payload.target_user_id),
    )
    record_audit_log(
        request,
        user_id=user["user_id"],
        action="PERMISSION_GRANT",
        resource_id=file_id,
        decision="ALLOWED",
        reason=f"Granted to user {payload.target_user_id}",
    )
    return {"message": "Permiso concedido exitosamente"}


@router.get("/files/{file_id}/permissions")
def list_file_permissions(
    file_id: uuid.UUID,
    user: dict[str, Any] = Depends(current_user),
    connection: Connection[Any] = Depends(get_db_connection),
) -> list[dict[str, Any]]:
    file_record = connection.execute(
        "SELECT owner_id FROM files WHERE file_id = %s",
        (file_id,),
    ).fetchone()
    if file_record is None or file_record["owner_id"] != user["user_id"]:
        raise HTTPException(status_code=404, detail="Documento no encontrado")

    return connection.execute(
        """
        SELECT fp.user_id, u.username, r.role_name, fp.created_at
        FROM file_permissions AS fp
        JOIN users AS u ON u.user_id = fp.user_id
        JOIN roles AS r ON r.role_id = u.role_id
        WHERE fp.file_id = %s
        ORDER BY u.username
        """,
        (file_id,),
    ).fetchall()


@router.delete("/files/{file_id}/permissions/{target_user_id}", status_code=204)
def revoke_file_access(
    request: Request,
    file_id: uuid.UUID,
    target_user_id: uuid.UUID,
    user: dict[str, Any] = Depends(current_user),
    connection: Connection[Any] = Depends(get_db_connection),
) -> None:
    file_record = connection.execute(
        "SELECT owner_id FROM files WHERE file_id = %s",
        (file_id,),
    ).fetchone()
    if file_record is None or file_record["owner_id"] != user["user_id"]:
        raise HTTPException(status_code=404, detail="Documento no encontrado")

    deleted = connection.execute(
        """
        DELETE FROM file_permissions
        WHERE file_id = %s AND user_id = %s
        RETURNING permission_id
        """,
        (file_id, target_user_id),
    ).fetchone()
    if deleted is None:
        raise HTTPException(status_code=404, detail="Permiso no encontrado o ya revocado")

    record_audit_log(
        request,
        user_id=user["user_id"],
        action="PERMISSION_REVOKE",
        resource_id=file_id,
        decision="ALLOWED",
        reason=f"Revoked from user {target_user_id}",
    )


@router.post("/files/{file_id}/role-permissions", status_code=201)
def grant_file_role_access(
    request: Request,
    file_id: uuid.UUID,
    payload: GrantFileRoleAccessIn,
    user: dict[str, Any] = Depends(current_user),
    connection: Connection[Any] = Depends(get_db_connection),
) -> dict[str, str]:
    file_record = connection.execute(
        "SELECT owner_id FROM files WHERE file_id = %s", (file_id,)
    ).fetchone()
    if not file_record:
        raise HTTPException(status_code=404, detail="Fichero no encontrado")

    authorize_file_access(
        request,
        user,
        "write",
        file_record["owner_id"],
        connection,
    )

    connection.execute(
        """
        INSERT INTO file_role_permissions (file_id, role_name)
        VALUES (%s, %s)
        ON CONFLICT DO NOTHING
        """,
        (file_id, payload.role_name),
    )
    record_audit_log(
        request,
        user_id=user["user_id"],
        action="ROLE_PERMISSION_GRANT",
        resource_id=file_id,
        decision="ALLOWED",
        reason=f"Granted to role {payload.role_name}",
    )
    return {"message": f"Permiso concedido al rol {payload.role_name}"}


@router.get("/files/{file_id}/role-permissions")
def list_file_role_permissions(
    request: Request,
    file_id: uuid.UUID,
    user: dict[str, Any] = Depends(current_user),
    connection: Connection[Any] = Depends(get_db_connection),
) -> list[dict[str, Any]]:
    file_record = connection.execute(
        "SELECT owner_id FROM files WHERE file_id = %s",
        (file_id,),
    ).fetchone()
    if file_record is None:
        raise HTTPException(status_code=404, detail="Documento no encontrado")

    authorize_file_access(
        request,
        user,
        "write",
        file_record["owner_id"],
        connection,
        denial_status_code=404,
    )

    return connection.execute(
        """
        SELECT role_name, created_at
        FROM file_role_permissions
        WHERE file_id = %s
        ORDER BY role_name
        """,
        (file_id,),
    ).fetchall()


@router.delete("/files/{file_id}/role-permissions/{role_name}", status_code=204)
def revoke_file_role_access(
    request: Request,
    file_id: uuid.UUID,
    role_name: str,
    user: dict[str, Any] = Depends(current_user),
    connection: Connection[Any] = Depends(get_db_connection),
) -> None:
    role_name = role_name.upper()
    if role_name not in ("DOCTOR", "RESEARCHER"):
        raise HTTPException(status_code=400, detail="Rol no válido")

    file_record = connection.execute(
        "SELECT owner_id FROM files WHERE file_id = %s",
        (file_id,),
    ).fetchone()
    if file_record is None:
        raise HTTPException(status_code=404, detail="Documento no encontrado")

    authorize_file_access(
        request,
        user,
        "write",
        file_record["owner_id"],
        connection,
        denial_status_code=404,
    )

    deleted = connection.execute(
        """
        DELETE FROM file_role_permissions
        WHERE file_id = %s AND role_name = %s
        RETURNING permission_id
        """,
        (file_id, role_name),
    ).fetchone()
    if deleted is None:
        raise HTTPException(status_code=404, detail="Permiso de rol no encontrado o ya revocado")

    record_audit_log(
        request,
        user_id=user["user_id"],
        action="ROLE_PERMISSION_REVOKE",
        resource_id=file_id,
        decision="ALLOWED",
        reason=f"Revoked from role {role_name}",
    )


@router.delete("/files/{file_id}", status_code=204)
def delete_file(
    request: Request,
    file_id: uuid.UUID,
    reason: str | None = None,
    user: dict[str, Any] = Depends(current_user),
    connection: Connection[Any] = Depends(get_db_connection),
) -> None:
    if user["role_name"] == "ADMIN" and (not reason or len(reason.strip()) < 10):
        record_audit_log(
            request,
            user_id=user["user_id"],
            action="ADMIN_FILE_DELETE",
            resource_id=file_id,
            decision="DENIED",
            reason="Not enough justification provided",
        )
        raise HTTPException(
            status_code=400,
            detail="El administrador debe justificar la eliminacion del fichero con al menos 10 caracteres",
        )

    record = connection.execute(
        "SELECT owner_id, original_filename FROM files WHERE file_id = %s",
        (file_id,),
    ).fetchone()
    if record is None:
        raise HTTPException(status_code=404, detail="Documento no encontrado")

    authorize_file_access(
        request,
        user,
        "delete",
        file_id,
        connection,
        denial_status_code=404,
    )

    deleted = connection.execute(
        "DELETE FROM files WHERE file_id = %s AND owner_id = %s RETURNING file_id",
        (file_id, record["owner_id"]),
    ).fetchone()
    if deleted is None:
        raise HTTPException(status_code=404, detail="Documento no encontrado")

    if user["role_name"] == "ADMIN":
        clean_reason = reason.strip()
        connection.execute(
            """
            INSERT INTO file_deletion_notices (
                user_id, file_id, original_filename, deleted_by_id, deleted_by_username, reason
            )
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (
                record["owner_id"],
                file_id,
                record["original_filename"],
                user["user_id"],
                user["username"],
                clean_reason,
            ),
        )
        logger.warning(
            "AUDIT_ADMIN_DELETE | admin=%s (%s) | file_id=%s | filename=%s | owner_id=%s | reason=%s",
            user["username"],
            user["user_id"],
            file_id,
            record["original_filename"],
            record["owner_id"],
            clean_reason,
        )
        record_audit_log(
            request,
            user_id=user["user_id"],
            action="ADMIN_FILE_DELETE",
            resource_id=file_id,
            decision="ALLOWED",
            reason=f"Moderation delete ({record['original_filename']}): {clean_reason}",
        )