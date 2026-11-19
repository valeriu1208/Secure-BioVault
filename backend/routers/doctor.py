import logging
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from psycopg import Connection

from database import get_db_connection
from dependencies import current_user
from opa import authorize_file_access
from security import decrypt_field, get_blind_index

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Doctor"])


@router.get("/doctor/patients")
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
    if user["role_name"] != "ADMIN":
        sql += " AND u.is_active = TRUE"
    if query:
        email_hash = get_blind_index(query)
        sql += " AND (u.username ILIKE %s OR u.email_hash = %s)"
        params.extend([f"%{query}%", email_hash])

    patients = connection.execute(sql, params).fetchall()
    for p in patients:
        p["email"] = decrypt_field(p["email"], request.app.state.field_encryption_key)
    return patients


@router.get("/doctor/patients/{patient_id}/files")
def list_patient_files_for_doctor(
    patient_id: uuid.UUID,
    request: Request,
    user: dict[str, Any] = Depends(current_user),
    connection: Connection[Any] = Depends(get_db_connection),
) -> list[dict[str, Any]]:
    files = connection.execute(
        """
        SELECT file_id AS id, original_filename AS filename, description, created_at
        FROM files
        WHERE owner_id = %s
        ORDER BY created_at DESC
        """,
        (patient_id,),
    ).fetchall()

    result = []
    for f in files:
        file_dict = dict(f)
        if user.get("role_name") == "ADMIN":
            file_dict["has_access"] = False
        else:
            try:
                authorize_file_access(request, user, "read", f["id"], connection, audit=False)
                file_dict["has_access"] = True
            except HTTPException:
                file_dict["has_access"] = False
            except Exception as exc:
                logger.error("Error al autorizar archivo %s: %s", f["id"], exc)
                file_dict["has_access"] = False
        result.append(file_dict)

    return result