import json
import logging
import uuid
from typing import Any
from urllib.error import URLError
from urllib.request import Request as URLRequest, urlopen

from fastapi import HTTPException, Request
from psycopg import Connection

from audit import record_audit_log
from config import OPA_DECISION_PATH

logger = logging.getLogger(__name__)


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


def authorize_file_access(
    request: Request,
    user: dict[str, Any],
    action: str,
    target_id: uuid.UUID,
    connection: Connection[Any],
    *,
    denial_status_code: int = 403,
    audit: bool = True,
) -> None:
    allowed_users = []
    allowed_roles = []

    file_record = connection.execute(
        "SELECT file_id, owner_id FROM files WHERE file_id = %s", (target_id,)
    ).fetchone()

    if file_record:
        file_id = str(file_record["file_id"])
        owner_id = str(file_record["owner_id"])

        file_perms = connection.execute(
            "SELECT user_id FROM file_permissions WHERE file_id = %s", (target_id,)
        ).fetchall()
        for fp in file_perms:
            allowed_users.append(str(fp["user_id"]))

        role_perms = connection.execute(
            "SELECT role_name FROM file_role_permissions WHERE file_id = %s", (target_id,)
        ).fetchall()
        for rp in role_perms:
            allowed_roles.append(str(rp["role_name"]))
    else:
        file_id = None
        owner_id = str(target_id)

        file_perms = connection.execute(
            """
            SELECT DISTINCT fp.user_id
            FROM file_permissions fp
            JOIN files f ON f.file_id = fp.file_id
            WHERE f.owner_id = %s
            """,
            (target_id,),
        ).fetchall()
        for fp in file_perms:
            allowed_users.append(str(fp["user_id"]))

        role_perms = connection.execute(
            """
            SELECT DISTINCT frp.role_name
            FROM file_role_permissions frp
            JOIN files f ON f.file_id = frp.file_id
            WHERE f.owner_id = %s
            """,
            (target_id,),
        ).fetchall()
        for rp in role_perms:
            allowed_roles.append(str(rp["role_name"]))

    consents = connection.execute(
        """
        SELECT granted_to_user_id, granted_to_role
        FROM consents
        WHERE patient_id = %s AND is_granted = TRUE AND expires_at > CURRENT_TIMESTAMP
        """,
        (owner_id,),
    ).fetchall()

    for c in consents:
        if c["granted_to_user_id"]:
            allowed_users.append(str(c["granted_to_user_id"]))
        if c["granted_to_role"]:
            allowed_roles.append(c["granted_to_role"])

    allowed_users = list(set(allowed_users))
    allowed_roles = list(set(allowed_roles))

    input_document = {
        "input": {
            "subject": {
                "id": str(user["user_id"]),
                "role": user["role_name"],
            },
            "action": action,
            "resource": {
                "type": "file",
                "file_id": file_id,
                "owner_id": owner_id,
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
    if audit:
        audit_action = "ROLE_CHANGE" if action == "change_role" else f"FILE_{action.upper()}"
        record_audit_log(
            request,
            user_id=user["user_id"],
            action=audit_action,
            resource_id=target_id,
            decision="ALLOWED" if allow else "DENIED",
            reason=f"OPA decision for role = {user['role_name']}",
        )
    if not allow:
        raise HTTPException(
            status_code=denial_status_code,
            detail="No autorizado para acceder a este documento",
        )