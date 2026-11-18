"""Cliente HTTP para el backend FastAPI de SecureBioVault.

Todos los endpoints están centralizados aquí: si el backend usa rutas
distintas, solo hay que tocar este fichero.
"""
import os
from dataclasses import dataclass
from urllib.parse import quote

import requests

BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000").rstrip("/")
TIMEOUT = 15  # segundos
# En local con certificado autofirmado: VERIFY_TLS=false (nunca en producción)
VERIFY_TLS = os.getenv("VERIFY_TLS", "true").lower() != "false"


class ApiError(Exception):
    """Error devuelto por el backend (o de conexión)."""

    def __init__(self, message: str, status: int | None = None, payload: dict | None = None):
        super().__init__(message)
        self.status = status
        self.payload = payload or {}

@dataclass
class Session:
    """Tokens de la sesión actual.

    access_token: JWT firmado (Ed25519) de vida corta; el backend lo valida sin BD.
    refresh_token: token opaco de un solo uso para obtener un nuevo par de tokens.
    """

    access_token: str
    refresh_token: str | None = None

    @property
    def headers(self) -> dict:
        return {"Authorization": f"Bearer {self.access_token}"}


def _request(method: str, path: str, session: Session | None = None, **kwargs):
    try:
        return _send(method, path, session, **kwargs)
    except ApiError as exc:
        # Access token caducado: rotamos con el refresh token y reintentamos una vez.
        if exc.status != 401 or session is None or not session.refresh_token:
            raise
        try:
            _refresh(session)
        except ApiError:
            raise exc from None  # refresh rechazado: la sesión ha caducado (401)
        return _send(method, path, session, **kwargs)


def _refresh(session: Session) -> None:
    """Obtiene un nuevo par de tokens y actualiza la sesión in situ."""
    refresh_token, session.refresh_token = session.refresh_token, None
    resp = _send(
        "POST", "/auth/token", data={"grant_type": "refresh_token", "refresh_token": refresh_token}
    )
    body = resp.json()
    session.access_token = body["access_token"]
    session.refresh_token = body.get("refresh_token")


def _send(method: str, path: str, session: Session | None = None, **kwargs):
    headers = dict(kwargs.pop("headers", {}))
    if session:
        headers.update(session.headers)
    try:
        resp = requests.request(
            method,
            f"{BACKEND_URL}{path}",
            headers=headers,
            timeout=TIMEOUT,
            verify=VERIFY_TLS,
            **kwargs,
        )
    except requests.RequestException as exc:
        raise ApiError(f"No se pudo conectar con el backend: {exc}") from exc

    if not resp.ok:
        payload: dict = {}
        try:
            body = resp.json()
            if isinstance(body, dict):
                payload = body["detail"] if isinstance(body.get("detail"), dict) else body
                # OAuth 2.0 errors (RFC 6749 §5.2) use error / error_description.
                detail = (
                    payload.get("message")
                    or payload.get("detail")
                    or payload.get("error_description")
                    or payload.get("code")
                    or resp.text
                )
            else:
                detail = str(body)
        except ValueError:
            detail = resp.text
        raise ApiError(str(detail), resp.status_code, payload=payload)
    return resp


# ---------- Autenticación ----------
def register(username: str, email: str, password: str) -> dict:
    resp = _request(
        "POST",
        "/auth/register",
        json={"username": username, "email": email, "password": password},
    )
    return resp.json()


def login(username: str, password: str, totp_code: str | None = None) -> Session:
    # OAuth2 Password flow: el formulario va en x-www-form-urlencoded
    form_data = {"grant_type": "password", "username": username, "password": password}
    if totp_code:
        form_data["totp_code"] = totp_code.strip()

    resp = _request("POST", "/auth/token", data=form_data)
    body = resp.json()
    return Session(access_token=body["access_token"], refresh_token=body.get("refresh_token"))

def logout(session: Session) -> None:
    # RFC 7009: revoca el refresh token; el access token caduca solo (vida corta).
    if session.refresh_token:
        _send("POST", "/auth/revoke", data={"token": session.refresh_token, "token_type_hint": "refresh_token"})
    session.refresh_token = None

def me(session: Session) -> dict:
    return _request("GET", "/users/me", session).json()

def list_all_users(session: Session) -> list[dict]:
    return _request("GET", "/admin/users", session).json()
# ---------- Ficheros cifrados (bio-datos / PDFs) ----------
def list_files(session: Session) -> list[dict]:
    return _request("GET", "/files", session).json()

def list_all_files_metadata(session) -> list[dict]:
    return _request("GET", "/admin/files", session).json()

def update_user_role(session: Session, target_user_id: str, new_role: str) -> dict:
    return _request(
        "PATCH",
        f"/admin/users/{target_user_id}/role",
        session,
        json={"new_role": new_role},
    ).json()

def upload_file(session: Session, name: str, content: bytes, description: str = ""):
    return _request(
        "POST",
        "/files",
        session,
        files={"file": (name, content, "application/pdf")},
        data={"description": description},
    ).json()


def download_file(session: Session, file_id: str) -> bytes:
    return _request("GET", f"/files/{file_id}", session).content


def delete_file(session: Session, file_id: str, reason: str | None = None) -> None:
    path = f"/files/{file_id}"
    if reason:
        path = f"{path}?reason={quote(reason)}"
    _request("DELETE", path, session)

def get_deletion_notices(session: Session) -> list[dict]:
    return _request("GET", "/users/me/deletion-notices", session).json()


def dismiss_deletion_notice(session: Session, notice_id: str) -> None:
    _request("POST", f"/users/me/deletion-notices/{notice_id}/dismiss", session)

def search_patients(session: Session, query: str = "") -> list[dict]:
    return _request("GET", f"/doctor/patients?query={query}", session).json()

def list_patient_files(session: Session, patient_id: str) -> list[dict]:
    return _request("GET", f"/doctor/patients/{patient_id}/files", session).json()

def request_file_access(session: Session, file_id: str, reason: str = "") -> dict:
    return _request("POST", f"/files/{file_id}/access-requests", session, json={"file_id": file_id, "reason": reason}).json()

def get_incoming_access_requests(session: Session) -> list[dict]:
    return _request("GET", f"/access-requests/incoming", session).json()

def respond_access_request(session: Session, request_id: str, status: str) -> dict:
    return _request("PATCH", f"/access-requests/{request_id}", session, json={"status": status}).json()

def grant_file_access(session: Session, file_id: str, target_user_id: str) -> dict:
    return _request("POST", f"/files/{file_id}/permissions", session, json={"target_user_id": target_user_id}).json()

def list_file_permissions(session: Session, file_id: str) -> list[dict]:
    return _request("GET", f"/files/{file_id}/permissions", session).json()

def revoke_file_access(session: Session, file_id: str, target_user_id: str) -> None:
    _request("DELETE", f"/files/{file_id}/permissions/{target_user_id}", session)

def grant_file_role_access(session: Session, file_id: str, role_name: str) -> dict:
    return _request("POST", f"/files/{file_id}/role-permissions", session, json = {"role_name": role_name}).json()

def list_file_role_permissions(session: Session, file_id: str) -> list[dict]:
    return _request("GET", f"/files/{file_id}/role-permissions", session).json()

def revoke_file_role_access(session: Session, file_id: str, role_name: str) -> None:
    _request("DELETE", f"/files/{file_id}/role-permissions/{role_name}", session)

def list_professionals(session: Session) -> list[dict]:
    return _request("GET", "/users/professionals", session).json()

def delete_my_account(session: Session, password: str) -> None:
    return _request("DELETE", "/users/me", session, json={"password": password}).json()

def delete_user(session: Session, target_user_id: str) -> None:
    return _request("DELETE", f"/admin/users/{target_user_id}", session).json()

def update_user_active_status(session: Session, target_user_id: str, is_active: bool) -> dict:
    return _request(
        "PATCH",
        f"/admin/users/{target_user_id}/active",
        session,
        json={"is_active": is_active}
    ).json()

def request_role_change(session: Session, req_role: str, justification: str) -> dict:
    return _request("POST", "/users/me/role-request", session, json={"req_role": req_role, "justification": justification}).json()

def get_role_requests(session: Session) -> list[dict]:
    return _request("GET", "/admin/role-requests", session).json()

def resolve_role_request(session: Session, req_id: str, status: str) -> dict:
    return _request("PATCH", f"/admin/role-requests/{req_id}", session, json={"status": status}).json()
