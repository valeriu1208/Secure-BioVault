"""Cliente HTTP para el backend FastAPI de SecureBioVault.

Todos los endpoints están centralizados aquí: si el backend usa rutas
distintas, solo hay que tocar este fichero.
"""
import os
from dataclasses import dataclass

import requests

BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000").rstrip("/")
TIMEOUT = 15  # segundos
# En local con certificado autofirmado: VERIFY_TLS=false (nunca en producción)
VERIFY_TLS = os.getenv("VERIFY_TLS", "true").lower() != "false"


class ApiError(Exception):
    """Error devuelto por el backend (o de conexión)."""

    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


@dataclass
class Session:
    """Token JWT de la sesión actual."""

    access_token: str

    @property
    def headers(self) -> dict:
        return {"Authorization": f"Bearer {self.access_token}"}


def _request(method: str, path: str, session: Session | None = None, **kwargs):
    headers = kwargs.pop("headers", {})
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
        try:
            detail = resp.json().get("detail", resp.text)
        except ValueError:
            detail = resp.text
        raise ApiError(str(detail), resp.status_code)
    return resp


# ---------- Autenticación ----------
def register(username: str, email: str, password: str) -> dict:
    resp = _request(
        "POST",
        "/auth/register",
        json={"username": username, "email": email, "password": password},
    )
    return resp.json()


def login(username: str, password: str) -> Session:
    # OAuth2 Password flow: el formulario va en x-www-form-urlencoded
    resp = _request(
        "POST", "/auth/token", data={"username": username, "password": password}
    )
    return Session(access_token=resp.json()["access_token"])


def me(session: Session) -> dict:
    return _request("GET", "/users/me", session).json()


# ---------- Ficheros cifrados (bio-datos / PDFs) ----------
def list_files(session: Session) -> list[dict]:
    return _request("GET", "/files", session).json()


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


def delete_file(session: Session, file_id: str) -> None:
    _request("DELETE", f"/files/{file_id}", session)
