"""Backend FALSO para probar el frontend sin el FastAPI real.

- Todo se guarda en memoria (se pierde al parar el servidor).
- NO cifra, NO usa OPA, NO usa JWT real: solo imita las rutas.
- No usar nunca fuera de desarrollo local.

Ejecutar:  python -m uvicorn mock_backend:app --port 8000
"""
import secrets
import uuid
from datetime import datetime

from fastapi import Depends, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import Response
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel

app = FastAPI(title="SecureBioVault MOCK")
oauth2 = OAuth2PasswordBearer(tokenUrl="/auth/token")

USERS: dict[str, dict] = {}   # username -> {email, password}
TOKENS: dict[str, str] = {}   # token -> username
FILES: dict[str, dict] = {}   # file_id -> {owner, filename, description, created_at, data}

@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "ok"}

class RegisterIn(BaseModel):
    username: str
    email: str
    password: str


def current_user(token: str = Depends(oauth2)) -> str:
    user = TOKENS.get(token)
    if not user:
        raise HTTPException(401, "Token inválido o caducado")
    return user


@app.post("/auth/register", status_code=201)
def register(body: RegisterIn):
    if body.username in USERS:
        raise HTTPException(400, "El usuario ya existe")
    USERS[body.username] = {"email": body.email, "password": body.password}
    return {"username": body.username, "email": body.email}


@app.post("/auth/token")
def token(form: OAuth2PasswordRequestForm = Depends()):
    user = USERS.get(form.username)
    if not user or user["password"] != form.password:
        raise HTTPException(401, "Credenciales incorrectas")
    tok = secrets.token_hex(24)
    TOKENS[tok] = form.username
    return {"access_token": tok, "token_type": "bearer"}


@app.get("/users/me")
def me(user: str = Depends(current_user)):
    return {"username": user, "email": USERS[user]["email"]}


@app.get("/files")
def list_files(user: str = Depends(current_user)):
    return [
        {k: v for k, v in {"id": fid, **f}.items() if k not in ("data", "owner")}
        for fid, f in FILES.items()
        if f["owner"] == user
    ]


@app.post("/files", status_code=201)
async def upload(
    file: UploadFile = File(...),
    description: str = Form(""),
    user: str = Depends(current_user),
):
    fid = str(uuid.uuid4())
    FILES[fid] = {
        "owner": user,
        "filename": file.filename,
        "description": description,
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "data": await file.read(),
    }
    return {"id": fid, "filename": file.filename}


def _own_file(fid: str, user: str) -> dict:
    f = FILES.get(fid)
    if not f:
        raise HTTPException(404, "Documento no encontrado")
    if f["owner"] != user:
        raise HTTPException(403, "Acceso denegado")
    return f


@app.get("/files/{fid}")
def download(fid: str, user: str = Depends(current_user)):
    f = _own_file(fid, user)
    return Response(f["data"], media_type="application/pdf")


@app.delete("/files/{fid}", status_code=204)
def delete(fid: str, user: str = Depends(current_user)):
    _own_file(fid, user)
    del FILES[fid]
