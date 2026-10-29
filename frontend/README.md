# SecureBioVault · Frontend (Streamlit)

## Instalación

```bash
cd frontend
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Ejecución

```bash
# Backend FastAPI debe estar corriendo (por defecto en http://localhost:8000)
streamlit run app.py
```

Se abre en <http://localhost:8501>. Para apuntar a otro backend:

```bash
BACKEND_URL=https://mi-backend:8000 streamlit run app.py
```

## Estructura

| Fichero | Función |
|---|---|
| `app.py` | Interfaz: login, registro, listado/subida/descarga/borrado de PDFs |
| `api_client.py` | Cliente HTTP del backend (aquí se ajustan los endpoints) |
| `.streamlit/config.toml` | Tema (azul UPC) y ajustes del servidor |
| `requirements.txt` | Dependencias (`streamlit>=1.54.0` por CVE-2026-33682) |

## Endpoints que espera el backend

| Método | Ruta | Uso |
|---|---|---|
| POST | `/auth/register` | JSON `{username, email, password}` |
| POST | `/auth/token` | OAuth2 password form → `{access_token}` (JWT) |
| GET | `/.well-known/jwks.json` | Public Ed25519 signing key for JWT verification |
| GET | `/users/me` | Datos del usuario |
| GET | `/files` | Lista `[{id, filename, description, created_at}]` |
| POST | `/files` | Multipart `file` + `description` |
| GET | `/files/{id}` | Descarga el PDF descifrado |
| DELETE | `/files/{id}` | Borra el documento |

Si tu FastAPI usa otras rutas, edita solo `api_client.py`.

## Notas de seguridad

- El JWT se guarda únicamente en `st.session_state` (nunca en disco ni en la URL).
- Tamaño máximo de PDF: 25 MB y comprobación de la firma `%PDF-` antes de subir.
- Para HTTPS entre navegador y Streamlit, ponlo detrás de un proxy inverso (nginx/Caddy) con TLS.
- Revisa el código con Bandit (SAST) y `pip-audit` (SCA) como en la slide de SecDevOps.
