"""SecureBioVault - Frontend Streamlit.
 
Ejecutar:  streamlit run app.py
"""
import re
 
import streamlit as st
 
import api_client as api
 
st.set_page_config(
    page_title="SecureBioVault",
    page_icon="🔐",
    layout="centered",
)
 
MAX_PDF_MB = 25
PASSWORD_RULES = "Mínimo 12 caracteres, con mayúscula, minúscula, número y símbolo."
 
 
# ---------- Utilidades ----------
def strong_password(pw: str) -> bool:
    return (
        len(pw) >= 12
        and re.search(r"[a-z]", pw)
        and re.search(r"[A-Z]", pw)
        and re.search(r"\d", pw)
        and re.search(r"[^\w\s]", pw)
    )
 
 
def is_pdf(data: bytes) -> bool:
    return data[:5] == b"%PDF-"
 
 
def logout():
    # El token vive solo en st.session_state (memoria del servidor de Streamlit)
    for key in ("session", "username"):
        st.session_state.pop(key, None)
    st.rerun()
 
 
def handle_api_error(exc: api.ApiError):
    if exc.status == 401:
        st.warning("La sesión ha caducado. Vuelve a iniciar sesión.")
        logout()
    elif exc.status == 403:
        st.error("No tienes permisos para realizar esta acción (política OPA).")
    else:
        st.error(str(exc))
 
 
# ---------- Pantalla de acceso ----------
def auth_page():
    st.title("🔐 SecureBioVault")
    st.caption("Almacenamiento cifrado de bio-datos · AES-256-GCM")
 
    tab_login, tab_register = st.tabs(["Iniciar sesión", "Registrarse"])
 
    with tab_login:
        with st.form("login_form"):
            username = st.text_input("Usuario")
            password = st.text_input("Contraseña", type="password")
            submitted = st.form_submit_button("Entrar", type="primary")
        if submitted:
            if not username or not password:
                st.error("Introduce usuario y contraseña.")
            else:
                try:
                    st.session_state["session"] = api.login(username, password)
                    st.session_state["username"] = username
                    st.rerun()
                except api.ApiError as exc:
                    st.error(
                        "Credenciales incorrectas."
                        if exc.status in (400, 401)
                        else str(exc)
                    )
 
    with tab_register:
        with st.form("register_form"):
            new_user = st.text_input("Usuario", key="reg_user")
            email = st.text_input("Email")
            pw1 = st.text_input("Contraseña", type="password", key="reg_pw1")
            pw2 = st.text_input("Repite la contraseña", type="password", key="reg_pw2")
            st.caption(PASSWORD_RULES)
            submitted = st.form_submit_button("Crear cuenta", type="primary")
        if submitted:
            if not (new_user and email and pw1):
                st.error("Rellena todos los campos.")
            elif pw1 != pw2:
                st.error("Las contraseñas no coinciden.")
            elif not strong_password(pw1):
                st.error(PASSWORD_RULES)
            else:
                try:
                    api.register(new_user, email, pw1)
                    st.success("Cuenta creada. Ya puedes iniciar sesión.")
                except api.ApiError as exc:
                    st.error(str(exc))
 
 
# ---------- Pantalla principal ----------
def vault_page():
    session = st.session_state["session"]
 
    with st.sidebar:
        st.markdown(f"### 👤 {st.session_state.get('username', '')}")
        if st.button("Cerrar sesión", use_container_width=True):
            logout()
        st.divider()
        st.caption(f"Backend: `{api.BACKEND_URL}`")
 
    st.title("🔐 Mi bóveda")
 
    tab_files, tab_upload = st.tabs(["📄 Mis documentos", "⬆️ Subir PDF"])
 
    # --- Listado ---
    with tab_files:
        try:
            files = api.list_files(session)
        except api.ApiError as exc:
            handle_api_error(exc)
            files = []
 
        # Buscador: filtra por nombre o descripción (sin distinguir mayúsculas)
        col_search, col_sort = st.columns([3, 2])
        query = col_search.text_input(
            "Buscar",
            placeholder="🔍 Buscar por nombre o descripción…",
            label_visibility="collapsed",
        ).strip().lower()
        sort_by = col_sort.selectbox(
            "Ordenar",
            ["Más recientes", "Más antiguos", "Nombre (A-Z)"],
            label_visibility="collapsed",
        )
 
        if query:
            files = [
                f
                for f in files
                if query in str(f.get("filename", "")).lower()
                or query in str(f.get("description", "")).lower()
            ]
        if sort_by == "Nombre (A-Z)":
            files = sorted(files, key=lambda f: str(f.get("filename", "")).lower())
        else:
            files = sorted(
                files,
                key=lambda f: str(f.get("created_at", "")),
                reverse=(sort_by == "Más recientes"),
            )
 
        if not files:
            st.info(
                f"Ningún documento coincide con «{query}»."
                if query
                else "Todavía no has subido ningún documento."
            )
        else:
            st.caption(f"{len(files)} documento(s)")
        for f in files:
            fid = str(f.get("id"))
            with st.container(border=True):
                col_info, col_dl, col_del = st.columns([5, 2, 1])
                col_info.markdown(f"**{f.get('filename', fid)}**")
                if f.get("description"):
                    col_info.caption(f["description"])
                if f.get("created_at"):
                    col_info.caption(f"Subido: {f['created_at']}")
 
                # El PDF se descifra en el backend solo al pulsar "Descargar"
                if col_dl.button("Preparar descarga", key=f"prep_{fid}"):
                    try:
                        st.session_state[f"data_{fid}"] = api.download_file(session, fid)
                    except api.ApiError as exc:
                        handle_api_error(exc)
                if f"data_{fid}" in st.session_state:
                    col_dl.download_button(
                        "⬇️ Descargar",
                        data=st.session_state[f"data_{fid}"],
                        file_name=f.get("filename", f"{fid}.pdf"),
                        mime="application/pdf",
                        key=f"dl_{fid}",
                    )
 
                if col_del.button("🗑️", key=f"del_{fid}", help="Eliminar"):
                    try:
                        api.delete_file(session, fid)
                        st.session_state.pop(f"data_{fid}", None)
                        st.rerun()
                    except api.ApiError as exc:
                        handle_api_error(exc)
 
    # --- Subida ---
    with tab_upload:
        with st.form("upload_form", clear_on_submit=True):
            uploaded = st.file_uploader("Selecciona un PDF", type=["pdf"])
            description = st.text_input("Descripción (opcional)", max_chars=200)
            submitted = st.form_submit_button("Cifrar y subir", type="primary")
        if submitted:
            if uploaded is None:
                st.error("Selecciona un fichero.")
            else:
                data = uploaded.getvalue()
                if len(data) > MAX_PDF_MB * 1024 * 1024:
                    st.error(f"El fichero supera {MAX_PDF_MB} MB.")
                elif not is_pdf(data):
                    st.error("El fichero no parece un PDF válido.")
                else:
                    try:
                        api.upload_file(session, uploaded.name, data, description)
                        st.success("Documento cifrado y almacenado correctamente.")
                    except api.ApiError as exc:
                        handle_api_error(exc)
 
 
# ---------- Router ----------
if "session" in st.session_state:
    vault_page()
else:
    auth_page()