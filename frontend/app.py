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
    session = st.session_state.get("session")
    if session:
        try:
            api.logout(session)
        except api.ApiError as exc:
            st.warning(f"Error al cerrar sesión: {exc}")
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
                    token = api.login(username, password)
                    st.session_state["session"] = token
                    st.session_state["username"] = username
                    profile = api.me(token)
                    st.session_state["role"] = profile.get("role", "PATIENT")

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
def vault_page(embedded: bool = False, key_prefix: str = "vault"):
    session = st.session_state["session"]

    if not embedded:
        with st.sidebar:
            st.markdown(f"### 👤 {st.session_state.get('username', '')}")
            if st.button("Cerrar sesión", use_container_width=True, key=f"{key_prefix}_logout"):
                logout()

    st.title("🔐 Bóveda de Documentos")

    # File upload section
    with st.expander("📤 Subir nuevo documento cifrado"):
        uploaded_file = st.file_uploader(
            "Seleccionar archivo PDF", 
            type=["pdf"], 
            key=f"{key_prefix}_file_uploader"
        )
        description = st.text_input(
            "Descripción (opcional)", 
            key=f"{key_prefix}_file_desc"
        )
        if st.button("Subir y cifrar", key=f"{key_prefix}_btn_upload"):
            if uploaded_file:
                try:
                    content = uploaded_file.read()
                    api.upload_file(session, uploaded_file.name, content, description)
                    st.success("Archivo subido y cifrado correctamente.")
                    st.rerun()
                except api.ApiError as exc:
                    handle_api_error(exc)
            else:
                st.warning("Selecciona un archivo primero.")

    # File list section
    st.subheader("📋 Tus documentos")
    try:
        files = api.list_files(session)
        if not files:
            st.info("No tienes documentos guardados.")
        else:
            for f in files:
                fid = str(f.get("file_id") or f.get("id"))
                with st.container(border=True):
                    col1, col2, col3 = st.columns([4, 2, 2])
                    col1.markdown(f"**{f.get('filename', fid)}**")
                    if f.get("description"):
                        col1.caption(f["description"])

                    # Prepare / Download button
                    if col2.button("Preparar", key=f"{key_prefix}_prep_{fid}"):
                        try:
                            st.session_state[f"file_data_{fid}"] = api.download_file(session, fid)
                        except api.ApiError as exc:
                            handle_api_error(exc)

                    if f"file_data_{fid}" in st.session_state:
                        col2.download_button(
                            "⬇️ Descargar",
                            data=st.session_state[f"file_data_{fid}"],
                            file_name=f.get("original_filename", f"{fid}.pdf"),
                            mime="application/pdf",
                            key=f"{key_prefix}_dl_{fid}",
                        )

                    # Delete button
                    if col3.button("Eliminar", key=f"{key_prefix}_del_{fid}", type="secondary"):
                        try:
                            api.delete_file(session, fid)
                            st.success("Eliminado")
                            st.rerun()
                        except api.ApiError as exc:
                            handle_api_error(exc)

    except api.ApiError as exc:
        handle_api_error(exc)

# ---------- Vista de Médico ----------
def doctor_view(key_prefix: str = "doc"):
    session = st.session_state["session"]
    st.title("👨‍⚕️ Panel Médico")
    st.caption("Consulta de expedientes de pacientes con consentimiento activo")

    # Added key_prefix to search input
    search_query = st.text_input(
        "🔍 Buscar paciente", 
        placeholder="Nombre de usuario o email...",
        key=f"{key_prefix}_search_input"
    )
    
    try:
        patients = api.search_patients(session, search_query)
    except api.ApiError as exc:
        handle_api_error(exc)
        patients = []

    if not patients:
        st.info("No se encontraron pacientes con consentimiento activo.")
        return

    # Added key_prefix to selectbox
    selected_patient = st.selectbox(
        "Seleccionar paciente:",
        options=patients,
        format_func=lambda p: f"{p['username']} ({p['email']})",
        key=f"{key_prefix}_select_patient"
    )

    if selected_patient:
        patient_id = selected_patient["user_id"]
        st.subheader(f"📄 Expedientes de {selected_patient['username']}")
        
        try:
            files = api.list_patient_files(session, patient_id)
            if not files:
                st.info("Este paciente no tiene documentos o el consentimiento ha expirado.")
            else:
                for f in files:
                    fid = str(f.get("id"))
                    with st.container(border=True):
                        col_info, col_dl = st.columns([5, 2])
                        col_info.markdown(f"**{f.get('filename', fid)}**")
                        if f.get("description"):
                            col_info.caption(f["description"])
                        
                        # Added key_prefix to buttons
                        if col_dl.button("Preparar descarga", key=f"{key_prefix}_prep_{fid}"):
                            try:
                                st.session_state[f"doc_data_{fid}"] = api.download_file(session, fid)
                            except api.ApiError as exc:
                                handle_api_error(exc)
                        
                        if f"doc_data_{fid}" in st.session_state:
                            col_dl.download_button(
                                "⬇️ Descargar",
                                data=st.session_state[f"doc_data_{fid}"],
                                file_name=f.get("filename", f"{fid}.pdf"),
                                mime="application/pdf",
                                key=f"{key_prefix}_dl_{fid}",
                            )
        except api.ApiError as exc:
            handle_api_error(exc)



# ---------- Vista de Admin (con Pestañas para todo) ----------
def admin_page():
    session = st.session_state["session"]

    with st.sidebar:
        st.markdown(f"### 🛡️ {st.session_state.get('username', '')} (Admin)")
        if st.button("Cerrar sesión", use_container_width=True):
            logout()
        st.divider()
        st.caption(f"Backend: `{api.BACKEND_URL}`")

    # Tabs allowing Admin to switch between User Management and pre-viewing other roles
    tab_users, tab_doctor_view, tab_patient_view = st.tabs([
        "👥 Gestión de Usuarios", 
        "👨‍⚕️ Vista Médico", 
        "🔐 Vista Bóveda Paciente"
    ])

    # Tab 1: User Management
    with tab_users:
        st.title("🛡️ Gestión de Roles y Usuarios")
        try:
            users = api.list_all_users(session)
            for u in users:
                with st.container(border=True):
                    col1, col2, col3 = st.columns([3, 2, 2])
                    col1.markdown(f"**{u['username']}** ({u['email']})")
                    col2.write(f"Rol: `{u['role_name']}`")
                    
                    roles = ["PATIENT", "DOCTOR", "ADMIN", "RESEARCHER"]
                    current_idx = roles.index(u['role_name']) if u['role_name'] in roles else 0
                    
                    new_role = col3.selectbox(
                        "Cambiar rol", 
                        options=roles, 
                        index=current_idx,
                        key=f"role_{u['user_id']}"
                    )
                    
                    if new_role != u['role_name']:
                        if col3.button("Guardar", key=f"btn_{u['user_id']}"):
                            try:
                                api.update_user_role(session, u['user_id'], new_role)
                                st.success(f"Rol cambiado a {new_role}")
                                st.rerun()
                            except api.ApiError as exc:
                                handle_api_error(exc)
        except api.ApiError as exc:
            handle_api_error(exc)

    # Tab 2: Embedded Doctor View
    with tab_doctor_view:
        doctor_view(key_prefix="admin_tab_doc")  # Use a different key prefix to avoid conflicts

    # Tab 3: Embedded Patient Vault View
    with tab_patient_view:
        vault_page(embedded=True, key_prefix="admin_tab_patient")  # Use a different key prefix to avoid conflicts


# ---------- Router ----------
if "session" in st.session_state:
    role = st.session_state.get("role", "PATIENT")
    
    if role == "ADMIN":
        admin_page()
    elif role == "DOCTOR":
        with st.sidebar:
            st.markdown(f"### 👨‍⚕️ {st.session_state.get('username', '')}")
            if st.button("Cerrar sesión", use_container_width=True):
                logout()
        doctor_view()
    else:
        vault_page()
else:
    auth_page()
