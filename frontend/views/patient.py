import streamlit as st
import api_client as api
from util import logout, handle_api_error

def vault_page(embedded: bool = False, key_prefix: str = "vault"):
    session = st.session_state["session"]
    option_menu = "🔐 Mi Bóveda"  # Default option for embedded view
    if not embedded:
        with st.sidebar:
            st.markdown(f"### 👤 {st.session_state.get('username', '')}")
            st.caption("🛡️ Paciente Registrado")
            
            st.divider()
            
            st.write("### 📌 Navegación")
            option_menu = st.radio(
                "Navegación Paciente",
                ["🔐 Mi Bóveda", "⚕️ Compartir Datos", "⚙️ Configuración"],
                label_visibility="collapsed"
            )    
            st.divider()
            if st.button("🚪 Cerrar sesión", use_container_width=True, type="primary"):
                logout()
    if option_menu == "🔐 Mi Bóveda":
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

    # Share specific files  
    elif option_menu == "⚕️ Compartir Datos":
        st.title("⚕️ Gestión de Permisos y Accesos")
        
        tab_requests, tab_grant = st.tabs(["📥 Solicitudes Pendientes", "➕ Conceder Acceso Directo"])

        # Accept/Deny requests from doctors/researchers
        with tab_requests:
            st.subheader("Solicitudes de acceso recibidas")
            try:
                pending_requests = api.get_incoming_access_requests(session)
                if not pending_requests:
                    st.info("No tienes solicitudes de acceso pendientes.")
                else:
                    for req in pending_requests:
                        req_id = str(req["id"])
                        with st.container(border=True):
                            col_info, col_actions = st.columns([3, 2])
                            with col_info:
                                st.markdown(f"**Solicitante:** {req['requester_name']}")
                                st.markdown(f"**Fichero:** {req['filename']}")
                                if req.get("reason"):
                                    st.caption(f"Motivo: {req['reason']}")

                            with col_actions:
                                c1, c2 = st.columns(2)
                                if c1.button("✅ Aprobar", key=f"app_{req_id}", type="primary"):
                                    api.respond_access_request(session, req_id, "APPROVED")
                                    st.success("Acceso concedido.")
                                    st.rerun()
                                if c2.button("❌ Denegar", key=f"den_{req_id}"):
                                    api.respond_access_request(session, req_id, "DENIED")
                                    st.warning("Solicitud denegada.")
                                    st.rerun()
            except api.ApiError as exc:
                handle_api_error(exc)

        # Grant access directly without needing a previous request
        with tab_grant:
            st.subheader("Otorgar acceso voluntario a un Profesional")
            try:
                user_files = api.list_files(session)
                professionals = api.list_professionals(session)

                if not user_files:
                    st.info("Sube al menos un fichero a tu bóveda para poder otorgar permisos.")
                elif not professionals:
                    st.info("No hay médicos o investigadores registrados en el sistema.")
                else:
                    selected_file = st.selectbox(
                        "Selecciona el fichero:",
                        options=user_files,
                        format_func=lambda f: f.get("filename") or str(f.get("id") or f.get("file_id")),
                        key=f"{key_prefix}_grant_file_select",
                    )

                    selected_prof = st.selectbox(
                        "Selecciona el Profesional (Médico / Investigador):",
                        options=professionals,
                        format_func=lambda p: f"[{p['role_name']}] {p['username']}",
                        key=f"{key_prefix}_grant_prof_select",
                    )

                    if st.button("🔑 Otorgar Permiso Directo", type="primary", key=f"{key_prefix}_btn_grant"):
                        fid = str(selected_file.get("file_id") or selected_file.get("id"))
                        target_id = str(selected_prof["user_id"])
                        api.grant_file_access(session, file_id=fid, target_user_id=target_id)
                        st.success(f"Permiso concedido a {selected_prof['username']}.")
            except api.ApiError as exc:
                handle_api_error(exc)

    elif option_menu == "⚙️ Configuración":
        st.title("⚙️ Configuración de Cuenta")

        st.subheader("🎓 Cuenta Profesional")
        with st.expander("Solicitar cuenta de Médico o Investigador"):
            with st.form("role_req_form"):
                st.write("Si eres personal sanitario o de investigación, verifica tu identidad:")
                new_role = st.selectbox("Rol solicitado", ["DOCTOR", "RESEARCHER"])
                justification = st.text_area("Justificación (Nº Colegiado, Centro, Proyecto...)")

                if st.form_submit_button("Enviar solicitud", type="primary"):
                    if not justification:
                        st.error("Debes incluir una justificación.")
                    else:
                        try:
                            api.request_role_change(session, new_role, justification)
                            st.success("Solicitud enviada. Un administrador la revisará en breve.")
                        except api.ApiError as exc:
                            handle_api_error(exc)

        st.divider()
        
        st.subheader("Zona de Peligro")
        with st.expander("🚨 Eliminar mi cuenta"):
            st.warning("⚠️ **Advertencia:** Tu cuenta será desactivada y programada para eliminación permanente en 30 días. Perderás el acceso inmediatamente.")
            
            password_confirm = st.text_input(
                "Por seguridad, ingresa tu contraseña actual para confirmar:", 
                type="password",
                key="del_pass_confirm"
            )
            
            confirm = st.checkbox("Entiendo que esta acción desactivará mi cuenta.")

            if st.button("Desactivar mi cuenta", type="primary", disabled=not confirm or not password_confirm):
                try:
                    api.delete_my_account(session, password_confirm)
                    st.success("Tu cuenta ha sido desactivada. Cerrando sesión...")
                    logout()
                except api.ApiError as exc:
                    handle_api_error(exc)
