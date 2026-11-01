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
    # Reemplaza el bloque de "Configuración" en views/patient.py con esto:

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
