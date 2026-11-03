import streamlit as st
import api_client as api
from util import logout, handle_api_error

def professional_view(embedded: bool = False, key_prefix: str = "prof"):
    """
    Combined view for both DOCTOR and RESEARCHER roles.
    Adapts the UI text and icons dynamically based on the session role.
    """
    session = st.session_state.get("session")
    role = st.session_state.get("role", "DOCTOR").upper()
    username = st.session_state.get("username", "")

    # Role-based UI configuration
    is_researcher = (role == "RESEARCHER")
    ui_config = {
        "icon": "🔬" if is_researcher else "👨‍⚕️",
        "title": "Investigador/a" if is_researcher else "Dr/a.",
        "subtitle": "Centro de Investigación" if is_researcher else "🩺 Especialista",
        "panel_name": "Panel de Investigación" if is_researcher else "Panel Médico Principal",
        "welcome_msg": "resumen de investigación" if is_researcher else "resumen clínico"
    }

    option_menu = "👥 Directorio de Pacientes"  # Default for embedded view

    # --- SIDEBAR NAVIGATION ---
    if not embedded:
        with st.sidebar:
            st.markdown(f"### {ui_config['icon']} {ui_config['title']} {username}")
            st.caption(ui_config['subtitle'])
            
            st.divider()
            
            st.write("### 📌 Navegación")
            option_menu = st.radio(
                "Selecciona una vista:",
                ["🏠 Panel Principal", "👥 Directorio de Pacientes"],
                label_visibility="collapsed"
            )        
            st.divider()
            
            if st.button("🚪 Cerrar sesión", use_container_width=True, type="primary"):
                logout()

    # --- MAIN CONTENT ROUTING ---
    if option_menu == "🏠 Panel Principal":
        st.title(f"{ui_config['icon']} {ui_config['panel_name']}")
        st.markdown(f"Bienvenido/a, **{ui_config['title']} {username}**. Aquí tienes tu {ui_config['welcome_msg']} de hoy.")

        pacientes_con_acceso = 0
        total_documentos = 0
        
        with st.spinner("Calculando accesos y documentos seguros..."):
            try:
                todos_los_pacientes = api.search_patients(session, "")
                for p in todos_los_pacientes:
                    try:
                        archivos = api.list_patient_files(session, str(p["user_id"]))
                        pacientes_con_acceso += 1
                        total_documentos += len(archivos)
                    except api.ApiError:
                        pass # Silently skip patients if access to their file list fails
            except Exception:
                pass 

        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Pacientes Accesibles", f"{pacientes_con_acceso}", "Consentimiento verificado")
        with col2:
            st.metric("Total de Documentos", f"{total_documentos}", "Archivos autorizados", delta_color="normal")
        with col3:
            st.metric("Alertas Críticas", "0", "Estable", delta_color="off")
            
        st.divider()

        st.subheader("📋 Información del Sistema")
        with st.container(border=True):
            st.markdown("✅ **Seguridad OPA Activa:** Las métricas mostradas reflejan únicamente los datos a los que tienes acceso criptográfico autorizado en este momento.")
            st.markdown("🔹 **Privacidad garantizada:** Si un paciente revoca su consentimiento, su perfil y documentos desaparecerán automáticamente de este panel.")

    elif option_menu == "👥 Directorio de Pacientes":
        st.title("👥 Directorio de Pacientes")
        st.caption("Consulta de expedientes de pacientes con consentimiento activo")

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
            st.info("No se encontraron pacientes.")
            return

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
                    st.info("Este paciente no tiene documentos registrados.")
                else:
                    for f in files:
                        fid = str(f.get("id"))
                        has_access = f.get("has_access", False)
                        
                        with st.container(border=True):
                            col_info, col_action = st.columns([5, 3])
                            
                            if has_access:
                                col_info.markdown(f"📄 **{f.get('filename', fid)}**")
                            else:
                                col_info.markdown(f"🔒 **{f.get('filename', fid)}** *(Sin acceso)*")
                                
                            if f.get("description"):
                                col_info.caption(f["description"])
                            
                            # If professional has access, allow download
                            if has_access:
                                if col_action.button("Preparar descarga", key=f"{key_prefix}_prep_{fid}"):
                                    try:
                                        st.session_state[f"{key_prefix}_doc_data_{fid}"] = api.download_file(session, fid)
                                    except api.ApiError as exc:
                                        handle_api_error(exc)
                                
                                if f"{key_prefix}_doc_data_{fid}" in st.session_state:
                                    col_action.download_button(
                                        "⬇️ Descargar",
                                        data=st.session_state[f"{key_prefix}_doc_data_{fid}"],
                                        file_name=f.get("filename", f"{fid}.pdf"),
                                        mime="application/pdf",
                                        key=f"{key_prefix}_dl_{fid}",
                                    )
                            # If no access, show request form
                            else:
                                with col_action.expander("📩 Solicitar acceso"):
                                    reason = st.text_input(
                                        "Motivo de la solicitud:",
                                        key=f"{key_prefix}_req_reason_{fid}",
                                    )
                                    if st.button("Enviar Solicitud", key=f"{key_prefix}_req_btn_{fid}"):
                                        try:
                                            api.request_file_access(session, fid, reason)
                                            st.success("Solicitud enviada correctamente al paciente.")
                                        except api.ApiError as exc:
                                            handle_api_error(exc)
                            
            except api.ApiError as exc:
                handle_api_error(exc)
