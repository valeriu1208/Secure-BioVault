import streamlit as st
import api_client as api
from util import logout, handle_api_error


def doctor_view(embedded: bool = False, key_prefix: str = "doc"):
    session = st.session_state["session"]
    role = st.session_state.get("role", "DOCTOR")

    is_res = (role == "RESEARCHER")
    icono = "🔬" if is_res else "👨‍⚕️"
    titulo_profesional = "Investigador/a" if is_res else "Dr/a."
    subtitulo = "Centro de Investigación" if is_res else "🩺 Especialista"
    titulo_panel = "Panel de Investigación" if is_res else "Panel Médico Principal"

    option_menu = "👥 Directorio de Pacientes"  # Default option for embedded view
    # --- SIDEBAR NAVIGATION ---
    if not embedded:
        with st.sidebar:
            st.markdown(f"### {icono} {titulo_profesional} {st.session_state.get('username', '')}")
            st.caption(subtitulo)
            
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
        st.title("👨‍⚕️ Panel Médico Principal")
        st.markdown(f"Bienvenido/a, **Dr/a. {st.session_state.get('username', '')}**. Aquí tienes tu resumen clínico de hoy.")
        
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
                        pass
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

        col_actividad, col_acciones = st.columns([2, 1])

        with col_actividad:
            st.subheader("📋 Información del Sistema")
            with st.container(border=True):
                st.markdown("✅ **Seguridad OPA Activa:** Las métricas mostradas reflejan únicamente los datos a los que tienes acceso criptográfico autorizado en este momento.")
                st.markdown("🔹 **Privacidad garantizada:** Si un paciente revoca su consentimiento, su perfil y documentos desaparecerán automáticamente de este panel.")

        with col_acciones:
            st.subheader("⚡ Acciones Rápidas")
            with st.container(border=True):
                if st.button("🔍 Buscar en el Directorio", use_container_width=True):
                    st.info("💡 Consejo: Selecciona 'Directorio de Pacientes' en el menú lateral.")
                    


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
                    st.info("Este paciente no tiene documentos o el consentimiento ha expirado.")
                else:
                    for f in files:
                        fid = str(f.get("id"))
                        with st.container(border=True):
                            col_info, col_dl = st.columns([5, 2])
                            col_info.markdown(f"**{f.get('filename', fid)}**")
                            if f.get("description"):
                                col_info.caption(f["description"])
                            
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
    
