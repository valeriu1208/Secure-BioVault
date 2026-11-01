import re
 
import streamlit as st
import api_client as api
from util import logout, handle_api_error
from views.doctor import doctor_view
from views.patient import vault_page


def admin_page():
    session = st.session_state["session"]

    # --- SIDEBAR NAVIGATION ---
    with st.sidebar:
        st.markdown(f"### 🛡️ {st.session_state.get('username', '')}")
        st.caption("⚙️ Administrador del Sistema")
        st.divider()
        
        st.write("### 📌 Módulos")
        option_menu = st.radio(
            "Navegación Admin",
            ["👥 Gestión de Usuarios", "👨‍⚕️ Simular Vista Médico", "🔐 Simular Vista Bóveda"],
            label_visibility="collapsed"
        )
        
        st.divider()
        
        if hasattr(api, 'BACKEND_URL'):
            st.caption(f"Backend: `{api.BACKEND_URL}`")
            
        st.divider()
        
        if st.button("🚪 Cerrar sesión", use_container_width=True, type="primary"):
            logout()

    # --- MAIN CONTENT ROUTING ---
    if option_menu == "👥 Gestión de Usuarios":
        st.title("🛡️ Gestión de Roles y Usuarios")

        # ROLE CHANGE REQs
        try:
            reqs = api.get_role_requests(session)
            if reqs:
                with st.expander(f"🔔 Solicitudes de ascenso pendientes ({len(reqs)})", expanded=True):
                    for r in reqs:
                        st.markdown(f"**{r['username']}** ({r['email']}) solicita ser **{r['req_role']}**")
                        st.caption(f"Justificación: {r['justification']}")
                        col_ok, col_ko, _ = st.columns([2, 2, 6])
                        if col_ok.button("✅ Aprobar", key=f"app_{r['req_id']}", type="primary"):
                            try:
                                api.resolve_role_request(session, str(r['req_id']), "APPROVED")
                                st.success("Ascenso aprobado.")
                                st.rerun()
                            except api.ApiError as exc:
                                handle_api_error(exc)
                        if col_ko.button("❌ Rechazar", key=f"rej_{r['req_id']}"):
                            try:
                                api.resolve_role_request(session, str(r['req_id']), "REJECTED")
                                st.info("Solicitud rechazada.")
                                st.rerun()
                            except api.ApiError as exc:
                                handle_api_error(exc)

                st.divider()
        except api.ApiError as exc:
            pass

        # Users list for manual change
        try:
            users = api.list_all_users(session)
            for u in users:
                with st.container(border=True):

                    col1, col2, col3, col4, col5 = st.columns([3, 2, 2, 2, 1])
                    
                    col1.markdown(f"**{u['username']}** ({u['email']})")
                    col1.caption(f"ID: {u['user_id']}")
                    
                    col2.write(f"Rol: `{u['role_name']}`")
                    col2.write(f"Estado: {'🟢 Activo' if u['is_active'] else '🔴 Inactivo'}")
                    

                    roles = ["PATIENT", "DOCTOR", "ADMIN", "RESEARCHER"]
                    current_idx = roles.index(u['role_name']) if u['role_name'] in roles else 0
                    
                    new_role = col3.selectbox(
                        "Cambiar rol", 
                        options=roles, 
                        index=current_idx,
                        key=f"role_{u['user_id']}",
                        label_visibility="collapsed"
                    )
                    
                    if new_role != u['role_name']:
                        if col3.button("Guardar Rol", key=f"btn_role_{u['user_id']}"):
                            try:
                                api.update_user_role(session, u['user_id'], new_role)
                                st.success(f"Rol cambiado a {new_role}")
                                st.rerun()
                            except api.ApiError as exc:
                                handle_api_error(exc)

                    active_status = col4.checkbox(
                        "Cuenta Activa", 
                        value=u['is_active'], 
                        key=f"active_{u['user_id']}"
                    )
                    
                    if active_status != u['is_active']:
                        if col4.button("Guardar Estado", key=f"btn_active_{u['user_id']}"):
                            try:
                                api.update_user_active_status(session, u['user_id'], active_status)
                                st.success(f"Estado actualizado.")
                                st.rerun()
                            except api.ApiError as exc:
                                handle_api_error(exc)
                    
                    # Columna 5: Botón para eliminar (Soft Delete)
                    is_current_user = u['username'] == st.session_state.get('username')
                    
                    if not is_current_user:
                        if u['is_active']:
                            if col5.button("🗑️", key=f"btn_del_{u['user_id']}", help="Desactivar usuario (Soft Delete)", type="primary"):
                                try:
                                    api.delete_user(session, str(u['user_id']))
                                    st.success("Usuario desactivado.")
                                    st.rerun()
                                except api.ApiError as exc:
                                    handle_api_error(exc)
                    else:
                        col5.markdown("<div style='text-align: center; color: gray; margin-top: 8px;'><i>(Tú)</i></div>", unsafe_allow_html=True)

        except api.ApiError as exc:
            handle_api_error(exc)

    elif option_menu == "👨‍⚕️ Simular Vista Médico":
        doctor_view(embedded=True, key_prefix="admin_tab_doc")  

    elif option_menu == "🔐 Simular Vista Bóveda":
        vault_page(embedded=True, key_prefix="admin_tab_patient")  
