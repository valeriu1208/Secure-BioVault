import re
 
import streamlit as st
import api_client as api
from util import logout, handle_api_error
from views.doctor import professional_view as doctor_view
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
            [
                "👥 Gestión de Usuarios",
                "📁 Control de Ficheros",
                "📜 Logs de Auditoría",
                "👨‍⚕️ Simular Vista Médico",
                "🔐 Simular Vista Bóveda"
            ],
            label_visibility = "collapsed"
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

    elif option_menu == "📁 Control de Ficheros":
        st.title("Gestión de Ficheros")

        try:
            files = api.list_all_files_metadata(session)
            if not files:
                st.caption("No hay ficheros registrados en el sistema.")
            else:
                serach = st.text_input(
                    "Filtrar por nombre de archivo o usuario",
                ).strip().lower()

                filtered = [
                    f for f in files
                    if not serach
                    or serach in f["original_filename"].lower()
                    or serach in f["owner_username"].lower()
                ]

                st.caption(f"Mostrando {len(filtered)} de {len(files)} ficheros")

                for f in filtered:
                    file_id_str = str(f["file_id"])
                    with st.container(border=True):
                        c1, c2, c3, c4 = st.columns([4, 2.6, 2, 1.4])
                        c1.markdown(f"**📄 {f['original_filename']}**")
                        c1.caption(f"Descripción: {f['description'] or 'Sin descripción'}")
                        c1.caption(f"ID: `{file_id_str}`")

                        c2.markdown(f"👤 **{f['owner_username']}**")
                        c2.caption("Paciente")

                        c3.write(f"Tipo: `{f['file_type']}`")
                        c3.caption(f"Subido: {str(f['created_at'])[:19]}")

                        with c4.popover("🗑️", help="Eliminar fichero por moderación"):
                            st.markdown("**Confirmar eliminación**")
                            reason = st.text_input(
                                "Justificación (mín. 10 caracteres)",
                                key=f"reason_{file_id_str}",
                                placeholder="Ej. Reporte de contenido no clínico",
                            )
                            if st.button(
                                "Eliminar definitivamente",
                                key=f"confirm_del_{file_id_str}",
                                type="primary",
                                use_container_width=True,
                            ):
                                if len(reason.strip()) < 10:
                                    st.warning("Introduce una justificación de al menos 10 caracteres.")
                                else:
                                    try:
                                        api.delete_file(session, file_id_str, reason=reason.strip())
                                        st.success("Fichero eliminado y registrado en auditoría.")
                                        st.rerun()
                                    except api.ApiError as exc:
                                        handle_api_error(exc)
        except api.ApiError as exc:
            handle_api_error(exc)

    elif option_menu == "📜 Logs de Auditoría":
        st.title("📜 Auditoría Inmutable (HMAC-SHA256 Hash Chaining)")
        st.caption(
            "Cada registro encadena su HMAC-SHA256 con el registro anterior (prev_hash -> current_hash) "
            "y la tabla está protegida como append-only."
        )

        col_btn, col_limit = st.columns([2, 1])
        with col_limit:
            limit = st.selectbox("Últimos registros", [50, 100, 250, 500], index = 1, key = "audit_limit")
        with col_btn:
            if st.button("🔍 Re-verificar integridad de la cadena", type = "primary"):
                st.rerun()

        try:
            verification = api.verify_audit_logs(session)
            if verification["valid"]:
                st.success(
                    f"✅ Integridad verificada: {verification['total_logs']} registros encadenados sin alteraciones."
                )
            else:
                st.error(
                    f"🚨 ¡MANIPULACIÓN DETECTADA en log_id #{verification['broken_at_log_id']}! "
                    f"{verification['reason']}"
                )

            broken_id = None if verification["valid"] else verification.get("broken_at_log_id")
            if broken_id is not None:
                st.html(
                    """
                    <style>
                    .st-key-tampered_audit_log {
                        background-color: rgba(255, 75, 75, 0.20);
                        border-color: rgba(255, 75, 75, 0.65) !important;
                        border-radius: 0.5rem;
                    }
                    </style>
                    """
                )

            logs = api.get_audit_logs(session, limit = limit)
            if not logs:
                st.info("Todavía no hay registros de auditoría.")
            else:
                for entry in logs:
                    badge = "🟢" if entry["decision"] in ("ALLOWED", "APPROVED") else "🔴"
                    actor = entry.get("username") or str(entry.get("user_id") or "anónimo")
                    container_kwargs = {"border": True}
                    if broken_id is not None and entry["log_id"] == broken_id:
                        container_kwargs["key"] = "tampered_audit_log"

                    with st.container(**container_kwargs):
                        c1, c2 = st.columns([4, 2])
                        c1.markdown(
                            f"**#{entry['log_id']} · {badge} {entry['action']}** ({entry['decision']}) — `{actor}`"
                        )
                        if entry.get("reason"):
                            c1.caption(f"Motivo: {entry['reason']} · IP: {entry.get('ip_address', '-')}")
                        c2.caption(f"🕒 {entry['timestamp']}")
                        c2.code(
                            f"prev: {entry['prev_hash'][:12]}...\ncurr: {entry['current_hash'][:12]}...",
                            language = None,
                        )
        except api.ApiError as exc:
            handle_api_error(exc)
