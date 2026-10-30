import streamlit as st
import api_client as api
from util import strong_password, PASSWORD_RULES


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