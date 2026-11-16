import streamlit as st
import api_client as api
import io
import qrcode
from util import strong_password, PASSWORD_RULES


def _reset_mfa_state() -> None:
    st.session_state.pop("mfa_mode", None)
    st.session_state.pop("mfa_setup_data", None)

def auth_page():
    st.title("🔐 SecureBioVault")
    st.caption("Almacenamiento cifrado de bio-datos · AES-256-GCM")
 
    tab_login, tab_register = st.tabs(["Iniciar sesión", "Registrarse"])
 
    with tab_login:
        mfa_mode = st.session_state.get("mfa_mode") # None | "setup" | "verify"

        # First access -> Show QR to configure MFA
        if mfa_mode == "setup" and "mfa_setup_data" in st.session_state:
            setup = st.session_state["mfa_setup_data"]
            qr_img = qrcode.make(setup["otpauth_url"])
            buf = io.BytesIO()
            qr_img.save(buf, format="PNG")

            st.warning(
                "Configuración de seguridad obligatoria: escane este código QR "
                "con Google Authenticator, Authy o similares."
            )
            st.image(buf.getvalue(), width=210)
            st.caption(f"Clave manual: `{setup['secret']}`")

        with st.form("login_form"):
            username = st.text_input("Usuario", key="login_user")
            password = st.text_input("Contraseña", type="password", key="login_pw")

            totp_code = None
            if mfa_mode in ("setup", "verify"):
                label = (
                    "Introduce el primer codigo para activar 2FA"
                    if mfa_mode == "setup"
                    else "Código 2FA (6 dígitos)"
                )
                totp_code = st.text_input(label, max_chars=6, key="login_totp")

            submitted = st.form_submit_button("Entrar", type="primary")

        if mfa_mode in ("setup", "verify"):
            if st.button("Cancelar verificación 2FA", key="cancel_mfa"):
                _reset_mfa_state()
                st.rerun()
        
        if submitted:
            if not username or not password:
                st.error("Introduce usuario y contraseña.")
            elif mfa_mode in ("setup", "verify") and not totp_code:
                st.error("Introduce el código de 6 dígitos de la app autenticadora.")
            else:
                try:
                    session = api.login(username, password, totp_code=totp_code)
                    profile = api.me(session)

                    _reset_mfa_state()
                    st.session_state["role"] = profile.get("role", "PATIENT")
                    st.session_state["username"] = username
                    st.session_state["session"] = session

                    st.rerun()
                except api.ApiError as exc:
                    code = exc.payload.get("code")

                    if exc.status == 403 and code == "MFA_SETUP_REQUIRED":
                        st.session_state["mfa_mode"] = "setup"
                        st.session_state["mfa_setup_data"] = exc.payload
                        st.rerun()
                    elif exc.status == 403 and code == "MFA_REQUIRED":
                        st.session_state["mfa_mode"] = "verify"
                        st.rerun()
                    elif exc.status == 401 and mfa_mode in ("setup", "verify"):
                        st.error("Código MFA incorrecto o caducado.")
                    else:
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
