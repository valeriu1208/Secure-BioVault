import re
 
import streamlit as st
 
import api_client as api


MAX_PDF_MB = 25
PASSWORD_RULES = "Mínimo 12 caracteres, con mayúscula, minúscula, número y símbolo."
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