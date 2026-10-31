"""SecureBioVault - Frontend Streamlit.
 
Ejecutar:  streamlit run app.py
"""
 
import streamlit as st
from util import logout
 
st.set_page_config(
    page_title="SecureBioVault",
    page_icon="🔐",
    layout="centered",
)

from views.auth import auth_page
from views.admin import admin_page
from views.doctor import doctor_view
from views.patient import vault_page

def main():
    if "session" not in st.session_state:
        auth_page()
        return
    role = st.session_state.get("role", "PATIENT")
    if role == "ADMIN":
        admin_page()
    elif role in ["DOCTOR", "RESEARCHER"]:
        prefix = "doc" if role == "DOCTOR" else "res"
        doctor_view(key_prefix=prefix)
    else:
        vault_page(key_prefix="vault")

if __name__ == "__main__":
    main()
