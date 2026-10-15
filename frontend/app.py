import os

import requests
import streamlit as st

API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000").rstrip("/")

st.set_page_config(page_title="Secure BioVault", page_icon="🔐")
st.title("Secure BioVault")
st.write("Streamlit frontend connected to a FastAPI backend.")

try:
    response = requests.get(f"{API_BASE_URL}/health", timeout=5)
    response.raise_for_status()
    st.success(f"Backend status: {response.json()['status']}")
except requests.RequestException as error:
    st.error(f"Could not connect to the backend at {API_BASE_URL}: {error}")
