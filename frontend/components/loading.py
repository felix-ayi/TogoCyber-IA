import streamlit as st


def analysis_spinner(label: str = "Analyse en cours…"):
    return st.spinner(label)