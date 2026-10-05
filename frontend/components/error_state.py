import streamlit as st


def render_error(message: str) -> None:
    st.error(message)
    st.caption("Aucune donnée soumise n’est conservée par cette interface. Vous pouvez réessayer.")