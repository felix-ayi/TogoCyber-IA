import streamlit as st

from frontend.components.error_state import render_error
from frontend.services.api_client import APIError, ask_assistant


def render() -> None:
    st.subheader("Assistant de prévention")
    st.caption("Service externe OpenAI, disponible seulement si le déploiement a configuré une clé API.")
    with st.form("assistant_form"):
        message = st.text_area("Votre question de prévention", max_chars=8_000)
        submitted = st.form_submit_button("Demander un conseil", type="primary")
    if submitted:
        if not message.strip():
            st.warning("Saisissez une question.")
            return
        try:
            with st.spinner("Préparation d’un conseil…"):
                result = ask_assistant(message)
            st.markdown(result["response"])
            st.info(result["disclaimer"])
        except APIError as exc:
            render_error(str(exc))