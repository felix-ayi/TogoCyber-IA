import streamlit as st

from frontend.components.error_state import render_error
from frontend.components.loading import analysis_spinner
from frontend.components.result_card import render_result
from frontend.services.api_client import APIError, analyze_phishing


def render() -> None:
    st.subheader("Vérifier un SMS, e-mail ou lien")
    st.caption("Évitez de coller des conversations privées : le texte n’est pas enregistré dans l’historique.")
    with st.form("phishing_form"):
        message = st.text_area("Message ou lien à vérifier", max_chars=20_000, height=180)
        submitted = st.form_submit_button("Analyser le message", type="primary")
    if submitted:
        if not message.strip():
            st.warning("Saisissez un message avant de lancer l’analyse.")
            return
        try:
            with analysis_spinner():
                result = analyze_phishing(message)
            render_result(result, "Signaux de phishing détectés", "Aucun signal évident détecté")
        except APIError as exc:
            render_error(str(exc))