import streamlit as st

from frontend.components.header import render_header
from frontend.components.sidebar import select_page
from frontend.styles.theme import stylesheet
from frontend.views import (
    about,
    ai_assistant,
    cookies,
    history,
    home,
    network_analysis,
    phishing_analysis,
    privacy,
    terms,
    transparency,
)

st.set_page_config(page_title="TogoCyber AI", layout="wide", initial_sidebar_state="expanded")
st.markdown(stylesheet(), unsafe_allow_html=True)

page = select_page()
render_header()

st.caption("Prototype de recherche — ne soumettez pas d’informations réellement confidentielles.")
renderers = {
    "Accueil": home.render,
    "Analyse réseau": network_analysis.render,
    "Analyse phishing / SMS": phishing_analysis.render,
    "Historique": history.render,
    "Assistant prévention": ai_assistant.render,
    "À propos": about.render,
    "Transparence": transparency.render,
    "Confidentialité": privacy.render,
    "Conditions d’utilisation": terms.render,
    "Cookies": cookies.render,
}
renderers[page]()

if not st.session_state.get("essential_cookie_choice", False):
    st.markdown(
        '<div role="note" aria-label="Information sur les cookies" '
        'style="padding:12px;border:1px solid #31506f;border-radius:8px;background:#fff">'
        'Cette démonstration utilise uniquement des cookies techniques de session.</div>',
        unsafe_allow_html=True,
    )
    if st.button("J’accepte les cookies essentiels", key="cookie_consent"):
        st.session_state["essential_cookie_choice"] = True
        st.rerun()

st.divider()
st.caption("TogoCyber AI · Démonstration de recherche · Vérifiez toute alerte auprès d’une source fiable.")