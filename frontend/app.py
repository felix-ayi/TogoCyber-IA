import streamlit as st

from frontend.components.header import render_header
from frontend.components.sidebar import select_page
from frontend.components.error_state import render_error
from frontend.services.api_client import APIError, get_current_user
from frontend.styles.theme import stylesheet
from frontend.views import (
    about,
    alerts,
    audit,
    ai_assistant,
    authentication,
    cookies,
    history,
    incidents,
    home,
    network_analysis,
    phishing_analysis,
    privacy,
    terms,
    transparency,
    url_analysis,
    users,
    soc_dashboard,
    search,
    threat_intel,
    correlation,
    ml_monitoring,
    playbooks,
    integrations,
)

st.set_page_config(page_title="TogoCyber AI", layout="wide", initial_sidebar_state="expanded")
st.markdown(stylesheet(), unsafe_allow_html=True)

if not st.session_state.get("auth_token"):
    authentication.render()
    st.stop()

try:
    st.session_state["auth_user"] = get_current_user()
except APIError as exc:
    if exc.status_code == 401:
        st.session_state.pop("auth_token", None)
        st.session_state.pop("auth_user", None)
        st.warning("Votre session a expiré. Veuillez vous reconnecter.")
        authentication.render()
    else:
        render_error(str(exc))
    st.stop()

page = select_page()
render_header()

st.caption("Prototype de recherche — ne soumettez pas d’informations réellement confidentielles.")
renderers = {
    "Accueil": home.render,
    "Analyse réseau": network_analysis.render,
    "Analyse phishing / SMS": phishing_analysis.render,
    "Analyse URL": url_analysis.render,
    "Historique": history.render,
    "Incidents": incidents.render,
    "Tableau de bord SOC": soc_dashboard.render,
    "Alertes (SOC)": alerts.render,
    "Recherche (SOC)": search.render,
    "Threat Intel (IOC)": threat_intel.render,
    "Corrélation & règles": correlation.render,
    "Supervision ML": ml_monitoring.render,
    "Playbooks": playbooks.render,
    "Intégrations & notifications": integrations.render,
    "Audit de sécurité": audit.render,
    "Gestion des utilisateurs": users.render,
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