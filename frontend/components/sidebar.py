import streamlit as st

from frontend.services.api_client import APIError, get_health
PAGES = [
    "Accueil",
    "Analyse réseau",
    "Analyse phishing / SMS",
    "Historique",
    "Assistant prévention",
    "À propos",
    "Transparence",
    "Confidentialité",
    "Conditions d’utilisation",
    "Cookies",
]

PAGE_ICONS = {
    "Accueil": "⌂",
    "Analyse réseau": "⌁",
    "Analyse phishing / SMS": "✉",
    "Historique": "◷",
    "Assistant prévention": "✦",
    "À propos": "ⓘ",
    "Transparence": "◈",
    "Confidentialité": "▣",
    "Conditions d’utilisation": "≡",
    "Cookies": "◌",
}


def select_page() -> str:
    with st.sidebar:
        st.markdown(
            '<div class="tc-sidebar-brand"><span class="tc-sidebar-shield">🛡</span>'
            '<span><strong>TogoCyber <em>AI</em></strong><small>Vigilance numérique</small></span></div>',
            unsafe_allow_html=True,
        )
        st.caption("Prototype de recherche · N’entrez aucun secret ni donnée sensible.")
        try:
            health = get_health()
            missing = [name for name, ready in health["models"].items() if not ready]
            if missing:
                labels = {"network": "réseau", "phishing": "phishing"}
                required = ", ".join(labels.get(name, name) for name in missing)
                st.warning(f"API disponible ; modèles à entraîner : {required}.")
            else:
                st.success("API et modèles disponibles")
                for name, source in health.get("model_sources", {}).items():
                    label = {"network": "Réseau", "phishing": "Phishing"}.get(name, name)
                    if name == "network" and source == "unsw":
                        source = "UNSW-NB15 · démo"
                    elif name == "phishing" and "English" in source:
                        source = "Courriels anglais · démo"
                    st.caption(f"{label} — {source}")
        except APIError:
            st.warning("API hors ligne — les analyses sont indisponibles.")
        st.markdown('<p class="tc-sidebar-label">ESPACE DE TRAVAIL</p>', unsafe_allow_html=True)
        return st.radio(
            "Navigation",
            PAGES,
            format_func=lambda page: f"{PAGE_ICONS[page]}   {page}",
            label_visibility="collapsed",
            key="main_navigation",
        )