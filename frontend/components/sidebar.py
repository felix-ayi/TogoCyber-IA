import streamlit as st

from frontend.services.api_client import APIError, get_health, logout
PAGES = [
    "Accueil",
    "Analyse réseau",
    "Analyse phishing / SMS",
    "Analyse URL",
    "Historique",
    "Incidents",
    "Tableau de bord SOC",
    "Alertes (SOC)",
    "Recherche (SOC)",
    "Threat Intel (IOC)",
    "Corrélation & règles",
    "Supervision ML",
    "Playbooks",
    "Intégrations & notifications",
    "Audit de sécurité",
    "Gestion des utilisateurs",
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
    "Analyse URL": "↗",
    "Historique": "◷",
    "Incidents": "⚑",
    "Tableau de bord SOC": "▦",
    "Alertes (SOC)": "🔔",
    "Recherche (SOC)": "⌕",
    "Threat Intel (IOC)": "☣",
    "Corrélation & règles": "⇄",
    "Supervision ML": "📈",
    "Playbooks": "🗂",
    "Intégrations & notifications": "🔌",
    "Audit de sécurité": "▤",
    "Gestion des utilisateurs": "☰",
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
        user = st.session_state.get("auth_user", {})
        role = user.get("role")
        admin_only_pages = {"Audit de sécurité", "Gestion des utilisateurs"}
        soc_pages = {
            "Tableau de bord SOC",
            "Alertes (SOC)",
            "Recherche (SOC)",
            "Threat Intel (IOC)",
            "Corrélation & règles",
            "Supervision ML",
            "Playbooks",
            "Intégrations & notifications",
        }
        if role == "Admin":
            visible_pages = PAGES
        elif role == "Analyst":
            visible_pages = [page for page in PAGES if page not in admin_only_pages]
        else:
            visible_pages = [
                page for page in PAGES if page not in admin_only_pages and page not in soc_pages
            ]
        if user:
            st.caption(f"Connecté : {user.get('email')} · rôle {user.get('role')}")
            if st.button("Se déconnecter", key="logout_button"):
                try:
                    logout()
                except APIError as exc:
                    st.warning(f"Déconnexion distante impossible : {exc}")
                finally:
                    st.session_state.pop("auth_token", None)
                    st.session_state.pop("auth_user", None)
                st.rerun()
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
            visible_pages,
            format_func=lambda page: f"{PAGE_ICONS[page]}   {page}",
            label_visibility="collapsed",
            key="main_navigation",
        )