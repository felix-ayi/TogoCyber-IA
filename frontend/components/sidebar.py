import streamlit as st

from frontend.services.api_client import APIError, get_health, logout
PAGES = [
    "Accueil",
    "Guide utilisateur",
    "Mon profil",
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
    "Guide utilisateur": "❔",
    "Mon profil": "👤",
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

ADMIN_ONLY_PAGES = {"Audit de sécurité", "Gestion des utilisateurs"}
SOC_PAGES = {
    "Tableau de bord SOC",
    "Alertes (SOC)",
    "Recherche (SOC)",
    "Threat Intel (IOC)",
    "Corrélation & règles",
    "Supervision ML",
    "Playbooks",
    "Intégrations & notifications",
}


def pages_for_role(role: str | None) -> list[str]:
    if role == "Admin":
        return PAGES.copy()
    if role == "Analyst":
        return [page for page in PAGES if page not in ADMIN_ONLY_PAGES]
    return [
        page for page in PAGES if page not in ADMIN_ONLY_PAGES and page not in SOC_PAGES
    ]


def apply_navigation_override(visible_pages: list[str], session_state: dict) -> None:
    requested = session_state.pop("profile_page_target", None)
    if requested in visible_pages:
        session_state["main_navigation"] = requested


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
        visible_pages = pages_for_role(role)
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
        apply_navigation_override(visible_pages, st.session_state)
        sidebar_status = "OK" if health.get("status") == "healthy" else "Hors ligne"
        st.markdown(
            f"""
            <div class="tc-sidebar-summary">
              <div class="tc-sidebar-summary-top">
                <span class="tc-sidebar-summary-badge">MODE DÉMO</span>
                <span class="tc-sidebar-summary-status">{sidebar_status}</span>
              </div>
              <div class="tc-sidebar-summary-meta">
                <span>Rôle : {role or 'Utilisateur'}</span>
                <span>Scénario : synthétique</span>
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.markdown('<p class="tc-sidebar-label">ESPACE DE TRAVAIL</p>', unsafe_allow_html=True)
        selected_page = st.radio(
            "Navigation",
            visible_pages,
            format_func=lambda page: f"{PAGE_ICONS[page]}   {page}",
            label_visibility="collapsed",
            key="main_navigation",
        )

        st.markdown('<div class="tc-sidebar-user-card">', unsafe_allow_html=True)
        if user:
            st.markdown(
                f"""
                <div class="tc-sidebar-user-header">
                    <span class="tc-sidebar-user-badge">{user.get('role', 'User')}</span>
                    <span class="tc-sidebar-user-meta">Session active</span>
                </div>
                <div class="tc-sidebar-user-email">{user.get('email', 'Compte')}</div>
                """,
                unsafe_allow_html=True,
            )
        st.markdown('</div>', unsafe_allow_html=True)

        st.markdown('<div class="tc-sidebar-footer">', unsafe_allow_html=True)
        if st.button("Paramètres utilisateur", key="sidebar_profile_button", use_container_width=True):
            st.session_state["profile_page_target"] = "Mon profil"
            st.rerun()
        if st.button("Se déconnecter", key="logout_button", use_container_width=True):
            try:
                logout()
            except APIError as exc:
                st.warning(f"Déconnexion distante impossible : {exc}")
            finally:
                st.session_state.pop("auth_token", None)
                st.session_state.pop("auth_user", None)
            st.rerun()
        st.markdown('</div>', unsafe_allow_html=True)
        return selected_page