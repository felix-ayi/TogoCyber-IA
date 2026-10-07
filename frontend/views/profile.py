import streamlit as st

from frontend.components.error_state import render_error
from frontend.services.api_client import APIError, change_password, get_current_user


_ROLE_LABELS = {"Admin": "Administrateur", "Analyst": "Analyste", "User": "Utilisateur"}


def _navigate(page: str) -> None:
    st.session_state["main_navigation"] = page


def render() -> None:
    st.subheader("Mon profil")
    user = st.session_state.get("auth_user", {})
    if not user:
        try:
            user = get_current_user()
            st.session_state["auth_user"] = user
        except APIError as exc:
            render_error(str(exc))
            return

    st.markdown(
        """
        <section class="tc-profile-panel" aria-label="Profil utilisateur">
          <div class="tc-profile-head">
            <span class="tc-profile-chip">Compte</span>
            <span class="tc-profile-role">{role}</span>
          </div>
          <div class="tc-profile-body">
            <div>
              <span class="tc-profile-label">E-mail</span>
              <strong>{email}</strong>
            </div>
            <div>
              <span class="tc-profile-label">Statut</span>
              <strong>{status}</strong>
            </div>
          </div>
        </section>
        """.format(
            role=_ROLE_LABELS.get(user.get("role"), user.get("role", "—")),
            email=str(user.get("email", "—")),
            status="Actif" if user.get("is_active") else "Désactivé",
        ),
        unsafe_allow_html=True,
    )

    col_a, col_b = st.columns(2)
    with col_a:
        st.markdown("### Informations du compte")
        st.text_input("Prénom", value="—", disabled=True, key="profile_firstname")
        st.text_input("Nom", value="—", disabled=True, key="profile_lastname")
        st.text_input("E-mail", value=str(user.get("email", "—")), disabled=True, key="profile_email")
        st.text_input("Rôle", value=_ROLE_LABELS.get(user.get("role"), user.get("role", "—")), disabled=True, key="profile_role")
    with col_b:
        st.markdown("### État du compte")
        st.text_input("Date de création", value=str(user.get("created_at", "—")), disabled=True, key="profile_created")
        st.text_input("Statut", value="Actif" if user.get("is_active") else "Désactivé", disabled=True, key="profile_status")
        st.text_input("Identifiant utilisateur", value=str(user.get("id", "—")), disabled=True, key="profile_id")

    st.markdown("### Actions rapides")
    st.markdown('<div class="tc-profile-actions">', unsafe_allow_html=True)
    quick_actions = st.columns(3)
    with quick_actions[0]:
        st.button(
            "⌂ Accueil",
            key="profile_home",
            use_container_width=True,
            on_click=_navigate,
            args=("Accueil",),
        )
    with quick_actions[1]:
        st.button(
            "◷ Historique",
            key="profile_history",
            use_container_width=True,
            on_click=_navigate,
            args=("Historique",),
        )
    with quick_actions[2]:
        st.button(
            "▦ SOC",
            key="profile_soc",
            use_container_width=True,
            on_click=_navigate,
            args=("Tableau de bord SOC",),
        )
    st.markdown('</div>', unsafe_allow_html=True)

    st.markdown("### Paramètres utilisateur")
    prefs = st.session_state.setdefault(
        "profile_preferences",
        {
            "notifications": True,
            "auto_refresh": True,
            "compact_mode": False,
            "reduced_motion": False,
            "theme": "Nuit cyber",
        },
    )
    st.markdown('<div class="tc-settings-panel">', unsafe_allow_html=True)
    with st.form("profile_preferences_form"):
        col_pref_a, col_pref_b = st.columns(2)
        with col_pref_a:
            notifications = st.checkbox("Afficher les alertes prioritaires", value=prefs.get("notifications", True), key="profile_notifications")
            auto_refresh = st.checkbox("Rafraîchissement automatique du SOC", value=prefs.get("auto_refresh", True), key="profile_auto_refresh")
        with col_pref_b:
            compact_mode = st.checkbox("Mode compact", value=prefs.get("compact_mode", False), key="profile_compact_mode")
            reduced_motion = st.checkbox("Réduire les animations", value=prefs.get("reduced_motion", False), key="profile_reduced_motion")
            theme = st.selectbox(
                "Palette d’interface",
                ["Nuit cyber", "Sécurité claire", "Alerte standard"],
                index=["Nuit cyber", "Sécurité claire", "Alerte standard"].index(prefs.get("theme", "Nuit cyber")),
                key="profile_theme",
            )
        save_preferences = st.form_submit_button("Enregistrer les préférences", type="primary")

    if save_preferences:
        st.session_state["profile_preferences"] = {
            "notifications": notifications,
            "auto_refresh": auto_refresh,
            "compact_mode": compact_mode,
            "reduced_motion": reduced_motion,
            "theme": theme,
        }
        st.success("Préférences utilisateur enregistrées.")
        st.rerun()
    st.markdown('</div>', unsafe_allow_html=True)

    st.divider()
    st.subheader("Changer le mot de passe")
    with st.form("profile_password_form"):
        current_password = st.text_input("Ancien mot de passe", type="password", key="profile_current_password")
        new_password = st.text_input("Nouveau mot de passe", type="password", key="profile_new_password")
        confirm_password = st.text_input("Confirmer le nouveau mot de passe", type="password", key="profile_confirm_password")
        submitted = st.form_submit_button("Valider le changement", type="primary")

    if submitted:
        if not current_password or not new_password or not confirm_password:
            st.warning("Veuillez remplir tous les champs du changement de mot de passe.")
            return
        if new_password != confirm_password:
            st.warning("La confirmation du nouveau mot de passe ne correspond pas.")
            return
        try:
            change_password(current_password, new_password)
            st.success("Votre mot de passe a été mis à jour avec succès.")
        except APIError as exc:
            st.error(str(exc))
