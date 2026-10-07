import pandas as pd
import streamlit as st

from frontend.components.error_state import render_error
from frontend.services.api_client import (
    APIError,
    create_managed_user,
    delete_user,
    get_users,
    reset_user_password,
    update_user,
)

_ROLE_LABELS = {"Admin": "Administrateur", "Analyst": "Analyste", "User": "Utilisateur"}


def render() -> None:
    st.subheader("Gestion des utilisateurs")
    st.caption(
        "Réservé aux administrateurs : création de comptes, changement de rôle, "
        "activation/désactivation et réinitialisation de mot de passe. "
        "Le dernier administrateur actif ne peut être ni dégradé, ni désactivé, ni supprimé."
    )
    st.markdown(
        """
        <div class="tc-ops-summary">
          <div>
            <span class="tc-soc-summary-kicker">ACCES</span>
            <h3>Administration des comptes</h3>
          </div>
          <div class="tc-ops-summary-badges">
            <span>Rôles</span>
            <span>Activations</span>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    current_user = st.session_state.get("auth_user", {})
    if current_user.get("role") != "Admin":
        st.warning("Cette section est réservée aux administrateurs.")
        return

    try:
        users = get_users()
    except APIError as exc:
        render_error(str(exc))
        return

    if not users:
        st.info("Aucun utilisateur enregistré.")
    else:
        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "ID": user["id"],
                        "E-mail": user["email"],
                        "Rôle": _ROLE_LABELS.get(user["role"], user["role"]),
                        "Statut": "Actif" if user["is_active"] else "Désactivé",
                        "Créé le": user["created_at"],
                        "Dernière connexion": user.get("last_login") or "Jamais",
                    }
                    for user in users
                ]
            ),
            hide_index=True,
            use_container_width=True,
        )

    st.divider()
    with st.expander("Créer un compte", expanded=not users):
        with st.form("create_user_form", clear_on_submit=True):
            new_email = st.text_input("Adresse e-mail", max_chars=254, key="new_user_email")
            new_password = st.text_input(
                "Mot de passe (12 caractères minimum)",
                type="password",
                max_chars=128,
                key="new_user_password",
            )
            new_role = st.selectbox(
                "Rôle",
                options=["Analyst", "User"],
                format_func=lambda role: _ROLE_LABELS[role],
                key="new_user_role",
            )
            create_submitted = st.form_submit_button("Créer le compte", type="primary")
        if create_submitted:
            try:
                create_managed_user(new_email, new_password, new_role)
                st.success("Compte créé.")
                st.rerun()
            except APIError as exc:
                render_error(str(exc))

    if not users:
        return

    st.divider()
    st.markdown("**Gérer un compte**")
    options = {f"{user['id']} — {user['email']}": user for user in users}
    selected_label = st.selectbox("Utilisateur", options=list(options), key="manage_user_select")
    selected = options[selected_label]
    is_self = selected["id"] == current_user.get("id")

    with st.form("update_user_form"):
        target_role = st.selectbox(
            "Rôle",
            options=["Admin", "Analyst", "User"],
            index=["Admin", "Analyst", "User"].index(selected["role"]),
            format_func=lambda role: _ROLE_LABELS[role],
            key="manage_user_role",
        )
        target_active = st.toggle("Compte actif", value=bool(selected["is_active"]), key="manage_user_active")
        update_submitted = st.form_submit_button("Enregistrer les modifications")
    if update_submitted:
        try:
            update_user(
                selected["id"],
                role=target_role if target_role != selected["role"] else None,
                is_active=target_active if target_active != bool(selected["is_active"]) else None,
            )
            st.success("Compte mis à jour.")
            st.rerun()
        except APIError as exc:
            render_error(str(exc))

    with st.form("reset_password_form", clear_on_submit=True):
        reset_password = st.text_input(
            "Nouveau mot de passe (12 caractères minimum)",
            type="password",
            max_chars=128,
            key="manage_user_password",
        )
        reset_submitted = st.form_submit_button("Réinitialiser le mot de passe")
    if reset_submitted:
        try:
            reset_user_password(selected["id"], reset_password)
            st.success("Mot de passe réinitialisé. Les sessions actives de ce compte ont été révoquées.")
        except APIError as exc:
            render_error(str(exc))

    if is_self:
        st.caption("Vous ne pouvez pas supprimer votre propre compte.")
    elif st.button("Supprimer ce compte", type="secondary", key="manage_user_delete"):
        try:
            delete_user(selected["id"])
            st.success("Compte supprimé.")
            st.rerun()
        except APIError as exc:
            render_error(str(exc))
