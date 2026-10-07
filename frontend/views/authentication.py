import os

import streamlit as st

from frontend.components.brand_identity import render_brand_identity, render_capabilities
from frontend.services.api_client import (
    APIError,
    confirm_password_reset,
    login,
    register,
    request_password_reset,
)


def build_bootstrap_admin_hint(email: str | None) -> str:
    normalized = (email or "").strip()
    if not normalized:
        return ""
    return f"Compte administrateur prêt à l’emploi : {normalized}"


def _save_session(response: dict) -> None:
    st.session_state["auth_token"] = response["access_token"]
    st.session_state["auth_user"] = response["user"]
    st.rerun()


def render() -> None:
    left, right = st.columns([1.2, 0.8], gap="large", vertical_alignment="center")
    with left:
        render_brand_identity()
        render_capabilities()
    with right:
      with st.container(key="tc-auth-panel", border=True):
        st.subheader("Accès sécurisé")
        st.caption("Connectez-vous à la plateforme TogoCyber-IA.")
        mode = st.segmented_control(
            "Mode de connexion",
            options=["Se connecter", "Créer un compte"],
            default="Se connecter",
            label_visibility="collapsed",
            key="auth_mode",
            width="stretch",
        )

        if mode == "Se connecter":
            _render_sign_in()
        else:
            _render_sign_up()


def _render_sign_in() -> None:
    bootstrap_email = os.getenv("BOOTSTRAP_ADMIN_EMAIL", "").strip()
    bootstrap_password = os.getenv("BOOTSTRAP_ADMIN_PASSWORD", "").strip()
    hint = build_bootstrap_admin_hint(bootstrap_email)
    if hint:
        st.info(hint)
        st.caption("Démo locale : connectez-vous avec le compte administrateur bootstrap configuré dans .env.")
        if st.button("Remplir le compte administrateur", key="prefill_bootstrap_admin"):
            st.session_state["login_email"] = bootstrap_email
            st.session_state["login_password"] = bootstrap_password
            st.rerun()
    else:
        st.warning(
            "Aucun compte bootstrap n’est configuré. Définissez BOOTSTRAP_ADMIN_EMAIL et "
            "BOOTSTRAP_ADMIN_PASSWORD dans .env puis redémarrez l’API pour créer le premier admin."
        )

    with st.form("login_form"):
        email = st.text_input("Adresse e-mail", max_chars=254, key="login_email")
        password = st.text_input(
            "Mot de passe", type="password", max_chars=128, key="login_password"
        )
        submitted = st.form_submit_button("Se connecter", type="primary")
    if submitted:
        email = email.strip()
        password = password.strip()
        if not email or not password:
            st.warning("Veuillez saisir une adresse e-mail et un mot de passe.")
            return
        try:
            with st.spinner("Vérification des identifiants…"):
                response = login(email, password)
            _save_session(response)
        except APIError as exc:
            st.error(str(exc))

    if st.button("Mot de passe oublié ?", key="forgot_password_button"):
        st.session_state["show_password_reset"] = True
        st.rerun()

    if st.session_state.get("show_password_reset"):
        st.markdown("### Réinitialiser mon mot de passe")
        with st.form("password_reset_request_form"):
            reset_email = st.text_input(
                "Adresse e-mail",
                value=st.session_state.get("login_email", ""),
                max_chars=254,
                key="reset_email",
            )
            reset_requested = st.form_submit_button("Envoyer la demande")
        if reset_requested:
            email_value = reset_email.strip()
            if not email_value:
                st.warning("Saisissez votre adresse e-mail pour continuer.")
            else:
                try:
                    with st.spinner("Vérification de votre compte…"):
                        reset_payload = request_password_reset(email_value)
                    if reset_payload.get("reset_token"):
                        st.info("Mode démonstration : copiez le jeton ci-dessous pour terminer la réinitialisation. SMTP n’est pas configuré, le jeton est donc affiché localement pour la démo.")
                        st.code(reset_payload["reset_token"])
                    else:
                        st.success("Si un compte correspond à cette adresse, une procédure de réinitialisation a été déclenchée.")
                    st.session_state["password_reset_email"] = email_value
                    st.session_state.pop("reset_token", None)
                    st.session_state.pop("reset_new_password", None)
                    st.session_state.pop("reset_confirm_password", None)
                except APIError as exc:
                    st.error(str(exc))

        if st.session_state.get("password_reset_email"):
            st.caption(
                "La confirmation utilisera l’adresse de la dernière demande de réinitialisation."
            )
            with st.form("password_reset_confirm_form"):
                token = st.text_input("Jeton de réinitialisation", max_chars=512, key="reset_token")
                new_password = st.text_input(
                    "Nouveau mot de passe (12 caractères minimum)",
                    type="password",
                    max_chars=128,
                    key="reset_new_password",
                )
                confirm_password = st.text_input(
                    "Confirmer le nouveau mot de passe",
                    type="password",
                    max_chars=128,
                    key="reset_confirm_password",
                )
                reset_submitted = st.form_submit_button(
                    "Valider le nouveau mot de passe", type="primary"
                )
            if reset_submitted:
                if not token.strip() or not new_password:
                    st.warning("Le jeton et le nouveau mot de passe sont requis.")
                elif len(new_password) < 12:
                    st.warning("Le nouveau mot de passe doit contenir au moins 12 caractères.")
                elif new_password != confirm_password:
                    st.warning("La confirmation du mot de passe ne correspond pas.")
                else:
                    try:
                        with st.spinner("Mise à jour du mot de passe…"):
                            confirm_password_reset(
                                st.session_state["password_reset_email"], token, new_password
                            )
                        st.success("Le mot de passe a été réinitialisé.")
                        st.session_state.pop("show_password_reset", None)
                        st.session_state.pop("password_reset_email", None)
                        st.session_state.pop("reset_token", None)
                        st.session_state.pop("reset_new_password", None)
                        st.session_state.pop("reset_confirm_password", None)
                    except APIError as exc:
                        st.error(str(exc))


def _render_sign_up() -> None:
    with st.form("register_form"):
        email = st.text_input("Adresse e-mail", max_chars=254, key="register_email")
        password = st.text_input(
            "Mot de passe (12 caractères minimum)",
            type="password",
            max_chars=128,
            key="register_password",
        )
        submitted = st.form_submit_button("Créer mon compte")
    if submitted:
        email = email.strip()
        password = password.strip()
        if not email or not password:
            st.warning("Veuillez saisir une adresse e-mail et un mot de passe.")
            return
        if len(password) < 12:
            st.warning("Le mot de passe doit contenir au moins 12 caractères.")
            return
        try:
            with st.spinner("Création du compte…"):
                register(email, password)
            st.success("Compte créé. Vous pouvez maintenant vous connecter.")
        except APIError as exc:
            st.error(str(exc))
