import streamlit as st

from frontend.components.brand_identity import render_brand_identity, render_capabilities
from frontend.services.api_client import APIError, login, register


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
    with st.form("login_form"):
        email = st.text_input("Adresse e-mail", max_chars=254, key="login_email")
        password = st.text_input(
            "Mot de passe", type="password", max_chars=128, key="login_password"
        )
        submitted = st.form_submit_button("Se connecter", type="primary")
    if submitted:
        try:
            with st.spinner("Vérification des identifiants…"):
                response = login(email, password)
            _save_session(response)
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
        try:
            with st.spinner("Création du compte…"):
                register(email, password)
            st.success("Compte créé. Vous pouvez maintenant vous connecter.")
        except APIError as exc:
            st.error(str(exc))
