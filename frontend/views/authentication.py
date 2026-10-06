import streamlit as st

from frontend.services.api_client import APIError, login, register


def _save_session(response: dict) -> None:
    st.session_state["auth_token"] = response["access_token"]
    st.session_state["auth_user"] = response["user"]
    st.rerun()


def render() -> None:
    st.title("Connexion à TogoCyber AI")
    st.caption("Créez un compte ou connectez-vous. Les nouvelles inscriptions reçoivent le rôle User.")
    sign_in, sign_up = st.tabs(["Se connecter", "Créer un compte"])

    with sign_in:
        with st.form("login_form"):
            email = st.text_input("Adresse e-mail", max_chars=254, key="login_email")
            password = st.text_input("Mot de passe", type="password", max_chars=128, key="login_password")
            submitted = st.form_submit_button("Se connecter", type="primary")
        if submitted:
            try:
                _save_session(login(email, password))
            except APIError as exc:
                st.error(str(exc))

    with sign_up:
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
                register(email, password)
                st.success("Compte créé. Vous pouvez maintenant vous connecter.")
            except APIError as exc:
                st.error(str(exc))
