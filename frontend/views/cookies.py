import streamlit as st


def render() -> None:
    st.subheader("Politique de cookies")
    st.markdown(
        "Cette démonstration n’ajoute pas de cookie publicitaire ou de suivi. Streamlit peut utiliser des "
        "cookies techniques nécessaires au fonctionnement de la session. Le bandeau de consentement ci-dessous "
        "mémorise votre choix uniquement dans l’état de la session Streamlit."
    )