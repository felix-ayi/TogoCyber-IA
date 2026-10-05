import streamlit as st


def render() -> None:
    st.subheader("À propos du projet")
    st.markdown(
        "TogoCyber AI est un prototype de recherche destiné à explorer la détection de flux réseau "
        "et de phishing/smishing, avec explications locales. Cette démonstration utilise un miroir "
        "UNSW-NB15 et un corpus public de courriels anglais. Vérifiez les conditions des sources "
        "originales avant toute redistribution ou tout usage commercial."
    )
    st.info(
        "Les modèles ont été entraînés et évalués sur ces jeux de démonstration. Cela ne valide pas "
        "CIC-IDS2017, les SMS, le français togolais ou les menaces Mobile Money."
    )