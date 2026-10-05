import streamlit as st


def render() -> None:
    st.subheader("Conditions d’utilisation")
    st.markdown(
        "Cet outil est un prototype de recherche et de sensibilisation, non un service de sécurité certifié. "
        "Les modèles peuvent se tromper ; ne prenez pas de décision critique sur leur seul avis.\n\n"
        "Utilisez uniquement des données et flux que vous êtes autorisé à analyser. Le scan, la surveillance "
        "ou l’accès non autorisé à un réseau sont interdits. N’utilisez pas l’outil pour nuire, frauder ou "
        "contourner des protections.\n\n"
        "Vous êtes responsable de vérifier les résultats et de respecter les lois applicables ainsi que les "
        "conditions des jeux de données et services tiers."
    )