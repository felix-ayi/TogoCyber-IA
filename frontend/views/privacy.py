import streamlit as st


def render() -> None:
    st.subheader("Politique de confidentialité")
    st.markdown(
        "**Données traitées.** Le texte soumis est envoyé à l’API d’analyse, et une question d’assistance configurée "
        "peut être transmise à OpenAI. Les caractéristiques de flux sont utilisées pour l’inférence.\n\n"
        "**Historique.** SQLite conserve uniquement le type d’analyse, la prédiction, la confiance et l’horodatage "
        "pendant 30 jours maximum ; ni le message brut ni les caractéristiques ne sont stockés.\n\n"
        "**Finalité.** Démonstration et prévention des menaces numériques. Les fournisseurs techniques peuvent "
        "traiter les données conformément à leurs propres conditions.\n\n"
        "**Droits.** Pour demander l’effacement de l’historique du déploiement de démonstration, contactez son "
        "administrateur ; celui-ci peut aussi supprimer le fichier SQLite. Ne saisissez pas de données confidentielles."
    )