import streamlit as st


def render() -> None:
    st.subheader("Transparence sur les données et les modèles")
    st.markdown(
        "- Le texte brut et les caractéristiques réseau ne sont pas stockés dans SQLite.\n"
        "- Seuls le module, le résultat, un score de confiance et la date sont conservés au plus 30 jours.\n"
        "- Les prédictions sont probabilistes ; les explications SHAP/LIME sont locales et ne démontrent pas une causalité.\n"
        "- La démonstration locale utilise un miroir UNSW-NB15 et un corpus d’e-mails publics en anglais ; ses mesures sont documentées dans `docs/demo_results.md`.\n"
        "- Aucun corpus CIC-IDS2017 ni corpus togolais validé n’a servi à cette démonstration ; les scores ne préjugent pas des performances sur le français, les SMS ou Mobile Money.\n"
        "- La généralisation CIC→UNSW et l’équité entre groupes linguistiques ne sont pas évaluées par ces résultats.\n"
        "- Pour effacer l’historique de démonstration, supprimer le fichier SQLite configuré par `TOGOCYBER_DB_PATH`."
    )