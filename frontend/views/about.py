import streamlit as st


def render() -> None:
    st.subheader("À propos du projet")
    st.markdown(
        """
        <div class="tc-knowledge-shell">
          <div class="tc-knowledge-card tc-knowledge-card-wide">
            <span class="tc-soc-summary-kicker">PROTOTYPE DE RECHERCHE</span>
            <h3>TogoCyber AI</h3>
            <p>TogoCyber AI est un prototype de recherche destiné à explorer la détection de flux réseau et de phishing/smishing, avec explications locales. Cette démonstration utilise un miroir UNSW-NB15 et un corpus public de courriels anglais. Vérifiez les conditions des sources originales avant toute redistribution ou tout usage commercial.</p>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.info(
        "Les modèles ont été entraînés et évalués sur ces jeux de démonstration. Cela ne valide pas "
        "CIC-IDS2017, les SMS, le français togolais ou les menaces Mobile Money."
    )