import pandas as pd
import streamlit as st

from frontend.components.error_state import render_error
from frontend.services.api_client import APIError, clear_history, get_history


def render() -> None:
    st.subheader("Historique récent")
    st.caption("Métadonnées de résultat, score de risque et modèle : conservés au plus 30 jours. Les entrées sont limitées à votre compte.")
    st.markdown(
        """
        <div class="tc-ops-summary">
          <div>
            <span class="tc-soc-summary-kicker">HISTORIQUE</span>
            <h3>Trace des décisions d’analyse</h3>
          </div>
          <div class="tc-ops-summary-badges">
            <span>30 jours</span>
            <span>Compte local</span>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col_primary, col_secondary = st.columns([3, 1])
    with col_secondary:
        if st.button("Vider l’historique", type="secondary", use_container_width=True):
            if st.confirm("Supprimer toutes les analyses récentes de ce compte ?"):
                try:
                    clear_history()
                    st.success("Historique nettoyé.")
                    st.rerun()
                except APIError as exc:
                    render_error(str(exc))

    try:
        items = get_history()
    except APIError as exc:
        render_error(str(exc))
        return
    if not items:
        st.info("Aucune analyse récente. Vos messages et caractéristiques brutes ne sont pas enregistrés.")
        return
    st.dataframe(pd.DataFrame(items), hide_index=True, use_container_width=True)