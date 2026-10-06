import streamlit as st
import pandas as pd

from frontend.components.error_state import render_error
from frontend.services.api_client import APIError, get_history


def render() -> None:
    st.subheader("Historique récent")
    st.caption("Métadonnées de résultat, score de risque et modèle : conservés au plus 30 jours. Les entrées sont limitées à votre compte.")
    try:
        items = get_history()
    except APIError as exc:
        render_error(str(exc))
        return
    if not items:
        st.info("Aucune analyse récente. Vos messages et caractéristiques brutes ne sont pas enregistrés.")
        return
    st.dataframe(pd.DataFrame(items), hide_index=True, use_container_width=True)