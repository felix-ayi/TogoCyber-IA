import streamlit as st
import pandas as pd

from frontend.components.error_state import render_error
from frontend.services.api_client import APIError, get_history


def render() -> None:
    st.subheader("Historique récent")
    st.caption("Seuls le type d’analyse, le résultat, la confiance et l’horodatage sont conservés, pour 30 jours maximum.")
    try:
        items = get_history()
    except APIError as exc:
        render_error(str(exc))
        return
    if not items:
        st.info("Aucune analyse récente. Vos messages et caractéristiques brutes ne sont pas enregistrés.")
        return
    st.dataframe(pd.DataFrame(items), hide_index=True, use_container_width=True)