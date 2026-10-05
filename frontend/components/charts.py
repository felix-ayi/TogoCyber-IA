import pandas as pd
import streamlit as st


def render_explanations(items: list[dict], term_key: str, contribution_key: str = "contribution") -> None:
    if not items:
        st.info("Aucune explication disponible pour cette analyse.")
        return
    frame = pd.DataFrame(items).set_index(term_key)
    st.bar_chart(frame[contribution_key], use_container_width=True)
    st.caption("Lecture du graphique : les contributions positives soutiennent la classe expliquée ; les négatives s’y opposent.")