import pandas as pd
import streamlit as st

from frontend.components.error_state import render_error
from frontend.services.api_client import APIError, analyze_url


def render() -> None:
    st.subheader("Inspection locale d’un lien")
    st.caption(
        "L’URL est examinée sans ouvrir le site, résoudre son domaine ni transmettre le lien à un service externe."
    )
    with st.form("url_analysis_form"):
        url = st.text_input("URL complète (http:// ou https://)", max_chars=2048)
        submitted = st.form_submit_button("Inspecter le lien", type="primary")
    if not submitted:
        return
    try:
        result = analyze_url(url)
    except APIError as exc:
        render_error(str(exc))
        return

    st.metric("Score heuristique de suspicion", f"{result['suspicion_score']}/100", result["severity"])
    st.caption(result["caution"])
    if result["indicators"]:
        st.subheader("Éléments de structure observés")
        st.dataframe(pd.DataFrame(result["indicators"]), hide_index=True, use_container_width=True)
    else:
        st.info("Aucun des indicateurs structurels connus n’a été observé.")
    st.subheader("Précautions")
    for recommendation in result["recommendations"]:
        st.markdown(f"- {recommendation}")
    st.caption(
        "Une structure inhabituelle n’est pas une preuve de fraude ; un lien sans indicateur peut tout de même être dangereux."
    )
