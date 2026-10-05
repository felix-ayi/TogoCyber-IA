import streamlit as st

from frontend.components.confidence_badge import render_confidence
from frontend.services.analysis_report import build_analysis_report
from frontend.services.response_guidance import get_action_guidance


def render_result(result: dict, positive_label: str, negative_label: str) -> None:
    positive = result["prediction"] in {"malicious", "phishing"}
    st.error(f"Résultat : {positive_label}") if positive else st.success(f"Résultat : {negative_label}")
    probability_key = "phishing_probability" if "phishing_probability" in result else "malicious_probability"
    probability = result[probability_key]
    st.write(f"Probabilité estimée de menace : **{probability:.1%}**")
    render_confidence(result["confidence_level"], result["confidence"])
    guidance = get_action_guidance(result["module"], result["prediction"])
    st.subheader(guidance["title"])
    for action in guidance["actions"]:
        st.markdown(f"- {action}")
    st.caption(guidance["caution"])
    explanations = result.get("explanation", [])
    if explanations:
        if result.get("explanation_truncated", False):
            st.caption("L’explication LIME porte sur les 2 000 premiers caractères ; la prédiction utilise le message complet.")
        st.subheader("Pourquoi ce résultat ?")
        st.caption(
            "L’explication porte sur le score de menace (phishing/malveillant), même si la classe retenue est légitime. "
            "Ces contributions locales ne prouvent pas une intention ni une causalité."
        )
        st.dataframe(explanations, hide_index=True, use_container_width=True)
    st.download_button(
        "Télécharger le rapport JSON",
        data=build_analysis_report(result),
        file_name=f"togocyber-{result['module']}-report.json",
        mime="application/json",
        key=f"download_analysis_{result['module']}_{result.get('history_id', 'latest')}",
    )