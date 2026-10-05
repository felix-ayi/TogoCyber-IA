import streamlit as st

from frontend.components.confidence_badge import render_confidence


def render_result(result: dict, positive_label: str, negative_label: str) -> None:
    positive = result["prediction"] in {"malicious", "phishing"}
    st.error(f"Résultat : {positive_label}") if positive else st.success(f"Résultat : {negative_label}")
    probability_key = "phishing_probability" if "phishing_probability" in result else "malicious_probability"
    probability = result[probability_key]
    st.write(f"Probabilité estimée de menace : **{probability:.1%}**")
    render_confidence(result["confidence_level"], result["confidence"])
    explanations = result.get("explanation", [])
    if explanations:
        st.subheader("Pourquoi ce résultat ?")
        st.caption(
            "L’explication porte sur le score de menace (phishing/malveillant), même si la classe retenue est légitime. "
            "Ces contributions locales ne prouvent pas une intention ni une causalité."
        )
        st.dataframe(explanations, hide_index=True, use_container_width=True)