import streamlit as st

LABELS = {
    "low": ("Faible", "🟢"),
    "medium": ("Moyen", "🟠"),
    "high": ("Élevé", "🔴"),
}


def render_confidence(level: str, confidence: float) -> None:
    label, symbol = LABELS.get(level, ("Inconnu", "⚪"))
    st.metric("Confiance estimée", f"{symbol} {label}", f"{confidence:.1%}")
    st.caption("La confiance décrit la certitude du modèle, pas la gravité d’une menace.")