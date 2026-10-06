"""ML supervision: honest monitoring signals and analyst false-positive feedback (SOC only)."""

import pandas as pd
import streamlit as st

from frontend.components.error_state import render_error
from frontend.services.api_client import APIError, get_ml_feedback, get_ml_monitoring

_MODULE_LABELS = {"network": "Réseau", "phishing": "Phishing/SMS"}
_VERDICT_LABELS = {"false_positive": "Faux positif", "confirmed": "Confirmé (vrai positif)"}


def render() -> None:
    st.subheader("Supervision des modèles (ML)")
    st.caption(
        "Indicateurs calculés uniquement à partir des détections réellement stockées et "
        "des verdicts saisis par les analystes. Les caractéristiques brutes ne sont pas "
        "conservées : aucun drift d’entrées (PSI/KS) n’est donc fabriqué. Le « drift » "
        "affiché est l’écart du taux de prédiction malveillante entre les deux moitiés de "
        "la fenêtre d’observation."
    )
    user = st.session_state.get("auth_user", {})
    if user.get("role") not in {"Admin", "Analyst"}:
        st.warning("Cette section est réservée aux analystes et administrateurs.")
        return

    days = st.select_slider(
        "Fenêtre d’observation", options=[7, 14, 30], value=30,
        format_func=lambda d: f"{d} jours", key="ml_window_days",
    )
    try:
        data = get_ml_monitoring(days=int(days))
    except APIError as exc:
        render_error(str(exc))
        return

    _render_summary(data)
    st.divider()
    _render_feedback(data)
    st.divider()
    _render_feedback_log()


def _render_summary(data: dict) -> None:
    st.markdown("##### Vue d’ensemble")
    total = data.get("total_analyses", 0)
    modules = data.get("modules", {})
    col_a, col_b = st.columns(2)
    col_a.metric("Analyses sur la fenêtre", total)
    col_b.metric("Modules observés", len(modules))

    if total == 0:
        st.info(
            "Aucune détection sur cette fenêtre. Les indicateurs apparaîtront dès que des "
            "analyses réseau ou phishing seront enregistrées."
        )
        return

    st.dataframe(
        pd.DataFrame(
            [
                {
                    "Module": _MODULE_LABELS.get(module, module),
                    "Analyses": summary["total"],
                    "Malveillantes": summary["malicious"],
                    "Taux malveillant": _percent(summary["malicious_rate"]),
                    "Taux récent": _percent(summary["drift"]["recent_malicious_rate"]),
                    "Taux antérieur": _percent(summary["drift"]["prior_malicious_rate"]),
                    "Drift (Δ)": _delta(summary["drift"]["delta"]),
                    "Modèles": ", ".join(summary["models"]) or "—",
                }
                for module, summary in modules.items()
            ]
        ),
        hide_index=True,
        use_container_width=True,
    )
    st.caption(
        "Drift (Δ) = taux malveillant récent − taux malveillant antérieur, calculé sur les "
        "détections stockées de la fenêtre."
    )


def _render_feedback(data: dict) -> None:
    st.markdown("##### Retours analystes (faux positifs / confirmations)")
    feedback = data.get("feedback", {})
    total = feedback.get("total", 0)
    col_a, col_b, col_c = st.columns(3)
    col_a.metric("Faux positifs", feedback.get("false_positive", 0))
    col_b.metric("Confirmés", feedback.get("confirmed", 0))
    col_c.metric("Taux de faux positifs", _percent(feedback.get("false_positive_rate")))

    if total == 0:
        st.info(
            "Aucun verdict enregistré. Le statut d’une alerte passé à « Faux positif » ou "
            "« Confirmé » alimente automatiquement ces compteurs."
        )
        return

    by_model = feedback.get("by_model", {})
    if by_model:
        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "Modèle": model,
                        "Faux positifs": stats.get("false_positive", 0),
                        "Confirmés": stats.get("confirmed", 0),
                    }
                    for model, stats in by_model.items()
                ]
            ),
            hide_index=True,
            use_container_width=True,
        )


def _render_feedback_log() -> None:
    st.markdown("##### Derniers verdicts")
    try:
        items = get_ml_feedback(limit=50)
    except APIError as exc:
        render_error(str(exc))
        return
    if not items:
        st.info("Aucun verdict pour le moment.")
        return
    st.dataframe(
        pd.DataFrame(
            [
                {
                    "N°": item["id"],
                    "Alerte": item["alert_id"] if item["alert_id"] is not None else "—",
                    "Module": _MODULE_LABELS.get(item["module"], item["module"]),
                    "Modèle": f"{item['model_name'] or '?'}@{item['model_version'] or '?'}",
                    "Verdict": _VERDICT_LABELS.get(item["verdict"], item["verdict"]),
                    "Date": item["created_at"],
                }
                for item in items
            ]
        ),
        hide_index=True,
        use_container_width=True,
    )


def _percent(value) -> str:
    return "—" if value is None else f"{round(value * 100, 1)} %"


def _delta(value) -> str:
    if value is None:
        return "Données insuffisantes"
    sign = "+" if value > 0 else ""
    return f"{sign}{round(value * 100, 1)} pts"
