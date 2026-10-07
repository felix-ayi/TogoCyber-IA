"""SOC dashboard: live triage posture computed from real alert and incident rows."""

import pandas as pd
import streamlit as st

from frontend.components.error_state import render_error
from frontend.services.api_client import APIError, get_alerts, get_soc_overview

_STATUS_LABELS = {
    "NEW": "Nouvelle",
    "INVESTIGATING": "En investigation",
    "CONFIRMED": "Confirmée",
    "FALSE_POSITIVE": "Faux positif",
    "RESOLVED": "Résolue",
    "CLOSED": "Clôturée",
}
_INCIDENT_STATUS_LABELS = {
    "OPEN": "Ouvert",
    "ACKNOWLEDGED": "Pris en charge",
    "RESOLVED": "Résolu",
}
_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM"]


def _navigate(page: str) -> None:
    st.session_state["main_navigation"] = page


def render() -> None:
    st.subheader("Tableau de bord SOC")
    st.caption(
        "Vue d’ensemble calculée en temps réel depuis les alertes et incidents réellement "
        "enregistrés. Réservé aux analystes et administrateurs. Aucun chiffre n’est simulé."
    )
    user = st.session_state.get("auth_user", {})
    if user.get("role") not in {"Admin", "Analyst"}:
        st.warning("Cette section est réservée aux analystes et administrateurs.")
        return

    try:
        overview = get_soc_overview()
    except APIError as exc:
        render_error(str(exc))
        return

    alerts = overview["alerts"]
    incidents = overview["incidents"]

    st.markdown(
        """
        <div class="tc-soc-summary">
            <div class="tc-soc-summary-copy">
                <span class="tc-soc-summary-kicker">VUE OPÉRATIONNELLE</span>
                <h3>Command center · vigilance active</h3>
            </div>
            <div class="tc-soc-summary-badges">
                <span>Flux en temps réel</span>
                <span>Historique réel</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    first, second, third, fourth = st.columns(4)
    with first:
        st.metric("Alertes ouvertes", alerts["open"])
    with second:
        st.metric("Non assignées", alerts["unassigned_open"])
    with third:
        st.metric("Critiques ouvertes", alerts["critical_open"])
    with fourth:
        st.metric("Incidents actifs", incidents["active"])

    st.divider()
    left, right = st.columns(2)
    with left:
        st.markdown("##### Alertes par statut")
        st.dataframe(
            pd.DataFrame(
                [
                    {"Statut": _STATUS_LABELS[status], "Nombre": alerts["by_status"][status]}
                    for status in _STATUS_LABELS
                ]
            ),
            hide_index=True,
            use_container_width=True,
        )
    with right:
        st.markdown("##### Alertes par sévérité")
        st.dataframe(
            pd.DataFrame(
                [
                    {"Sévérité": severity, "Nombre": alerts["by_severity"][severity]}
                    for severity in _SEVERITY_ORDER
                ]
            ),
            hide_index=True,
            use_container_width=True,
        )
        st.markdown("##### Incidents par statut")
        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "Statut": _INCIDENT_STATUS_LABELS[status],
                        "Nombre": incidents["by_status"][status],
                    }
                    for status in _INCIDENT_STATUS_LABELS
                ]
            ),
            hide_index=True,
            use_container_width=True,
        )

    st.divider()
    st.markdown("##### Alertes prioritaires")
    st.caption("Alertes ouvertes de sévérité haute ou critique, les plus récentes d’abord.")
    try:
        critical = get_alerts(severity="CRITICAL", limit=10)
        high = get_alerts(severity="HIGH", limit=10)
    except APIError as exc:
        render_error(str(exc))
        critical, high = [], []

    priority = [
        item
        for item in (*critical, *high)
        if item["status"] in {"NEW", "INVESTIGATING", "CONFIRMED"}
    ]
    seen: set[int] = set()
    unique_priority = []
    for item in priority:
        if item["id"] not in seen:
            seen.add(item["id"])
            unique_priority.append(item)

    if not unique_priority:
        st.info("Aucune alerte ouverte de sévérité haute ou critique pour le moment.")
    else:
        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "N°": item["id"],
                        "Créée le": item["created_at"],
                        "Titre": item["title"],
                        "Sévérité": item["severity"],
                        "Risque": f"{item['risk_score']}/100",
                        "Statut": _STATUS_LABELS[item["status"]],
                        "Assignée": item["assignee_user_id"] or "—",
                    }
                    for item in unique_priority
                ]
            ),
            hide_index=True,
            use_container_width=True,
        )

    col_a, col_b = st.columns(2)
    col_a.button(
        "🔔  Ouvrir la file d’alertes",
        key="soc_open_alerts",
        width="stretch",
        on_click=_navigate,
        args=("Alertes (SOC)",),
    )
    col_b.button(
        "⚑  Ouvrir les incidents",
        key="soc_open_incidents",
        width="stretch",
        on_click=_navigate,
        args=("Incidents",),
    )
