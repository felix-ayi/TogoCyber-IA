"""External integration status and the local notification outbox (SOC only)."""

import pandas as pd
import streamlit as st

from frontend.components.error_state import render_error
from frontend.services.api_client import (
    APIError,
    dispatch_notifications,
    get_integrations,
    get_notification_counts,
    get_notifications,
)

_CATEGORY_LABELS = {
    "network_sensor": "Capteur réseau",
    "ids": "IDS/IPS",
    "log_ingest": "Ingestion de journaux",
    "threat_intel": "Threat intelligence",
    "siem": "SIEM",
    "notification": "Canal de notification",
}
_STATUS_LABELS = {"configured": "Configuré", "not_configured": "Non configuré"}
_DELIVERY_LABELS = {
    "not_configured": "Non configuré",
    "sent": "Envoyé",
    "failed": "Échec",
}
_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def render() -> None:
    st.subheader("Intégrations & notifications")
    st.caption(
        "État réel des connecteurs externes. Une source non configurée n’est jamais "
        "simulée : aucune donnée fictive de Zeek, Suricata, VirusTotal, AbuseIPDB ou "
        "d’un SIEM n’est affichée. La file de notifications conserve les messages "
        "générés par de vraies alertes, en attente d’un canal de diffusion."
    )
    user = st.session_state.get("auth_user", {})
    if user.get("role") not in {"Admin", "Analyst"}:
        st.warning("Cette section est réservée aux analystes et administrateurs.")
        return

    _render_adapters()
    st.divider()
    _render_notifications()


def _render_adapters() -> None:
    st.markdown("##### Connecteurs externes")
    try:
        data = get_integrations()
    except APIError as exc:
        render_error(str(exc))
        return

    col_a, col_b = st.columns(2)
    col_a.metric("Connecteurs configurés", data.get("configured", 0))
    col_b.metric("Non configurés", data.get("not_configured", 0))

    adapters = data.get("adapters", [])
    if not adapters:
        st.info("Aucun connecteur déclaré.")
        return
    st.dataframe(
        pd.DataFrame(
            [
                {
                    "Source": item["name"],
                    "Catégorie": _CATEGORY_LABELS.get(item["category"], item["category"]),
                    "État": _STATUS_LABELS.get(item["status"], item["status"]),
                    "Configuration requise": ", ".join(item["required_env"]) or "—",
                    "Détail": item["detail"],
                }
                for item in adapters
            ]
        ),
        hide_index=True,
        use_container_width=True,
    )


def _render_notifications() -> None:
    st.markdown("##### File de notifications (outbox)")
    try:
        counts = get_notification_counts()
    except APIError as exc:
        render_error(str(exc))
        return

    col_a, col_b = st.columns(2)
    col_a.metric("Messages en file", counts.get("total", 0))
    col_b.metric("Non diffusés (aucun canal)", counts.get("not_configured", 0))

    if counts.get("not_configured", 0) > 0 and counts.get("sent", 0) == 0:
        st.info(
            "Aucun canal de diffusion (e-mail, Slack, webhook) n’est configuré : les "
            "messages restent en file d’attente et ne sont pas envoyés."
        )

    if st.button("Tenter la diffusion de la file", key="notif_dispatch"):
        try:
            result = dispatch_notifications()
        except APIError as exc:
            render_error(str(exc))
        else:
            if result.get("configured_channel") is None:
                st.warning(result.get("detail", "Aucun canal configuré."))
            else:
                st.success(
                    f"Canal « {result['configured_channel']} » : "
                    f"{result['sent']} envoyé(s), {result['failed']} échec(s)."
                )
            st.rerun()

    severity = st.selectbox(
        "Filtrer par sévérité",
        options=["all", *_SEVERITIES],
        format_func=lambda s: "Toutes" if s == "all" else s,
        key="notif_filter_severity",
    )
    try:
        items = get_notifications(severity=None if severity == "all" else severity)
    except APIError as exc:
        render_error(str(exc))
        return
    if not items:
        st.info("Aucune notification pour ce filtre.")
        return
    st.dataframe(
        pd.DataFrame(
            [
                {
                    "N°": item["id"],
                    "Événement": item["event_type"],
                    "Sévérité": item["severity"],
                    "Sujet": item["subject"],
                    "Canal": item["channel"],
                    "Diffusion": _DELIVERY_LABELS.get(
                        item["delivery_status"], item["delivery_status"]
                    ),
                    "Date": item["created_at"],
                }
                for item in items
            ]
        ),
        hide_index=True,
        use_container_width=True,
    )
