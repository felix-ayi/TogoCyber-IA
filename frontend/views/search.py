"""Global SOC search across alerts, incidents, detections and audit actions."""

import pandas as pd
import streamlit as st

from frontend.components.error_state import render_error
from frontend.services.api_client import APIError, search_soc

_ALERT_STATUS_LABELS = {
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


def render() -> None:
    st.subheader("Recherche globale (SOC)")
    st.caption(
        "Recherche littérale dans les alertes (titre, tags), les incidents, les détections "
        "et les actions d’audit. Réservée aux analystes et administrateurs."
    )
    user = st.session_state.get("auth_user", {})
    if user.get("role") not in {"Admin", "Analyst"}:
        st.warning("Cette section est réservée aux analystes et administrateurs.")
        return

    with st.form("soc_search_form"):
        term = st.text_input(
            "Terme recherché",
            max_chars=200,
            placeholder="ex. phishing, alert.status_changed, network…",
            key="soc_search_term",
        )
        submitted = st.form_submit_button("Rechercher", type="primary")

    if not submitted:
        return
    if not term.strip():
        st.warning("Saisissez un terme avant de lancer la recherche.")
        return

    try:
        results = search_soc(term.strip())
    except APIError as exc:
        render_error(str(exc))
        return

    alerts = results.get("alerts", [])
    incidents = results.get("incidents", [])
    detections = results.get("detections", [])
    audit_events = results.get("audit_events", [])
    total = len(alerts) + len(incidents) + len(detections) + len(audit_events)

    if total == 0:
        st.info("Aucun résultat pour ce terme.")
        return

    st.caption(
        f"{total} résultat(s) pour « {results.get('term', term.strip())} » "
        "(jusqu’à 20 par catégorie)."
    )

    if alerts:
        st.markdown("##### Alertes")
        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "N°": a["id"],
                        "Titre": a["title"],
                        "Sévérité": a["severity"],
                        "Statut": _ALERT_STATUS_LABELS.get(a["status"], a["status"]),
                        "Créée le": a["created_at"],
                    }
                    for a in alerts
                ]
            ),
            hide_index=True,
            use_container_width=True,
        )

    if incidents:
        st.markdown("##### Incidents")
        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "N°": i["id"],
                        "Module": i["module"],
                        "Prédiction": i["prediction"],
                        "Sévérité": i["severity"] or "—",
                        "Statut": _INCIDENT_STATUS_LABELS.get(i["status"], i["status"]),
                        "Créé le": i["created_at"],
                    }
                    for i in incidents
                ]
            ),
            hide_index=True,
            use_container_width=True,
        )

    if detections:
        st.markdown("##### Détections (historique)")
        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "N°": d["id"],
                        "Module": d["module"],
                        "Prédiction": d["prediction"],
                        "Sévérité": d["severity"] or "—",
                        "Confiance": d["confidence_level"] or "—",
                        "Date": d["created_at"],
                    }
                    for d in detections
                ]
            ),
            hide_index=True,
            use_container_width=True,
        )

    if audit_events:
        st.markdown("##### Journal d’audit")
        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "N°": e["id"],
                        "Action": e["action"],
                        "Résultat": e["outcome"],
                        "Cible": f"{e['target_type']} #{e['target_id']}"
                        if e["target_type"]
                        else "—",
                        "Date": e["created_at"],
                    }
                    for e in audit_events
                ]
            ),
            hide_index=True,
            use_container_width=True,
        )
