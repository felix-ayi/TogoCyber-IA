import pandas as pd
import streamlit as st

from frontend.components.error_state import render_error
from frontend.components.export_button import render_export_button
from frontend.services.api_client import (
    APIError,
    get_incident_events,
    get_incidents,
    update_incident,
)

_STATUS_LABELS = {
    "OPEN": "Ouvert",
    "ACKNOWLEDGED": "Pris en charge",
    "RESOLVED": "Résolu",
}


def render() -> None:
    st.subheader("Centre d’incidents")
    st.caption(
        "Les scores élevés créent un incident de suivi ; ils restent indicatifs et ne prouvent pas une compromission."
    )
    st.markdown(
        """
        <div class="tc-ops-summary">
          <div>
            <span class="tc-soc-summary-kicker">INCIDENTS</span>
            <h3>Suivi des cas à traiter</h3>
          </div>
          <div class="tc-ops-summary-badges">
            <span>État réel</span>
            <span>Historique des transitions</span>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    user = st.session_state.get("auth_user", {})
    can_manage = user.get("role") in {"Admin", "Analyst"}
    try:
        items = get_incidents()
    except APIError as exc:
        render_error(str(exc))
        return

    st.markdown(
        """
        <div class="tc-filter-shell">
          <div>
            <span class="tc-soc-summary-kicker">FILTRES</span>
            <strong>Vue d’incidents</strong>
          </div>
          <span class="tc-filter-tag">OPÉRATION</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if can_manage:
        render_export_button(
            "incidents",
            "Exporter ces incidents en CSV",
            key="export_incidents",
        )

    if not items:
        st.info("Aucun incident de sévérité élevée ou critique à suivre.")
    else:
        display_items = [
            {
                "N°": item["id"],
                "Créé le": item["created_at"],
                "Type": "Réseau" if item["module"] == "network" else "Phishing / SMS",
                "Détection": item["prediction"],
                "Risque": f"{item['risk_score']}/100",
                "Sévérité": item["severity"],
                "État": _STATUS_LABELS[item["status"]],
                **({"Compte": item["owner_user_id"]} if can_manage else {}),
            }
            for item in items
        ]
        st.dataframe(pd.DataFrame(display_items), hide_index=True, use_container_width=True)

        selected_id = st.number_input(
            "Identifiant de l’incident à consulter",
            min_value=1,
            step=1,
            value=items[0]["id"],
            key="incident_event_id",
        )
        try:
            events = get_incident_events(int(selected_id))
            if events:
                st.caption("Journal des transitions")
                st.dataframe(
                    pd.DataFrame(
                        [
                            {
                                "Date": event["created_at"],
                                "État précédent": _STATUS_LABELS.get(event["previous_status"], "Création"),
                                "Nouvel état": _STATUS_LABELS[event["new_status"]],
                                "Utilisateur responsable": event["actor_user_id"] or "Système",
                            }
                            for event in events
                        ]
                    ),
                    hide_index=True,
                    use_container_width=True,
                )
        except APIError as exc:
            render_error(str(exc))

        if can_manage:
            with st.form("incident_status_form"):
                target_status = st.selectbox(
                    "Nouvel état",
                    options=list(_STATUS_LABELS),
                    format_func=lambda state: _STATUS_LABELS[state],
                )
                submitted = st.form_submit_button("Mettre à jour l’incident")
            if submitted:
                try:
                    update_incident(int(selected_id), target_status)
                    st.success("État de l’incident mis à jour.")
                    st.rerun()
                except APIError as exc:
                    render_error(str(exc))
