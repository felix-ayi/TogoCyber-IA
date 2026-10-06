import pandas as pd
import streamlit as st

from frontend.components.error_state import render_error
from frontend.components.export_button import render_export_button
from frontend.services.api_client import APIError, get_audit_events

_ACTION_LABELS = {
    "auth.registered": "Inscription",
    "auth.login.succeeded": "Connexion réussie",
    "auth.login.failed": "Connexion refusée",
    "auth.login.rate_limited": "Connexion limitée",
    "auth.logout": "Déconnexion",
    "user.provisioned": "Compte créé par un administrateur",
    "user.role_changed": "Rôle modifié",
    "user.activated": "Compte activé",
    "user.deactivated": "Compte désactivé",
    "user.deleted": "Compte supprimé",
    "user.password_reset": "Mot de passe réinitialisé",
    "incident.status_changed": "État d’incident modifié",
    "alert.status_changed": "Statut d’alerte modifié",
    "alert.assigned": "Alerte assignée",
    "ioc.created": "Indicateur (IOC) créé",
    "ioc.updated": "Indicateur (IOC) modifié",
    "ioc.deleted": "Indicateur (IOC) supprimé",
    "rule.created": "Règle de détection créée",
    "rule.updated": "Règle de détection modifiée",
    "rule.deleted": "Règle de détection supprimée",
    "correlation.run": "Corrélation exécutée",
    "playbook.created": "Playbook créé",
    "playbook.updated": "Playbook modifié",
    "playbook.deleted": "Playbook supprimé",
}


def render() -> None:
    st.subheader("Journal d’audit de sécurité")
    st.caption(
        "Journal append-only des opérations d’authentification, d’administration et de gestion des incidents. "
        "Aucun mot de passe, jeton ou contenu analysé n’y figure."
    )
    selected_action = st.selectbox(
        "Filtrer par opération",
        options=["all", *_ACTION_LABELS],
        format_func=lambda action: "Toutes les opérations" if action == "all" else _ACTION_LABELS[action],
    )
    render_export_button(
        "audit",
        "Exporter ce journal en CSV",
        params={"action": None if selected_action == "all" else selected_action},
        key="export_audit",
    )
    try:
        events = get_audit_events(action=None if selected_action == "all" else selected_action)
    except APIError as exc:
        render_error(str(exc))
        return
    if not events:
        st.info("Aucune opération d’audit n’est enregistrée pour ce filtre.")
        return
    st.dataframe(
        pd.DataFrame(
            [
                {
                    "Date": event["created_at"],
                    "Opération": _ACTION_LABELS.get(event["action"], event["action"]),
                    "Résultat": "Réussie" if event["outcome"] == "success" else "Refusée",
                    "Compte opérateur (ID)": event["actor_user_id"] or "Anonyme",
                    "Cible": (
                        f"{event['target_type']} #{event['target_id']}"
                        if event["target_type"] is not None
                        else "—"
                    ),
                }
                for event in events
            ]
        ),
        hide_index=True,
        use_container_width=True,
    )
