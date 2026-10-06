import pandas as pd
import streamlit as st

from frontend.components.error_state import render_error
from frontend.components.export_button import render_export_button
from frontend.services.api_client import (
    APIError,
    add_alert_comment,
    add_alert_tag,
    assign_alert,
    get_alert_comments,
    get_alert_events,
    get_alert_timeline,
    get_alerts,
    get_users,
    remove_alert_tag,
    update_alert,
)

_STATUS_LABELS = {
    "NEW": "Nouvelle",
    "INVESTIGATING": "En investigation",
    "CONFIRMED": "Confirmée",
    "FALSE_POSITIVE": "Faux positif",
    "RESOLVED": "Résolue",
    "CLOSED": "Clôturée",
}
_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM"]
_TIMELINE_ICONS = {
    "detection": "⌁",
    "alert_status": "🔔",
    "comment": "✎",
    "incident_status": "⚑",
    "audit": "▤",
}


def _next_statuses(current: str) -> list[str]:
    allowed = {
        "NEW": ["INVESTIGATING", "FALSE_POSITIVE", "CLOSED"],
        "INVESTIGATING": ["CONFIRMED", "FALSE_POSITIVE", "RESOLVED", "CLOSED", "NEW"],
        "CONFIRMED": ["INVESTIGATING", "RESOLVED"],
        "FALSE_POSITIVE": ["INVESTIGATING", "CLOSED"],
        "RESOLVED": ["INVESTIGATING", "CLOSED"],
        "CLOSED": ["INVESTIGATING"],
    }
    return allowed.get(current, [])


def render() -> None:
    st.subheader("File d’alertes (SOC)")
    st.caption(
        "Alertes générées automatiquement par les détections de risque moyen à critique. "
        "Réservé aux analystes et administrateurs. Les scores restent indicatifs."
    )
    user = st.session_state.get("auth_user", {})
    if user.get("role") not in {"Admin", "Analyst"}:
        st.warning("Cette section est réservée aux analystes et administrateurs.")
        return

    filter_status = st.selectbox(
        "Filtrer par statut",
        options=["all", *_STATUS_LABELS],
        format_func=lambda s: "Tous les statuts" if s == "all" else _STATUS_LABELS[s],
        key="alert_filter_status",
    )
    filter_severity = st.selectbox(
        "Filtrer par sévérité",
        options=["all", *_SEVERITY_ORDER],
        format_func=lambda s: "Toutes les sévérités" if s == "all" else s,
        key="alert_filter_severity",
    )

    render_export_button(
        "alerts",
        "Exporter ces alertes en CSV",
        params={
            "status": None if filter_status == "all" else filter_status,
            "severity": None if filter_severity == "all" else filter_severity,
        },
        key="export_alerts",
    )

    try:
        items = get_alerts(
            status=None if filter_status == "all" else filter_status,
            severity=None if filter_severity == "all" else filter_severity,
        )
    except APIError as exc:
        render_error(str(exc))
        return

    if not items:
        st.info("Aucune alerte ne correspond à ces filtres.")
        return

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
                    "Tags": ", ".join(item["tags"]) or "—",
                }
                for item in items
            ]
        ),
        hide_index=True,
        use_container_width=True,
    )

    selected_id = st.number_input(
        "Identifiant de l’alerte à traiter",
        min_value=1,
        step=1,
        value=items[0]["id"],
        key="alert_selected_id",
    )
    selected = next((item for item in items if item["id"] == int(selected_id)), None)
    if selected is None:
        st.caption("Sélectionnez une alerte présente dans la liste ci-dessus.")
        return

    st.divider()
    st.markdown(f"**Alerte #{selected['id']} — {selected['title']}**")

    with st.form("alert_status_form"):
        options = _next_statuses(selected["status"])
        if not options:
            st.caption("Aucune transition disponible depuis ce statut.")
            target_status = None
        else:
            target_status = st.selectbox(
                "Nouveau statut",
                options=options,
                format_func=lambda s: _STATUS_LABELS[s],
                key="alert_target_status",
            )
        note = st.text_area("Note de transition (optionnelle)", key="alert_note", max_chars=2000)
        status_submitted = st.form_submit_button("Mettre à jour le statut")
    if status_submitted and target_status is not None:
        try:
            update_alert(int(selected_id), target_status, note.strip() or None)
            st.success("Statut de l’alerte mis à jour.")
            st.rerun()
        except APIError as exc:
            render_error(str(exc))

    try:
        people = get_users()
    except APIError:
        people = []
    if people:
        assign_options = {0: "— Non assignée —", **{p["id"]: f"{p['email']} ({p['role']})" for p in people}}
        current_assignee = selected["assignee_user_id"] or 0
        with st.form("alert_assign_form"):
            chosen = st.selectbox(
                "Assigner à",
                options=list(assign_options),
                index=list(assign_options).index(current_assignee)
                if current_assignee in assign_options
                else 0,
                format_func=lambda k: assign_options[k],
                key="alert_assignee",
            )
            assign_submitted = st.form_submit_button("Assigner")
        if assign_submitted:
            try:
                assign_alert(int(selected_id), None if chosen == 0 else int(chosen))
                st.success("Assignation mise à jour.")
                st.rerun()
            except APIError as exc:
                render_error(str(exc))

    with st.form("alert_tag_form", clear_on_submit=True):
        new_tag = st.text_input("Ajouter un tag", max_chars=48, key="alert_new_tag")
        tag_submitted = st.form_submit_button("Ajouter le tag")
    if tag_submitted and new_tag.strip():
        try:
            add_alert_tag(int(selected_id), new_tag.strip())
            st.rerun()
        except APIError as exc:
            render_error(str(exc))
    if selected["tags"]:
        for tag in selected["tags"]:
            if st.button(f"Retirer « {tag} »", key=f"alert_rm_tag_{tag}"):
                try:
                    remove_alert_tag(int(selected_id), tag)
                    st.rerun()
                except APIError as exc:
                    render_error(str(exc))

    with st.form("alert_comment_form", clear_on_submit=True):
        comment_body = st.text_area("Ajouter un commentaire", key="alert_comment_body", max_chars=4000)
        comment_submitted = st.form_submit_button("Publier le commentaire")
    if comment_submitted and comment_body.strip():
        try:
            add_alert_comment(int(selected_id), comment_body.strip())
            st.rerun()
        except APIError as exc:
            render_error(str(exc))

    try:
        comments = get_alert_comments(int(selected_id))
    except APIError as exc:
        render_error(str(exc))
        comments = []
    if comments:
        st.caption("Commentaires")
        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "Date": c["created_at"],
                        "Auteur (ID)": c["author_user_id"] or "Système",
                        "Commentaire": c["body"],
                    }
                    for c in comments
                ]
            ),
            hide_index=True,
            use_container_width=True,
        )

    try:
        events = get_alert_events(int(selected_id))
    except APIError as exc:
        render_error(str(exc))
        events = []
    if events:
        st.caption("Journal des transitions")
        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "Date": e["created_at"],
                        "De": _STATUS_LABELS.get(e["previous_status"], "Création")
                        if e["previous_status"]
                        else "Création",
                        "Vers": _STATUS_LABELS[e["new_status"]],
                        "Acteur (ID)": e["actor_user_id"] or "Système",
                        "Note": e["note"] or "—",
                    }
                    for e in events
                ]
            ),
            hide_index=True,
            use_container_width=True,
        )

    st.divider()
    st.markdown("**Chronologie d’investigation**")
    st.caption(
        "Détection d’origine, transitions de l’alerte, commentaires, incident lié et "
        "journal d’audit, fusionnés en une seule frise chronologique."
    )
    try:
        timeline = get_alert_timeline(int(selected_id))
    except APIError as exc:
        render_error(str(exc))
        timeline = []
    if not timeline:
        st.info("Aucun événement d’investigation pour cette alerte.")
    else:
        for event in timeline:
            icon = _TIMELINE_ICONS.get(event["kind"], "•")
            actor = event.get("actor_email") or (
                f"utilisateur #{event['actor_user_id']}" if event.get("actor_user_id") else "Système"
            )
            with st.container(border=True):
                st.markdown(f"{icon} **{event['title']}** · {event['timestamp']}")
                if event.get("detail"):
                    st.caption(event["detail"])
                st.caption(f"Auteur : {actor}")

