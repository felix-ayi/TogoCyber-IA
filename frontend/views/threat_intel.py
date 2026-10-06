"""Threat-intelligence indicator store: local IOC management and lookup (SOC only)."""

import pandas as pd
import streamlit as st

from frontend.components.error_state import render_error
from frontend.components.export_button import render_export_button
from frontend.services.api_client import (
    APIError,
    add_ioc_tag,
    create_ioc,
    delete_ioc,
    get_iocs,
    lookup_ioc,
    remove_ioc_tag,
    update_ioc,
)

_TYPE_LABELS = {
    "ip": "Adresse IP",
    "domain": "Nom de domaine",
    "url": "URL",
    "hash": "Empreinte",
    "email": "Adresse e-mail",
}
_STATUS_LABELS = {"ACTIVE": "Actif", "EXPIRED": "Expiré", "REVOKED": "Révoqué"}
_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def render() -> None:
    st.subheader("Threat Intelligence · indicateurs (IOC)")
    st.caption(
        "Base locale d’indicateurs de compromission gérée par les analystes. "
        "Aucun flux externe n’est connecté : les valeurs proviennent uniquement de ce "
        "que votre équipe ajoute manuellement."
    )
    user = st.session_state.get("auth_user", {})
    if user.get("role") not in {"Admin", "Analyst"}:
        st.warning("Cette section est réservée aux analystes et administrateurs.")
        return

    _render_lookup()
    st.divider()
    _render_create_form()
    st.divider()
    _render_table()


def _render_lookup() -> None:
    st.markdown("##### Rechercher un observable")
    with st.form("ioc_lookup_form"):
        value = st.text_input(
            "Valeur (IP, domaine, URL, empreinte ou e-mail)",
            max_chars=2048,
            key="ioc_lookup_value",
        )
        submitted = st.form_submit_button("Rechercher dans la base locale")
    if not submitted:
        return
    if not value.strip():
        st.warning("Saisissez une valeur à rechercher.")
        return
    try:
        result = lookup_ioc(value.strip())
    except APIError as exc:
        render_error(str(exc))
        return

    matches = result.get("matches", [])
    external = result.get("external_sources", [])
    if not external:
        st.info(
            "Sources externes de threat intelligence (VirusTotal, AbuseIPDB, SIEM…) : "
            "non configurées. Seule la base locale est interrogée."
        )
    if not matches:
        st.success("Aucun indicateur actif ne correspond à cette valeur dans la base locale.")
        return
    st.warning(f"{len(matches)} indicateur(s) actif(s) correspondant(s) dans la base locale.")
    st.dataframe(
        pd.DataFrame(
            [
                {
                    "N°": m["id"],
                    "Type": _TYPE_LABELS.get(m["type"], m["type"]),
                    "Valeur": m["value"],
                    "Sévérité": m["severity"],
                    "Confiance": f"{m['confidence']}/100",
                    "Statut": _STATUS_LABELS.get(m["status"], m["status"]),
                }
                for m in matches
            ]
        ),
        hide_index=True,
        use_container_width=True,
    )


def _render_create_form() -> None:
    st.markdown("##### Ajouter un indicateur")
    with st.form("ioc_create_form", clear_on_submit=True):
        col_a, col_b = st.columns(2)
        ioc_type = col_a.selectbox(
            "Type", options=list(_TYPE_LABELS), format_func=lambda t: _TYPE_LABELS[t], key="ioc_new_type"
        )
        severity = col_b.selectbox("Sévérité", options=_SEVERITIES, key="ioc_new_severity")
        value = st.text_input("Valeur", max_chars=2048, key="ioc_new_value")
        confidence = st.slider("Confiance (0-100)", 0, 100, 70, key="ioc_new_confidence")
        source = st.text_input(
            "Source (origine de l’indicateur, ex. « investigation interne »)",
            max_chars=255,
            key="ioc_new_source",
        )
        description = st.text_area("Description", max_chars=2000, key="ioc_new_description")
        tags = st.text_input("Tags (séparés par des virgules)", max_chars=200, key="ioc_new_tags")
        submitted = st.form_submit_button("Ajouter l’indicateur", type="primary")

    if not submitted:
        return
    if not value.strip():
        st.warning("Saisissez une valeur pour l’indicateur.")
        return
    tag_list = [t.strip() for t in tags.split(",") if t.strip()]
    try:
        create_ioc(
            {
                "type": ioc_type,
                "value": value.strip(),
                "severity": severity,
                "confidence": int(confidence),
                "source": source.strip() or None,
                "description": description.strip() or None,
                "tags": tag_list,
            }
        )
        st.success("Indicateur ajouté.")
        st.rerun()
    except APIError as exc:
        render_error(str(exc))


def _render_table() -> None:
    st.markdown("##### Indicateurs enregistrés")
    filter_type = st.selectbox(
        "Filtrer par type",
        options=["all", *_TYPE_LABELS],
        format_func=lambda t: "Tous les types" if t == "all" else _TYPE_LABELS[t],
        key="ioc_filter_type",
    )
    filter_status = st.selectbox(
        "Filtrer par statut",
        options=["all", *_STATUS_LABELS],
        format_func=lambda s: "Tous les statuts" if s == "all" else _STATUS_LABELS[s],
        key="ioc_filter_status",
    )
    render_export_button(
        "iocs",
        "Exporter ces indicateurs en CSV",
        params={
            "type": None if filter_type == "all" else filter_type,
            "status": None if filter_status == "all" else filter_status,
        },
        key="export_iocs",
    )
    try:
        items = get_iocs(
            ioc_type=None if filter_type == "all" else filter_type,
            status=None if filter_status == "all" else filter_status,
        )
    except APIError as exc:
        render_error(str(exc))
        return

    if not items:
        st.info("Aucun indicateur ne correspond à ces filtres.")
        return

    st.dataframe(
        pd.DataFrame(
            [
                {
                    "N°": item["id"],
                    "Type": _TYPE_LABELS.get(item["type"], item["type"]),
                    "Valeur": item["value"],
                    "Sévérité": item["severity"],
                    "Confiance": f"{item['confidence']}/100",
                    "Statut": _STATUS_LABELS.get(item["status"], item["status"]),
                    "Tags": ", ".join(item["tags"]) or "—",
                    "Créé le": item["created_at"],
                }
                for item in items
            ]
        ),
        hide_index=True,
        use_container_width=True,
    )

    _render_item_actions(items)


def _render_item_actions(items: list[dict]) -> None:
    selected_id = st.number_input(
        "Identifiant de l’indicateur à gérer",
        min_value=1,
        step=1,
        value=items[0]["id"],
        key="ioc_selected_id",
    )
    selected = next((item for item in items if item["id"] == int(selected_id)), None)
    if selected is None:
        st.caption("Sélectionnez un indicateur présent dans la liste ci-dessus.")
        return

    st.divider()
    st.markdown(f"**Indicateur #{selected['id']} — {selected['value']}**")

    with st.form("ioc_update_form"):
        col_a, col_b = st.columns(2)
        new_severity = col_a.selectbox(
            "Sévérité",
            options=_SEVERITIES,
            index=_SEVERITIES.index(selected["severity"]) if selected["severity"] in _SEVERITIES else 0,
            key="ioc_edit_severity",
        )
        new_status = col_b.selectbox(
            "Statut",
            options=list(_STATUS_LABELS),
            index=list(_STATUS_LABELS).index(selected["status"])
            if selected["status"] in _STATUS_LABELS
            else 0,
            format_func=lambda s: _STATUS_LABELS[s],
            key="ioc_edit_status",
        )
        new_confidence = st.slider(
            "Confiance (0-100)", 0, 100, int(selected["confidence"]), key="ioc_edit_confidence"
        )
        update_submitted = st.form_submit_button("Mettre à jour")
    if update_submitted:
        try:
            update_ioc(
                int(selected_id),
                {
                    "severity": new_severity,
                    "status": new_status,
                    "confidence": int(new_confidence),
                },
            )
            st.success("Indicateur mis à jour.")
            st.rerun()
        except APIError as exc:
            render_error(str(exc))

    with st.form("ioc_tag_form", clear_on_submit=True):
        new_tag = st.text_input("Ajouter un tag", max_chars=48, key="ioc_new_tag")
        tag_submitted = st.form_submit_button("Ajouter le tag")
    if tag_submitted and new_tag.strip():
        try:
            add_ioc_tag(int(selected_id), new_tag.strip())
            st.rerun()
        except APIError as exc:
            render_error(str(exc))
    if selected["tags"]:
        for tag in selected["tags"]:
            if st.button(f"Retirer « {tag} »", key=f"ioc_rm_tag_{tag}"):
                try:
                    remove_ioc_tag(int(selected_id), tag)
                    st.rerun()
                except APIError as exc:
                    render_error(str(exc))

    if st.button("Supprimer définitivement l’indicateur", key="ioc_delete", type="secondary"):
        try:
            delete_ioc(int(selected_id))
            st.success("Indicateur supprimé.")
            st.rerun()
        except APIError as exc:
            render_error(str(exc))
