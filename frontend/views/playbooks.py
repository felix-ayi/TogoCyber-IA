"""Response playbook authoring and review (SOC only)."""

import pandas as pd
import streamlit as st

from frontend.components.error_state import render_error
from frontend.services.api_client import (
    APIError,
    create_playbook,
    delete_playbook,
    get_playbooks,
    update_playbook,
)

_MODULE_LABELS = {"network": "Réseau", "phishing": "Phishing/SMS", "any": "Tous modules"}
_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM"]


def render() -> None:
    st.subheader("Playbooks de réponse")
    st.caption(
        "Procédures de réponse rédigées par les analystes, ordonnées par étape et "
        "rattachées à un module et à une sévérité minimale. Ce sont des guides "
        "documentaires : aucune action automatique n’est exécutée sur des systèmes externes."
    )
    user = st.session_state.get("auth_user", {})
    if user.get("role") not in {"Admin", "Analyst"}:
        st.warning("Cette section est réservée aux analystes et administrateurs.")
        return

    _render_create_form()
    st.divider()
    _render_list()


def _render_create_form() -> None:
    st.markdown("##### Créer un playbook")
    with st.form("playbook_create_form", clear_on_submit=True):
        name = st.text_input("Nom", max_chars=200, key="pb_new_name")
        col_a, col_b = st.columns(2)
        module = col_a.selectbox(
            "Module", options=list(_MODULE_LABELS),
            format_func=lambda m: _MODULE_LABELS[m], key="pb_new_module",
        )
        min_severity = col_b.selectbox(
            "Sévérité minimale", options=_SEVERITIES, key="pb_new_severity"
        )
        description = st.text_area("Description", max_chars=2000, key="pb_new_description")
        steps_text = st.text_area(
            "Étapes (une par ligne)", height=160, key="pb_new_steps"
        )
        submitted = st.form_submit_button("Créer le playbook", type="primary")

    if not submitted:
        return
    if not name.strip():
        st.warning("Saisissez un nom de playbook.")
        return
    steps = [line.strip() for line in steps_text.splitlines() if line.strip()]
    try:
        create_playbook(
            {
                "name": name.strip(),
                "module": module,
                "min_severity": min_severity,
                "description": description.strip() or None,
                "steps": steps,
            }
        )
        st.success("Playbook créé.")
        st.rerun()
    except APIError as exc:
        render_error(str(exc))


def _render_list() -> None:
    st.markdown("##### Playbooks existants")
    filter_module = st.selectbox(
        "Filtrer par module",
        options=["all", *_MODULE_LABELS],
        format_func=lambda m: "Tous les modules" if m == "all" else _MODULE_LABELS[m],
        key="pb_filter_module",
    )
    try:
        items = get_playbooks(module=None if filter_module == "all" else filter_module)
    except APIError as exc:
        render_error(str(exc))
        return

    if not items:
        st.info("Aucun playbook ne correspond à ce filtre.")
        return

    st.dataframe(
        pd.DataFrame(
            [
                {
                    "N°": item["id"],
                    "Nom": item["name"],
                    "Module": _MODULE_LABELS.get(item["module"], item["module"]),
                    "Sév. min.": item["min_severity"],
                    "Étapes": len(item["steps"]),
                    "Maj": item["updated_at"],
                }
                for item in items
            ]
        ),
        hide_index=True,
        use_container_width=True,
    )

    _render_detail(items)


def _render_detail(items: list[dict]) -> None:
    playbook_id = st.selectbox(
        "Playbook à consulter / gérer",
        options=[item["id"] for item in items],
        format_func=lambda pid: f"#{pid} — " + next(p["name"] for p in items if p["id"] == pid),
        key="pb_selected",
    )
    selected = next(item for item in items if item["id"] == playbook_id)

    st.markdown(f"**{selected['name']}**")
    if selected.get("description"):
        st.write(selected["description"])
    st.caption(
        f"Module : {_MODULE_LABELS.get(selected['module'], selected['module'])} · "
        f"Sévérité minimale : {selected['min_severity']}"
    )
    if selected["steps"]:
        for step in selected["steps"]:
            st.markdown(f"{step['position']}. {step['instruction']}")
    else:
        st.info("Ce playbook ne contient aucune étape.")

    st.divider()
    with st.form("playbook_edit_form"):
        new_steps = st.text_area(
            "Modifier les étapes (une par ligne)",
            value="\n".join(step["instruction"] for step in selected["steps"]),
            height=160,
            key=f"pb_edit_steps_{playbook_id}",
        )
        save = st.form_submit_button("Enregistrer les étapes")
    if save:
        steps = [line.strip() for line in new_steps.splitlines() if line.strip()]
        try:
            update_playbook(playbook_id, {"steps": steps})
            st.success("Étapes mises à jour.")
            st.rerun()
        except APIError as exc:
            render_error(str(exc))

    if st.button("Supprimer le playbook", key=f"pb_delete_{playbook_id}", type="secondary"):
        try:
            delete_playbook(playbook_id)
            st.success("Playbook supprimé.")
            st.rerun()
        except APIError as exc:
            render_error(str(exc))
