"""Detection rules and alert correlation (SOC only)."""

import pandas as pd
import streamlit as st

from frontend.components.error_state import render_error
from frontend.services.api_client import (
    APIError,
    create_rule,
    delete_rule,
    get_findings,
    get_rules,
    run_correlation,
    update_finding_status,
    update_rule,
)

_MODULE_LABELS = {"network": "Réseau", "phishing": "Phishing/SMS", "any": "Tous modules"}
_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM"]
_FINDING_STATUS_LABELS = {"OPEN": "Ouverte", "ACKNOWLEDGED": "Prise en compte", "CLOSED": "Clôturée"}


def render() -> None:
    st.subheader("Corrélation & règles de détection")
    st.caption(
        "Les règles décrivent des seuils d’alertes (« au moins N alertes de sévérité ≥ S "
        "pour un module donné, sur une fenêtre de W minutes »). Lancer la corrélation "
        "évalue chaque règle active sur les alertes réellement présentes et crée une "
        "corrélation lorsque le seuil est atteint. Aucune alerte n’est inventée."
    )
    user = st.session_state.get("auth_user", {})
    if user.get("role") not in {"Admin", "Analyst"}:
        st.warning("Cette section est réservée aux analystes et administrateurs.")
        return

    _render_run()
    st.divider()
    _render_findings()
    st.divider()
    _render_rule_form()
    st.divider()
    _render_rules()


def _render_run() -> None:
    st.markdown("##### Moteur de corrélation")
    if st.button("Lancer la corrélation sur les alertes récentes", type="primary"):
        try:
            result = run_correlation()
        except APIError as exc:
            render_error(str(exc))
            return
        created = result.get("findings_created", [])
        if created:
            st.success(
                f"{len(created)} corrélation(s) créée(s) sur "
                f"{result.get('rules_evaluated', 0)} règle(s) évaluée(s)."
            )
        else:
            st.info(
                f"{result.get('rules_evaluated', 0)} règle(s) évaluée(s) : aucun seuil atteint "
                "sur les alertes de la fenêtre en cours."
            )
        st.rerun()


def _render_findings() -> None:
    st.markdown("##### Corrélations détectées")
    filter_status = st.selectbox(
        "Filtrer par statut",
        options=["all", *_FINDING_STATUS_LABELS],
        format_func=lambda s: "Tous les statuts" if s == "all" else _FINDING_STATUS_LABELS[s],
        key="finding_filter_status",
    )
    try:
        findings = get_findings(
            finding_status=None if filter_status == "all" else filter_status
        )
    except APIError as exc:
        render_error(str(exc))
        return

    if not findings:
        st.info("Aucune corrélation enregistrée pour ce filtre.")
        return

    rules = {rule["id"]: rule for rule in _safe_rules()}
    st.dataframe(
        pd.DataFrame(
            [
                {
                    "N°": item["id"],
                    "Règle": rules.get(item["rule_id"], {}).get("name", f"#{item['rule_id']}"),
                    "Alertes": item["alert_count"],
                    "Fenêtre": f"{item['window_start']} → {item['window_end']}",
                    "Statut": _FINDING_STATUS_LABELS.get(item["status"], item["status"]),
                    "IDs alertes": ", ".join(str(a) for a in item["alert_ids"]) or "—",
                }
                for item in findings
            ]
        ),
        hide_index=True,
        use_container_width=True,
    )

    finding_id = st.selectbox(
        "Corrélation à gérer",
        options=[item["id"] for item in findings],
        format_func=lambda fid: f"Corrélation #{fid}",
        key="finding_selected",
    )
    new_status = st.selectbox(
        "Nouveau statut", options=list(_FINDING_STATUS_LABELS),
        format_func=lambda s: _FINDING_STATUS_LABELS[s], key="finding_new_status",
    )
    if st.button("Mettre à jour le statut", key="finding_update"):
        try:
            update_finding_status(int(finding_id), new_status)
            st.success("Statut mis à jour.")
            st.rerun()
        except APIError as exc:
            render_error(str(exc))


def _safe_rules() -> list[dict]:
    try:
        return get_rules()
    except APIError:
        return []


def _render_rule_form() -> None:
    st.markdown("##### Créer une règle")
    with st.form("rule_create_form", clear_on_submit=True):
        name = st.text_input("Nom", max_chars=200, key="rule_new_name")
        col_a, col_b = st.columns(2)
        module = col_a.selectbox(
            "Module", options=list(_MODULE_LABELS),
            format_func=lambda m: _MODULE_LABELS[m], key="rule_new_module",
        )
        min_severity = col_b.selectbox(
            "Sévérité minimale", options=_SEVERITIES, key="rule_new_severity"
        )
        col_c, col_d = st.columns(2)
        threshold = col_c.number_input(
            "Seuil (nombre d’alertes)", min_value=2, max_value=100, value=3, step=1,
            key="rule_new_threshold",
        )
        window_minutes = col_d.number_input(
            "Fenêtre (minutes)", min_value=1, max_value=1440, value=60, step=5,
            key="rule_new_window",
        )
        description = st.text_area("Description", max_chars=2000, key="rule_new_description")
        submitted = st.form_submit_button("Créer la règle", type="primary")

    if not submitted:
        return
    if not name.strip():
        st.warning("Saisissez un nom de règle.")
        return
    try:
        create_rule(
            {
                "name": name.strip(),
                "module": module,
                "min_severity": min_severity,
                "threshold": int(threshold),
                "window_minutes": int(window_minutes),
                "description": description.strip() or None,
            }
        )
        st.success("Règle créée.")
        st.rerun()
    except APIError as exc:
        render_error(str(exc))


def _render_rules() -> None:
    st.markdown("##### Règles existantes")
    try:
        rules = get_rules()
    except APIError as exc:
        render_error(str(exc))
        return
    if not rules:
        st.info("Aucune règle n’a encore été créée.")
        return

    st.dataframe(
        pd.DataFrame(
            [
                {
                    "N°": rule["id"],
                    "Nom": rule["name"],
                    "Module": _MODULE_LABELS.get(rule["module"], rule["module"]),
                    "Sév. min.": rule["min_severity"],
                    "Seuil": rule["threshold"],
                    "Fenêtre (min)": rule["window_minutes"],
                    "Active": "Oui" if rule["is_active"] else "Non",
                }
                for rule in rules
            ]
        ),
        hide_index=True,
        use_container_width=True,
    )

    rule_id = st.selectbox(
        "Règle à gérer", options=[rule["id"] for rule in rules],
        format_func=lambda rid: f"#{rid} — "
        + next(r["name"] for r in rules if r["id"] == rid),
        key="rule_selected",
    )
    selected = next(rule for rule in rules if rule["id"] == rule_id)
    is_active = st.toggle("Règle active", value=bool(selected["is_active"]), key="rule_active_toggle")
    if st.button("Enregistrer l’activation", key="rule_toggle_save"):
        try:
            update_rule(rule_id, {"is_active": bool(is_active)})
            st.rerun()
        except APIError as exc:
            render_error(str(exc))
    if st.button("Supprimer la règle", key="rule_delete", type="secondary"):
        try:
            delete_rule(rule_id)
            st.success("Règle supprimée.")
            st.rerun()
        except APIError as exc:
            render_error(str(exc))
