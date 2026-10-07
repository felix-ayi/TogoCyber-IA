"""Dashboard landing page with live summaries and a quick message check."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from frontend.components.brand_identity import render_capabilities
from frontend.components.error_state import render_error
from frontend.components.result_card import render_result
from frontend.services.api_client import APIError, analyze_phishing, get_health, get_history


def _navigate(page: str) -> None:
    st.session_state["main_navigation"] = page


def _render_summary(items: list[dict]) -> None:
    network_items = [item for item in items if item.get("module") == "network"]
    suspicious = [
        item for item in items
        if item.get("prediction") in {"malicious", "phishing"}
    ]
    suspicious_network = [
        item for item in network_items if item.get("prediction") == "malicious"
    ]
    network_rate = (
        f"{len(suspicious_network) / len(network_items):.0%}"
        if network_items
        else "—"
    )

    first, second, third = st.columns(3)
    first.metric("Analyses conservées", len(items))
    second.metric("Résultats signalés", len(suspicious))
    third.metric("Flux réseau signalés", network_rate)
    st.caption(
        "Indicateurs calculés à partir des analyses encore présentes dans l’historique — "
        "ce ne sont ni des volumes journaliers, ni des mesures globales du trafic."
    )


def _render_recent_alerts(items: list[dict]) -> None:
    st.markdown("### Alertes récentes")
    if not items:
        st.info("Aucune analyse enregistrée pour le moment. Les textes et caractéristiques brutes ne sont pas conservés.")
        return

    names = {"network": "Flux réseau", "phishing": "Message"}
    for item in items[:5]:
        is_suspicious = item.get("prediction") in {"malicious", "phishing"}
        module = names.get(item.get("module"), "Analyse")
        level = item.get("confidence_level", "unknown")
        confidence = item.get("confidence")
        try:
            confidence_text = f"{float(confidence):.0%} de confiance"
        except (TypeError, ValueError):
            confidence_text = "Confiance indisponible"

        created_at = pd.to_datetime(item.get("created_at"), errors="coerce", utc=True)
        time_text = (
            created_at.strftime("%d/%m/%Y · %H:%M UTC")
            if not pd.isna(created_at)
            else "Date indisponible"
        )
        prediction = "Signal détecté" if is_suspicious else "Aucun signal détecté"
        with st.container(border=True):
            left, right = st.columns([3, 2])
            with left:
                if is_suspicious:
                    st.markdown(f"**🔴 {prediction} · {module}**")
                else:
                    st.markdown(f"**🟢 {prediction} · {module}**")
                st.caption(time_text)
            with right:
                st.markdown(f"**{confidence_text}**")
                st.caption(f"Niveau de confiance : {level}")


def _format_algorithm(name: str) -> str:
    return {
        "xgboost": "XGBoost",
        "random_forest": "Random Forest",
        "logistic_regression": "Régression logistique",
        "multinomial_nb": "Naive Bayes",
    }.get(name, name.replace("_", " ").title())


def _comparison_rows(model: dict) -> list[dict[str, str]]:
    rows = []
    for algorithm, comparison in model.get("comparison_metrics", {}).items():
        test = comparison.get("held_out_test") or {}
        rows.append({
            "Algorithme": _format_algorithm(algorithm),
            "F1 validation": _format_percent(comparison.get("validation_f1")),
            "F1 test": _format_percent(test.get("f1")),
            "Précision test": _format_percent(test.get("precision")),
            "Rappel test": _format_percent(test.get("recall")),
            "ROC-AUC test": _format_percent(test.get("roc_auc")),
            "Modèle retenu": "Oui" if algorithm == model.get("algorithm") else "Non",
        })
    return rows


def _format_percent(value: object) -> str:
    if not isinstance(value, (int, float)):
        return "—"
    return f"{value:.1%}"


def _render_model_cards(details: dict) -> None:
    st.markdown("### Modèles de démonstration")
    labels = {
        "network": ("Réseau · UNSW-NB15", "Aucun résultat CIC-IDS2017"),
        "phishing": ("Messages · courriels anglais", "Aucun résultat SMS ou togolais"),
    }
    columns = st.columns(2)
    for column, key in zip(columns, ("network", "phishing")):
        with column:
            with st.container(border=True):
                title, caveat = labels[key]
                st.markdown(f"**{title}**")
                model = details.get(key, {})
                if not model:
                    st.info("Métriques d’entraînement indisponibles.")
                    continue

                metrics = model.get("metrics", {})
                f1 = metrics.get("f1")
                auc = metrics.get("roc_auc")
                row_count = model.get("test_rows")
                st.caption(f"Modèle retenu : {_format_algorithm(model.get('algorithm', 'inconnu'))}")
                first, second = st.columns(2)
                first.metric("F1 sur test", f"{f1:.1%}" if isinstance(f1, (int, float)) else "—")
                second.metric("ROC-AUC", f"{auc:.1%}" if isinstance(auc, (int, float)) else "—")
                count_text = f"{row_count:,}".replace(",", " ") if isinstance(row_count, int) else "indisponible"
                st.caption(f"Partition de test : {count_text} exemples · {caveat}.")


def _render_model_comparisons(details: dict) -> None:
    labels = {
        "network": "Réseau · comparaison Random Forest / XGBoost",
        "phishing": "Messages · comparaison régression logistique / Naive Bayes",
    }
    for key in ("network", "phishing"):
        model = details.get(key, {})
        rows = _comparison_rows(model)
        if not rows:
            continue
        with st.expander(labels[key]):
            st.dataframe(
                rows,
                hide_index=True,
                width="stretch",
            )
            st.caption(
                "Le modèle retenu est choisi sur le F1 de validation. Les scores « test » "
                "comparent les pipelines avant réentraînement final ; la carte de synthèse "
                "au-dessus affiche le score du modèle retenu après réentraînement."
            )


def render() -> None:
    st.markdown(
        '<section class="tc-home-intro">'
        '<p class="tc-home-kicker">PLATEFORME INTELLIGENTE DE CYBERSÉCURITÉ</p>'
        '<h2>Protégez vos systèmes contre les menaces numériques.</h2>'
        '<p>Détection · Analyse · Protection contre les menaces informatiques</p>'
        '<small>Une solution orientée cybersécurité pour la détection et l’analyse des menaces numériques.</small>'
        '</section>',
        unsafe_allow_html=True,
    )
    render_capabilities()
    st.markdown("### Votre espace de vigilance")
    st.caption("Vérifiez un message suspect, suivez les analyses et accédez aux outils SOC selon votre rôle.")

    try:
        items = get_history()
    except APIError as exc:
        items = []
        render_error(str(exc))
    try:
        model_details = get_health().get("model_details", {})
    except APIError:
        model_details = {}

    _render_summary(items)
    st.divider()

    left, right = st.columns([1.15, 0.85], gap="large")
    with left:
        st.markdown("### Vérifier un message")
        st.caption("SMS, e-mail ou lien · Le contenu n’est pas conservé dans l’historique.")
        st.warning(
            "Ne collez aucun mot de passe, code OTP, donnée bancaire ou information confidentielle."
        )
        with st.form("home_quick_phishing_form"):
            message = st.text_area(
                "Message à analyser",
                placeholder="Collez ici un message suspect…",
                max_chars=20_000,
                height=150,
            )
            submitted = st.form_submit_button("⌕  Analyser le message", type="primary")
        if submitted:
            if not message.strip():
                st.warning("Saisissez un message avant de lancer l’analyse.")
            else:
                try:
                    with st.spinner("Analyse en cours…"):
                        result = analyze_phishing(message)
                    render_result(result, "Signaux de phishing détectés", "Aucun signal évident détecté")
                except APIError as exc:
                    render_error(str(exc))
        st.caption(
            "Le modèle de démonstration a été entraîné sur des courriels anglais ; "
            "ses résultats ne sont pas validés pour les SMS ou le français togolais."
        )

        first, second = st.columns(2)
        with first:
            st.button(
                "⌁  Analyse réseau",
                key="home_open_network",
                width="stretch",
                on_click=_navigate,
                args=("Analyse réseau",),
            )
        with second:
            st.button(
                "◷  Historique complet",
                key="home_open_history",
                width="stretch",
                on_click=_navigate,
                args=("Historique",),
            )

    with right:
        _render_recent_alerts(items)
        st.button(
            "ⓘ  Comprendre les limites",
            key="home_open_transparency",
            width="stretch",
            on_click=_navigate,
            args=("Transparence",),
        )
    st.divider()
    _render_model_cards(model_details)
    _render_model_comparisons(model_details)
