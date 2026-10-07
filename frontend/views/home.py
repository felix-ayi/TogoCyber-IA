"""Dashboard landing page with live summaries and a quick message check."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from frontend.components.brand_identity import render_capabilities
from frontend.components.error_state import render_error
from frontend.components.result_card import render_result
from frontend.services.api_client import (
    APIError,
    analyze_phishing,
    clear_history,
    get_demo_scenario,
    get_health,
    get_history,
    get_security_posture,
)


def _navigate(page: str) -> None:
    st.session_state["main_navigation"] = page


def _inject_quick_action_style() -> None:
    st.markdown(
        """
        <style>
        div[data-testid="stHorizontalBlock"] div.stButton > button {
            background: linear-gradient(135deg, rgba(60, 95, 128, 0.90), rgba(46, 181, 168, 0.52));
            border: 1px solid rgba(135, 207, 221, 0.42);
            color: #edfaff;
            border-radius: 18px;
            min-height: 52px;
            font-weight: 700;
            letter-spacing: 0.01em;
            box-shadow: 0 14px 26px rgba(7, 19, 33, 0.22), inset 0 1px 0 rgba(255,255,255,0.18);
            animation: tc-button-arrive 480ms ease-out both;
        }
        div[data-testid="stHorizontalBlock"] div.stButton > button:hover {
            background: linear-gradient(135deg, rgba(62, 214, 196, 0.34), rgba(87, 126, 191, 0.34));
            border-color: rgba(146, 255, 226, 0.72);
            transform: translateY(-2px) scale(1.01);
            box-shadow: 0 18px 32px rgba(7, 19, 33, 0.24), inset 0 1px 0 rgba(255,255,255,0.22);
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


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
    st.markdown(
        """
        <section class="tc-hero-cta" aria-label="Vue d’ensemble cyber">
          <div class="tc-hero-cta-copy">
            <span class="tc-hero-kicker">PULSE CYBER</span>
            <h3>Surveillance proactive · Priorisation rapide · Réponse orientée risque</h3>
          </div>
          <div class="tc-hero-cta-meta">
            <span>Démo</span>
            <span>Sans donnée sensible</span>
          </div>
        </section>
        """,
        unsafe_allow_html=True,
    )

    try:
        health = get_health()
    except APIError:
        health = {}
    try:
        posture = get_security_posture()
    except APIError:
        posture = None
    try:
        items = get_history()
    except APIError as exc:
        items = []
        render_error(str(exc))

    network_ready = bool(health.get("models", {}).get("network"))
    phishing_ready = bool(health.get("models", {}).get("phishing"))
    assistant_ready = bool(health.get("assistant_configured"))
    api_state = "OK" if health.get("status") == "healthy" else "Indisponible"
    api_class = "tc-status-ok" if health.get("status") == "healthy" else "tc-status-warning"

    st.markdown(
        f"""
        <section class="tc-status-overview" aria-label="État de la plateforme">
          <div class="tc-status-header">
            <span class="tc-status-live">LIVE</span>
            <span class="tc-status-title">État de la plateforme</span>
          </div>
          <div class="tc-status-grid">
            <div class="tc-status-card {api_class}">
              <span class="tc-status-label">API</span>
              <strong>{api_state}</strong>
              <small>Service principal</small>
            </div>
            <div class="tc-status-card {'tc-status-ok' if network_ready else 'tc-status-warning'}">
              <span class="tc-status-label">Réseau</span>
              <strong>{'Prêt' if network_ready else 'À entraîner'}</strong>
              <small>Détection comportementale</small>
            </div>
            <div class="tc-status-card {'tc-status-ok' if phishing_ready else 'tc-status-warning'}">
              <span class="tc-status-label">Phishing</span>
              <strong>{'Prêt' if phishing_ready else 'À entraîner'}</strong>
              <small>Analyse du message</small>
            </div>
            <div class="tc-status-card {'tc-status-ok' if assistant_ready else 'tc-status-neutral'}">
              <span class="tc-status-label">Assistant IA</span>
              <strong>{'Oui' if assistant_ready else 'Non'}</strong>
              <small>Outil d’assistance</small>
            </div>
          </div>
        </section>
        """,
        unsafe_allow_html=True,
    )

    mission_score = int(posture.get("overall_score", 0)) if posture else 0
    mission_level = posture.get("level", "À définir") if posture else "À définir"
    st.markdown(
        f"""
        <section class="tc-mission-board" aria-label="Mission opérationnelle du SOC">
          <div class="tc-mission-head">
            <span class="tc-mission-kicker">MISSION</span>
            <strong>Console de surveillance opérationnelle</strong>
          </div>
          <div class="tc-mission-grid">
            <article class="tc-mission-card">
              <span>Risque global</span>
              <strong>{mission_score}</strong>
              <small>{mission_level}</small>
            </article>
            <article class="tc-mission-card">
              <span>API</span>
              <strong>{'OK' if health.get('status') == 'healthy' else 'HORS LIGNE'}</strong>
              <small>Service principal</small>
            </article>
            <article class="tc-mission-card">
              <span>Modèles</span>
              <strong>{sum(1 for ready in health.get('models', {}).values() if ready)}</strong>
              <small>Prêts pour la démo</small>
            </article>
          </div>
        </section>
        """,
        unsafe_allow_html=True,
    )

    if posture:
        score = int(posture.get("overall_score", 0))
        level = posture.get("level", "non défini")
        level_class = "tc-risk-ok" if score >= 70 else "tc-risk-watch" if score >= 45 else "tc-risk-alert"
        st.markdown(
            f"""
            <section class="tc-risk-panel {level_class}" aria-label="Synthèse de vigilance">
              <div class="tc-risk-header">
                <span class="tc-risk-kicker">Synthèse</span>
                <span class="tc-risk-pill">{level}</span>
              </div>
              <div class="tc-risk-body">
                <div>
                  <span class="tc-risk-caption">Risque global</span>
                  <strong class="tc-risk-score">{score}/100</strong>
                </div>
                <p class="tc-risk-summary">{posture.get('summary', 'État de sécurité non disponible.')}</p>
              </div>
            </section>
            """,
            unsafe_allow_html=True,
        )

    network_items = [item for item in items if item.get("module") == "network"]
    suspicious = [item for item in items if item.get("prediction") in {"malicious", "phishing"}]
    st.markdown(
        f"""
        <section class="tc-ops-strip" aria-label="Synthèse des opérations SOC">
          <article class="tc-ops-card">
            <span class="tc-ops-label">Analyses enregistrées</span>
            <strong>{len(items)}</strong>
            <small>Historique local</small>
          </article>
          <article class="tc-ops-card">
            <span class="tc-ops-label">Signalements</span>
            <strong>{len(suspicious)}</strong>
            <small>Malveillances détectées</small>
          </article>
          <article class="tc-ops-card">
            <span class="tc-ops-label">Flux réseau</span>
            <strong>{len(network_items)}</strong>
            <small>Éléments observés</small>
          </article>
        </section>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        <section class="tc-soc-workflow" aria-label="Cycle de réponse SOC">
          <div class="tc-workflow-header">
            <span>Cycle de réponse</span>
            <small>Détection · Priorisation · Remédiation</small>
          </div>
          <div class="tc-workflow-grid">
            <article class="tc-workflow-step">
              <span class="tc-step-index">01</span>
              <strong>Détection</strong>
              <small>Signalisation des anomalies et des comportements suspects.</small>
            </article>
            <article class="tc-workflow-step">
              <span class="tc-step-index">02</span>
              <strong>Priorisation</strong>
              <small>Analyse du niveau de risque et des actifs impactés.</small>
            </article>
            <article class="tc-workflow-step">
              <span class="tc-step-index">03</span>
              <strong>Remédiation</strong>
              <small>Suivi des actions et mise à jour de la posture de sécurité.</small>
            </article>
          </div>
        </section>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        <section class="tc-transparency-panel" aria-label="Transparence de la démonstration">
          <div class="tc-transparency-head">
            <span>Transparence</span>
            <small>Données synthétiques · limites explicites</small>
          </div>
          <div class="tc-transparency-pills">
            <span>UNSW-NB15</span>
            <span>Courriels anglais</span>
            <span>Pas de DNS réel</span>
            <span>Pas de téléphonie réelle</span>
          </div>
        </section>
        """,
        unsafe_allow_html=True,
    )

    if not items:
        st.info(
            "Aucune donnée de démonstration n’est encore enregistrée. Lancez la simulation pour générer un scénario de vigilance synthétique."
        )

    st.markdown("### Démo mode · AI4YOUTH DEMO")
    st.caption("SCÉNARIO DE DÉMONSTRATION — DONNÉES SYNTHÉTIQUES")

    demo_actions = st.columns(3)
    with demo_actions[0]:
        if st.button("▶ Lancer la simulation", key="launch_demo_scenario", use_container_width=True):
            try:
                scenario = get_demo_scenario()
            except APIError as exc:
                st.warning(f"La simulation de démo est indisponible : {exc}")
            else:
                st.success(f"{scenario['scenario']} · {scenario['notice']}")
                st.markdown(f"**RISK SCORE** : {scenario['risk_score']}/100")
                st.markdown(f"**SEVERITY** : {scenario['severity']}")
                st.markdown(f"**AFFECTED ASSET** : {scenario['asset']}")
                for fact in scenario["facts"]:
                    st.markdown(f"- {fact}")
                for step in scenario["steps"]:
                    st.markdown(f"**{step['order']}. {step['name']}** — {step['description']}")
                st.markdown("**RECOMMENDATIONS**")
                for recommendation in scenario["recommendations"]:
                    st.markdown(f"- {recommendation}")
    with demo_actions[1]:
        if st.button("🧹 Réinitialiser l’historique", key="demo_reset_history", use_container_width=True, type="secondary"):
            if st.confirm("Supprimer l’historique local de cette session de démonstration ?"):
                try:
                    clear_history()
                    st.success("Historique réinitialisé.")
                    st.rerun()
                except APIError as exc:
                    render_error(str(exc))
    with demo_actions[2]:
        st.button(
            "🛡 Ouvrir le SOC",
            key="demo_open_soc",
            use_container_width=True,
            on_click=_navigate,
            args=("Tableau de bord SOC",),
        )

    if posture:
        st.markdown("### Security Posture")
        st.metric("Score global", f"{posture['overall_score']}/100")
        st.caption(f"Niveau : {posture['level']} — {posture['summary']}")
        for category in posture["categories"][:4]:
            st.progress(category["score"] / 100, text=f"{category['name']} : {category['score']}/100")

    st.markdown("### Votre espace de vigilance")
    st.caption("Vérifiez un message suspect, suivez les analyses et accédez aux outils SOC selon votre rôle.")

    st.markdown(
        f"""
        <section class="tc-soc-brief" aria-label="Synthèse courte du command center">
          <div class="tc-soc-brief-head">
            <span>Command brief</span>
            <small>Panorama rapide</small>
          </div>
          <div class="tc-soc-brief-grid">
            <article class="tc-soc-brief-card tc-soc-brief-red">
              <span class="tc-soc-brief-label">Alertes</span>
              <strong>{len(suspicious)}</strong>
              <small>À traiter</small>
            </article>
            <article class="tc-soc-brief-card tc-soc-brief-gold">
              <span class="tc-soc-brief-label">Historique</span>
              <strong>{len(items)}</strong>
              <small>Éléments conservés</small>
            </article>
            <article class="tc-soc-brief-card tc-soc-brief-cyan">
              <span class="tc-soc-brief-label">Réseau</span>
              <strong>{len(network_items)}</strong>
              <small>Flux observés</small>
            </article>
          </div>
        </section>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        f"""
        <section class="tc-priority-panel" aria-label="Priorités d’intervention SOC">
          <div class="tc-priority-header">
            <span>Priorités d’intervention</span>
            <small>Focus opérationnel</small>
          </div>
          <div class="tc-priority-grid">
            <article class="tc-priority-card tc-priority-alert">
              <div class="tc-priority-thumb">⚑</div>
              <div>
                <strong>{len(suspicious)}</strong>
                <small>Éléments signalés</small>
              </div>
            </article>
            <article class="tc-priority-card tc-priority-watch">
              <div class="tc-priority-thumb">◉</div>
              <div>
                <strong>{len(network_items)}</strong>
                <small>Flux réseau surveillés</small>
              </div>
            </article>
            <article class="tc-priority-card tc-priority-ok">
              <div class="tc-priority-thumb">✓</div>
              <div>
                <strong>{len(items)}</strong>
                <small>Analyses dans l’historique</small>
              </div>
            </article>
          </div>
        </section>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("### Raccourcis de démonstration")
    quick_actions = st.columns(5)
    with quick_actions[0]:
        st.button(
            "📘 Guide",
            key="home_quick_guide",
            use_container_width=True,
            on_click=_navigate,
            args=("Guide utilisateur",),
        )
    with quick_actions[1]:
        st.button(
            "👤 Profil",
            key="home_quick_profile",
            use_container_width=True,
            on_click=_navigate,
            args=("Mon profil",),
        )
    with quick_actions[2]:
        st.button(
            "🛡 SOC",
            key="home_quick_soc",
            use_container_width=True,
            on_click=_navigate,
            args=("Tableau de bord SOC",),
        )
    with quick_actions[3]:
        st.button(
            "⚑ Alertes",
            key="home_quick_alerts",
            use_container_width=True,
            on_click=_navigate,
            args=("Alertes (SOC)",),
        )
    with quick_actions[4]:
        if st.button(
            "🧹 Réinitialiser",
            key="home_clear_history",
            use_container_width=True,
            type="secondary",
        ):
            if st.confirm("Supprimer l’historique local de cette session de démonstration ?"):
                try:
                    clear_history()
                    st.success("Historique réinitialisé.")
                    st.rerun()
                except APIError as exc:
                    render_error(str(exc))

    model_details = health.get("model_details", {})

    _render_summary(items)
    st.divider()

    _inject_quick_action_style()
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
