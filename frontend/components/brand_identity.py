import streamlit as st


_CAPABILITIES = (
    (
        "🎣",
        "Phishing",
        "Analyse ML de messages; modèle démo anglophone, à entraîner pour activer.",
    ),
    (
        "🌐",
        "Flux réseau",
        "Classification de flux à partir de neuf variables; aucune capture réseau.",
    ),
    (
        "🔗",
        "Inspection URL",
        "Heuristique structurelle locale, sans DNS ni réputation externe.",
    ),
    (
        "🔎",
        "IOC local",
        "Répertoire d’indicateurs géré par les analystes; sans flux externe connecté.",
    ),
    (
        "🚨",
        "Alertes et incidents",
        "Triage et suivi issus des analyses réellement enregistrées.",
    ),
    (
        "🧠",
        "Explicabilité ML",
        "SHAP et LIME lorsque les modèles réseau et phishing sont installés.",
    ),
    (
        "📊",
        "Dashboard SOC",
        "Compteurs d’alertes et d’incidents calculés depuis SQLite.",
    ),
    (
        "🤖",
        "Assistant IA",
        "Optionnel; disponible uniquement avec un fournisseur configuré.",
    ),
)


def render_brand_identity(compact: bool = False) -> None:
    animate = not st.session_state.get("tc_brand_intro_seen", False)
    st.session_state["tc_brand_intro_seen"] = True
    motion_class = "tc-brand-animated" if animate else "tc-brand-static"

    if compact:
        st.markdown(
            f"""
            <header class="tc-header tc-header-identity {motion_class}">
              <div class="tc-identity-mark" role="img" aria-label="Drapeau du Togo et bouclier cyber">
                <span class="tc-togo-flag" aria-hidden="true"><span>★</span></span>
                <span class="tc-mini-shield" aria-hidden="true">✓</span>
              </div>
              <div class="tc-brand-copy">
                <p class="tc-kicker">TOGOCYBER-IA · CYBERSÉCURITÉ</p>
                <h1>Plateforme intelligente de cybersécurité</h1>
              </div>
              <div class="tc-header-tag">ESPACE SÉCURISÉ</div>
            </header>
            """,
            unsafe_allow_html=True,
        )
        return

    st.markdown(
        f"""
        <section class="tc-brand-identity {motion_class}" aria-label="Identité TogoCyber-IA">
          <div class="tc-brand-scene" role="img" aria-label="Drapeau togolais et bouclier numérique connecté">
            <span class="tc-togo-flag" aria-hidden="true"><span>★</span></span>
            <span class="tc-network-line tc-line-one" aria-hidden="true"></span>
            <span class="tc-network-line tc-line-two" aria-hidden="true"></span>
            <span class="tc-network-line tc-line-three" aria-hidden="true"></span>
            <span class="tc-network-node tc-node-one" aria-hidden="true"></span>
            <span class="tc-network-node tc-node-two" aria-hidden="true"></span>
            <span class="tc-network-node tc-node-three" aria-hidden="true"></span>
            <span class="tc-cyber-shield" aria-hidden="true"><span>✓</span><i></i></span>
          </div>
          <div class="tc-brand-message">
            <p class="tc-brand-overline"><strong>TOGOCYBER-IA</strong><span>TOGO · CYBER</span></p>
            <h1>Protégez vos systèmes contre les menaces numériques.</h1>
            <p class="tc-brand-subtitle">Plateforme intelligente de cybersécurité</p>
            <p class="tc-brand-promise">Détection · Analyse · Protection contre les menaces informatiques</p>
            <p class="tc-brand-note">Une solution orientée cybersécurité pour la détection et l’analyse des menaces numériques.</p>
            <p class="tc-brand-limit">La plateforme analyse les données soumises; elle ne bloque pas automatiquement les menaces.</p>
          </div>
        </section>
        """,
        unsafe_allow_html=True,
    )


def render_capabilities() -> None:
    cards = "".join(
        f'<article class="tc-capability" role="listitem">'
        f'<span class="tc-capability-icon" aria-hidden="true">{icon}</span>'
        f'<span><strong>{title}</strong><small>{description}</small></span>'
        f"</article>"
        for icon, title, description in _CAPABILITIES
    )
    st.markdown(
        '<section class="tc-capability-section" aria-label="Capacités présentes">'
        '<p class="tc-capability-heading">OUTILS DISPONIBLES</p>'
        f'<div class="tc-capability-grid" role="list">{cards}</div>'
        "</section>",
        unsafe_allow_html=True,
    )