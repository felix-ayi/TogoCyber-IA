import streamlit as st


def render_header() -> None:
    st.markdown(
        '<header class="tc-header"><div class="tc-brand-mark" aria-hidden="true">🛡</div>'
        '<div class="tc-brand-copy"><p class="tc-kicker">CYBERSÉCURITÉ POUR TOUS</p>'
        '<h1>TogoCyber <span>AI</span></h1>'
        '<p>Votre assistant pour détecter, comprendre et prévenir.</p></div>'
        '<div class="tc-header-tag">DÉMO DE RECHERCHE</div></header>',
        unsafe_allow_html=True,
    )