import streamlit as st


def render_alert(message: str, kind: str = "info") -> None:
    renderer = {"info": st.info, "warning": st.warning, "error": st.error}.get(kind)
    if renderer is None:
        raise ValueError(f"unsupported alert kind: {kind}")
    renderer(message)