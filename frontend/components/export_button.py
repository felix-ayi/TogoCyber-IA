"""Reusable CSV export button backed by the /exports API."""

import streamlit as st

from frontend.components.error_state import render_error
from frontend.services.api_client import APIError, download_export


def render_export_button(
    resource: str,
    label: str = "Exporter en CSV",
    params: dict | None = None,
    key: str | None = None,
) -> None:
    try:
        filename, content = download_export(resource, params)
    except APIError as exc:
        render_error(str(exc))
        return
    st.download_button(
        label,
        data=content,
        file_name=filename,
        mime="text/csv",
        key=key or f"export_{resource}",
    )
