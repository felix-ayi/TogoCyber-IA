from pathlib import Path

PALETTE = {
    "navy": "#0A1F44",
    "teal": "#006f68",
    "teal_dark": "#075b65",
    "background": "#f6f8fb",
    "text": "#10233f",
    "sidebar": "#eaf0f5",
}

THEMES = {
    "Nuit cyber": {
        "bg": "#071321",
        "surface": "#0d1b2b",
        "surface_raised": "#122438",
        "border": "#263d52",
        "text": "#e4edf5",
        "muted": "#a3b4c5",
        "cyan": "#36d8cf",
        "green": "#37d39a",
        "yellow": "#f5ca43",
        "red": "#d93d4d",
        "panel": "#0f2436",
    },
    "Sécurité claire": {
        "bg": "#f4f7fb",
        "surface": "#ffffff",
        "surface_raised": "#edf4fb",
        "border": "#cfdce9",
        "text": "#162c4d",
        "muted": "#536a86",
        "cyan": "#1b7f8d",
        "green": "#248a5a",
        "yellow": "#9b7200",
        "red": "#b63d3d",
        "panel": "#edf5ff",
    },
    "Alerte standard": {
        "bg": "#0d1724",
        "surface": "#111e2d",
        "surface_raised": "#1a2f42",
        "border": "#2f4055",
        "text": "#edf4fb",
        "muted": "#b0c2d2",
        "cyan": "#53d8df",
        "green": "#4dd29a",
        "yellow": "#f0c55f",
        "red": "#ff6d73",
        "panel": "#132635",
    },
}

CSS_PATH = Path(__file__).with_name("main.css")


def build_theme_css(
    theme_name: str = "Nuit cyber",
    compact_mode: bool = False,
    reduced_motion: bool = False,
) -> str:
    palette = THEMES.get(theme_name, THEMES["Nuit cyber"])
    compact_width = "1280px" if compact_mode else "1440px"
    motion_block = """
        @media (prefers-reduced-motion: reduce) {
            *, *::before, *::after {
                animation-duration: 0.01ms !important;
                animation-iteration-count: 1 !important;
                transition-duration: 0.01ms !important;
                scroll-behavior: auto !important;
            }
        }
    """ if reduced_motion else ""
    return f"""
        :root {{
            --tc-bg: {palette['bg']};
            --tc-surface: {palette['surface']};
            --tc-surface-raised: {palette['surface_raised']};
            --tc-border: {palette['border']};
            --tc-text: {palette['text']};
            --tc-muted: {palette['muted']};
            --tc-cyan: {palette['cyan']};
            --tc-green: {palette['green']};
            --tc-yellow: {palette['yellow']};
            --tc-red: {palette['red']};
            --tc-surface-alt: {palette['panel']};
            --tc-surface-soft: rgba(13, 27, 43, 0.8);
            --tc-glow: rgba(54, 216, 207, 0.26);
        }}
        .block-container {{
            max-width: {compact_width};
            padding-top: 1rem;
            padding-bottom: 1.5rem;
        }}
        .stApp {{
            background: var(--tc-bg);
            color: var(--tc-text);
        }}
        .stApp [data-testid="stAppViewContainer"] {{
            background: radial-gradient(circle at top left, rgba(54, 216, 207, 0.12), transparent 28%), radial-gradient(circle at bottom right, rgba(30, 99, 150, 0.15), transparent 24%), var(--tc-bg);
        }}
        {motion_block}
    """


def stylesheet(
    theme_name: str | None = None,
    compact_mode: bool | None = None,
    reduced_motion: bool | None = None,
) -> str:
    if theme_name is None:
        try:
            import streamlit as st
        except ModuleNotFoundError:
            theme_name = "Nuit cyber"
        else:
            profile_preferences = st.session_state.get("profile_preferences", {})
            theme_name = profile_preferences.get("theme", "Nuit cyber")
    if compact_mode is None:
        try:
            import streamlit as st
        except ModuleNotFoundError:
            compact_mode = False
        else:
            compact_mode = st.session_state.get("profile_preferences", {}).get("compact_mode", False)
    if reduced_motion is None:
        try:
            import streamlit as st
        except ModuleNotFoundError:
            reduced_motion = False
        else:
            reduced_motion = st.session_state.get("profile_preferences", {}).get("reduced_motion", False)
    css = CSS_PATH.read_text(encoding="utf-8")
    return f"<style>{build_theme_css(theme_name, compact_mode, reduced_motion)}{css}</style>"