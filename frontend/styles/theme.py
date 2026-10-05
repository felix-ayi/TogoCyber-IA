from pathlib import Path

PALETTE = {
    "navy": "#0A1F44",
    "teal": "#006f68",
    "teal_dark": "#075b65",
    "background": "#f6f8fb",
    "text": "#10233f",
    "sidebar": "#eaf0f5",
}

CSS_PATH = Path(__file__).with_name("main.css")


def stylesheet() -> str:
    return f"<style>{CSS_PATH.read_text(encoding='utf-8')}</style>"