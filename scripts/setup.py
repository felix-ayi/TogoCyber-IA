"""Create runtime directories and verify declared packages are available."""

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = (
    "fastapi", "uvicorn", "pandas", "numpy", "sklearn", "xgboost",
    "imblearn", "matplotlib", "seaborn", "shap", "lime", "streamlit",
    "requests", "dotenv", "joblib",
)


def main() -> int:
    if sys.version_info < (3, 11):
        print("Python 3.11 or newer is required.")
        return 1
    missing = [package for package in REQUIRED if importlib.util.find_spec(package) is None]
    if missing:
        print("Missing dependencies: " + ", ".join(missing))
        print("Install the declared stack with: python -m pip install -r requirements.txt")
        return 1
    for directory in ("data/raw", "data/annotations", "models/artifacts", "models/metadata", "database", "reports"):
        (ROOT / directory).mkdir(parents=True, exist_ok=True)
    print("Environment checks passed. No dataset or trained model is bundled.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())