"""Path, artifact and reproducibility helpers."""

from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import joblib
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[2]
load_dotenv(ROOT / ".env")
MODELS_DIR = Path(os.getenv("TOGOCYBER_MODELS_DIR", ROOT / "models" / "artifacts"))
REGISTRY_PATH = ROOT / "models" / "metadata" / "model_registry.json"


def save_model(name: str, model: Any, metadata: dict[str, Any]) -> Path:
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    REGISTRY_PATH.parent.mkdir(parents=True, exist_ok=True)
    destination = MODELS_DIR / f"{name}.joblib"
    joblib.dump(model, destination)
    registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8")) if REGISTRY_PATH.exists() and REGISTRY_PATH.stat().st_size else {}
    try:
        artifact_path = str(destination.resolve().relative_to(ROOT))
    except ValueError:
        artifact_path = str(destination.resolve())
    registry[name] = {**metadata, "artifact": artifact_path}
    REGISTRY_PATH.write_text(json.dumps(registry, indent=2, ensure_ascii=False), encoding="utf-8")
    return destination


def load_model(name: str) -> Any:
    path = MODELS_DIR / f"{name}.joblib"
    if not path.is_file():
        raise FileNotFoundError(
            f"Le modèle '{name}' n'est pas entraîné. Fournissez le jeu de données réel puis lancez l'entraînement correspondant."
        )
    signature = path.stat()
    return _load_model_cached(
        str(path.resolve()), signature.st_mtime_ns, signature.st_size
    )


@lru_cache(maxsize=8)
def _load_model_cached(path: str, modified_ns: int, size: int) -> Any:
    return joblib.load(path)


def registered_model_metadata(name: str) -> dict[str, Any]:
    if not REGISTRY_PATH.exists():
        return {}
    try:
        registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Unable to read model registry at {REGISTRY_PATH}") from exc
    if not isinstance(registry, dict):
        raise ValueError(f"model registry must contain a JSON object: {REGISTRY_PATH}")
    metadata = registry.get(name, {})
    if not isinstance(metadata, dict):
        raise ValueError(f"model registry entry '{name}' must contain a JSON object")
    return metadata