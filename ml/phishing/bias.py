"""Evaluate phishing performance by pre-annotated language variety."""

from pathlib import Path

import pandas as pd

from ml.common.metrics import binary_metrics
from ml.common.utils import load_model
from ml.phishing.preprocessing import load_phishing_dataset

GROUPS = ("standard_french", "togolese_french")


def evaluate_language_groups(dataset_path: str | Path) -> dict:
    frame = pd.read_csv(dataset_path)
    if "language_group" not in frame.columns:
        raise ValueError("bias evaluation requires a manually annotated 'language_group' column")
    texts, labels = load_phishing_dataset(dataset_path)
    groups = frame.dropna(subset=["text", "label"]).loc[frame["text"].astype(str).str.strip().ne(""), "language_group"].reset_index(drop=True)
    model = load_model("phishing")
    scores = model.predict_proba(texts)[:, list(model.named_steps["classifier"].classes_).index(1)]
    results = {}
    for group in GROUPS:
        mask = groups.eq(group)
        if not mask.any():
            results[group] = {"rows": 0, "metrics": None, "status": "no annotated examples; no performance claim"}
            continue
        y_group = labels.loc[mask]
        score_group = scores[mask.to_numpy()]
        results[group] = {
            "rows": int(mask.sum()),
            "metrics": binary_metrics(y_group, score_group >= 0.5, score_group) if y_group.nunique() > 1 else {
                "accuracy": float(((score_group >= 0.5).astype(int) == y_group.to_numpy()).mean()),
                "status": "one class only; precision/recall comparison is not meaningful",
            },
            "status": "exploratory; interpret with sample size and annotation uncertainty",
        }
    return results
