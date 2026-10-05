"""Evaluate a saved phishing model on an explicitly supplied labeled dataset."""

from pathlib import Path

from ml.common.metrics import binary_metrics
from ml.common.utils import load_model
from ml.phishing.preprocessing import load_phishing_dataset


def evaluate(dataset_path: str | Path) -> dict:
    texts, labels = load_phishing_dataset(dataset_path)
    model = load_model("phishing")
    scores = model.predict_proba(texts)[:, list(model.named_steps["classifier"].classes_).index(1)]
    return {"metrics": binary_metrics(labels, scores >= 0.5, scores), "rows": len(labels)}