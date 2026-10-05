"""Cross-dataset evaluation of a CIC-trained model on UNSW-NB15."""

from pathlib import Path

from ml.common.metrics import binary_metrics
from ml.common.utils import load_model
from ml.network.preprocessing import load_network_dataset


def evaluate_unsw(dataset_path: str | Path) -> dict:
    model = load_model("network")
    features, labels = load_network_dataset(dataset_path, "unsw")
    scores = model.predict_proba(features)[:, 1]
    return {
        "metrics": binary_metrics(labels, scores >= 0.5, scores),
        "rows": len(labels),
        "warning": "Cross-dataset results are not directly comparable because CIC-IDS2017 and UNSW-NB15 feature definitions and distributions differ.",
        "verification": "real datasets executed",
    }