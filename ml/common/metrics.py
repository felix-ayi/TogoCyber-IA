"""Consistent binary-classification metrics used by both training pipelines."""

from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from imblearn.metrics import geometric_mean_score


def binary_metrics(y_true, y_pred, y_score) -> dict[str, float]:
    metrics = {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
        "average_precision": average_precision_score(y_true, y_score),
        "geometric_mean": geometric_mean_score(y_true, y_pred, average="binary"),
    }
    metrics["roc_auc"] = roc_auc_score(y_true, y_score) if len(set(y_true)) > 1 else float("nan")
    return {key: float(value) for key, value in metrics.items()}