"""Local SHAP explanations for the trained network tree model."""

import numpy as np
import shap

from ml.common.preprocessing import network_features_from_mapping
from ml.common.utils import load_model


def explain_network(values: dict, top_k: int = 5) -> list[dict]:
    row = network_features_from_mapping(values)
    model = load_model("network")
    prepared = model.named_steps["imputer"].transform(row)
    classifier = model.named_steps["classifier"]
    explanation = shap.TreeExplainer(classifier)(prepared)
    values_array = np.asarray(explanation.values)
    if values_array.ndim == 3:
        values_array = values_array[0, :, 1]
    elif values_array.ndim == 2:
        values_array = values_array[0]
    elif values_array.ndim == 1:
        pass
    else:
        raise ValueError(f"Unsupported SHAP value shape: {values_array.shape}")
    names = list(row.columns)
    ranked = sorted(zip(names, values_array.tolist()), key=lambda item: abs(item[1]), reverse=True)[:top_k]
    return [{"feature": name, "contribution": float(value)} for name, value in ranked]