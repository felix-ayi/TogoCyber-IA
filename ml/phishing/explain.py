"""Local LIME text explanations from the exact deployed TF-IDF pipeline."""

from lime.lime_text import LimeTextExplainer

from ml.common.utils import load_model

PHISHING_EXPLANATION_MAX_CHARS = 2_000
LIME_NUM_SAMPLES = 200


def explain_phishing(text: str, top_k: int = 8) -> list[dict]:
    message = text.strip()
    if not message:
        raise ValueError("message must not be empty")
    message = message[:PHISHING_EXPLANATION_MAX_CHARS]
    model = load_model("phishing")
    explainer = LimeTextExplainer(class_names=["legitimate", "phishing"], random_state=42)
    explanation = explainer.explain_instance(
        message,
        model.predict_proba,
        labels=(1,),
        num_features=top_k,
        num_samples=LIME_NUM_SAMPLES,
    )
    return [
        {"term": term, "contribution": float(weight)}
        for term, weight in explanation.as_list(label=1)
    ]