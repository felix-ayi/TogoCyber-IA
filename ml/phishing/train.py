"""Compare TF-IDF logistic regression and multinomial naive Bayes."""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline

from ml.common.metrics import binary_metrics
from ml.common.utils import save_model
from ml.phishing.preprocessing import load_phishing_dataset


def candidates(seed: int) -> dict[str, Pipeline]:
    vectorizer = {"ngram_range": (1, 2), "max_features": 50000, "sublinear_tf": True}
    return {
        "logistic_regression": Pipeline([
            ("tfidf", TfidfVectorizer(**vectorizer)),
            ("classifier", LogisticRegression(class_weight="balanced", max_iter=1000, random_state=seed)),
        ]),
        "multinomial_nb": Pipeline([
            ("tfidf", TfidfVectorizer(**vectorizer)),
            ("classifier", MultinomialNB(alpha=0.5)),
        ]),
    }


def train(dataset_path: str | Path, seed: int = 42) -> dict:
    texts, labels = load_phishing_dataset(dataset_path)
    if labels.value_counts().min() < 5:
        raise ValueError("phishing training requires at least five examples from each class for a stratified 60/20/20 split")
    x_train, x_holdout, y_train, y_holdout = train_test_split(
        texts, labels, test_size=0.4, stratify=labels, random_state=seed,
    )
    x_validation, x_test, y_validation, y_test = train_test_split(
        x_holdout, y_holdout, test_size=0.5, stratify=y_holdout, random_state=seed,
    )
    reports = {}
    for name, model in candidates(seed).items():
        model.fit(x_train, y_train)
        validation_score = model.predict_proba(x_validation)[:, 1]
        held_out_score = model.predict_proba(x_test)[:, 1]
        reports[name] = {
            "validation_f1": float(f1_score(y_validation, validation_score >= 0.5)),
            "held_out_test": binary_metrics(y_test, held_out_score >= 0.5, held_out_score),
        }
    selected_name = max(reports, key=lambda key: reports[key]["validation_f1"])
    selected = candidates(seed)[selected_name]
    x_final = pd.concat([x_train, x_validation], ignore_index=True)
    y_final = pd.concat([y_train, y_validation], ignore_index=True)
    selected.fit(x_final, y_final)
    test_score = selected.predict_proba(x_test)[:, 1]
    reports[selected_name]["refit_test"] = binary_metrics(y_test, test_score >= 0.5, test_score)
    artifact = save_model("phishing", selected, {
        "model": selected_name, "features": "TF-IDF word n-grams (1,2)",
        "training_corpus": (
            "public English phishing-email corpus (LGPL-3.0 declared by the Hugging Face mirror)"
            if Path(dataset_path).name.lower() == "phishing_email.csv"
            else "caller-supplied labeled text corpus"
        ),
        "test_rows": len(x_test),
        "comparison_metrics": {
            name: {
                "validation_f1": report["validation_f1"],
                "held_out_test": report["held_out_test"],
            }
            for name, report in reports.items()
        },
        "positive_class": "phishing", "threshold": 0.5,
        "metrics": reports[selected_name]["refit_test"],
        "verification": (
            "pinned public mirror SHA-256 verified by scripts/download_demo_datasets.py"
            if Path(dataset_path).name.lower() == "phishing_email.csv"
            else "computed from caller-supplied data; provenance not independently verified"
        ),
    })
    return {"selected_model": selected_name, "comparisons": reports, "test_rows": len(x_test), "artifact": str(artifact)}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", default="data/raw/phishing.csv")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    print(train(args.data, args.seed))


if __name__ == "__main__":
    main()