"""Compare Random Forest and XGBoost on CIC-IDS2017 using held-out test data."""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd
from sklearn.metrics import f1_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

from ml.common.metrics import binary_metrics
from ml.common.utils import save_model
from ml.network.preprocessing import load_network_dataset


def candidates(seed: int, positive_weight: float = 1.0) -> dict[str, Pipeline]:
    return {
        "random_forest": Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("classifier", RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=seed, n_jobs=-1)),
        ]),
        "xgboost": Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("classifier", XGBClassifier(
                n_estimators=300, max_depth=8, learning_rate=0.08, subsample=0.8,
                colsample_bytree=0.8, objective="binary:logistic", eval_metric="logloss",
                scale_pos_weight=positive_weight, random_state=seed, n_jobs=-1,
            )),
        ]),
    }


def train(
    dataset_path: str | Path,
    seed: int = 42,
    max_rows: int | None = 250_000,
    dataset: str = "cic",
    test_dataset_path: str | Path | None = None,
) -> dict:
    dataset = dataset.strip().lower()
    if dataset not in {"cic", "unsw"}:
        raise ValueError("dataset must be 'cic' or 'unsw'")
    features, labels = load_network_dataset(dataset_path, dataset)
    if labels.nunique() != 2 or labels.value_counts().min() < 5:
        raise ValueError("network training requires at least five benign and five malicious flows for a stratified 60/20/20 split")
    sampled = False
    if max_rows is not None:
        if max_rows < 25:
            raise ValueError("max_rows must be at least 25 or None")
        if len(labels) > max_rows:
            sampled = True
            features, _, labels, _ = train_test_split(
                features,
                labels,
                train_size=max_rows,
                stratify=labels,
                random_state=seed,
            )
            features = features.reset_index(drop=True)
            labels = labels.reset_index(drop=True)
    if labels.nunique() != 2 or labels.value_counts().min() < 5:
        raise ValueError(
            "the selected network sample must retain at least five benign and five malicious flows"
        )
    if dataset == "unsw":
        if test_dataset_path is None:
            raise ValueError("UNSW training requires its independent test CSV via test_dataset_path")
        x_train, x_validation, y_train, y_validation = train_test_split(
            features, labels, test_size=0.2, stratify=labels, random_state=seed,
        )
        x_test, y_test = load_network_dataset(test_dataset_path, "unsw")
        if y_test.nunique() != 2:
            raise ValueError("the independent UNSW test dataset must contain both classes")
    else:
        if test_dataset_path is not None:
            raise ValueError("test_dataset_path is only used when dataset='unsw'")
        x_train, x_holdout, y_train, y_holdout = train_test_split(
            features, labels, test_size=0.4, stratify=labels, random_state=seed,
        )
        x_validation, x_test, y_validation, y_test = train_test_split(
            x_holdout, y_holdout, test_size=0.5, stratify=y_holdout, random_state=seed,
        )
    reports = {}
    positive_weight = float((y_train == 0).sum() / max((y_train == 1).sum(), 1))
    for name, model in candidates(seed, positive_weight).items():
        model.fit(x_train, y_train)
        scores = model.predict_proba(x_validation)[:, 1]
        reports[name] = {
            "validation_f1": float(f1_score(y_validation, scores >= 0.5)),
        }
        if dataset == "unsw":
            test_scores = model.predict_proba(x_test)[:, 1]
            reports[name]["held_out_test"] = binary_metrics(y_test, test_scores >= 0.5, test_scores)
    selected_name = max(reports, key=lambda key: reports[key]["validation_f1"])
    selected = candidates(seed, positive_weight)[selected_name]
    if dataset == "unsw":
        selected.fit(features, labels)
        test_scores = selected.predict_proba(x_test)[:, 1]
        reports[selected_name]["refit_test"] = binary_metrics(y_test, test_scores >= 0.5, test_scores)
    else:
        x_final = pd.concat([x_train, x_validation], ignore_index=True)
        y_final = pd.concat([y_train, y_validation], ignore_index=True)
        selected.fit(x_final, y_final)
        test_scores = selected.predict_proba(x_test)[:, 1]
        reports[selected_name]["held_out_test"] = binary_metrics(y_test, test_scores >= 0.5, test_scores)
        reports[selected_name]["refit_test"] = reports[selected_name]["held_out_test"]
    artifact = save_model("network", selected, {
        "model": selected_name, "features": list(features.columns), "training_dataset": dataset,
        "test_dataset": str(Path(test_dataset_path).name) if test_dataset_path is not None else "stratified CIC holdout",
        "test_rows": len(x_test),
        "comparison_metrics": {
            name: {
                "validation_f1": report["validation_f1"],
                "held_out_test": report.get("held_out_test"),
            }
            for name, report in reports.items()
        },
        "positive_class": "malicious", "threshold": 0.5,
        "metrics": reports[selected_name]["refit_test"],
        "verification": (
            "pinned public mirror SHA-256 verified by scripts/download_demo_datasets.py"
            if dataset == "unsw"
            else "computed from caller-supplied CIC data; provenance not independently verified"
        ),
    })
    return {
        "selected_model": selected_name,
        "comparisons": reports,
        "rows_used": len(labels),
        "test_rows": len(x_test),
        "sampled": sampled,
        "training_dataset": dataset,
        "artifact": str(artifact),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", default="data/raw/cic_ids2017")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--max-rows", type=int, default=250_000, help="stratified row cap; use 0 for all rows")
    parser.add_argument("--dataset", choices=("cic", "unsw"), default="cic")
    parser.add_argument("--test-data", help="independent held-out UNSW CSV; required when dataset=unsw")
    args = parser.parse_args()
    print(train(
        args.data,
        args.seed,
        max_rows=args.max_rows or None,
        dataset=args.dataset,
        test_dataset_path=args.test_data,
    ))


if __name__ == "__main__":
    main()