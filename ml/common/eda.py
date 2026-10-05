"""Dataset exploration with class balance, distributions, boxplots and correlations."""

from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

from ml.network.preprocessing import load_network_dataset
from ml.phishing.preprocessing import load_phishing_dataset


def network_eda(dataset_path: str | Path, output_dir: str | Path, dataset: str = "cic") -> dict:
    x, y = load_network_dataset(dataset_path, dataset)
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    data = x.copy()
    data["label"] = y.map({0: "benign", 1: "malicious"})
    data["label"].value_counts().plot(kind="bar", color=["#00B39B", "#D94F4F"])
    plt.title("Network traffic class balance")
    plt.ylabel("Rows")
    plt.tight_layout()
    plt.savefig(output / "network_class_balance.png", dpi=150)
    plt.close()
    for feature in x.columns:
        fig, axes = plt.subplots(1, 2, figsize=(10, 3.5))
        sns.histplot(data=data, x=feature, hue="label", element="step", stat="density", common_norm=False, ax=axes[0])
        sns.boxplot(data=data, x="label", y=feature, ax=axes[1])
        fig.suptitle(f"Distribution and boxplot: {feature}")
        fig.tight_layout()
        fig.savefig(output / f"network_{feature}.png", dpi=130)
        plt.close(fig)
    correlation = data.drop(columns="label").corr(numeric_only=True)
    plt.figure(figsize=(10, 8))
    sns.heatmap(correlation, cmap="vlag", center=0)
    plt.tight_layout()
    plt.savefig(output / "network_correlations.png", dpi=150)
    plt.close()
    return {
        "rows": int(len(data)),
        "class_counts": {str(key): int(value) for key, value in y.value_counts().items()},
        "features": list(x.columns),
        "outputs": str(output),
    }


def phishing_eda(dataset_path: str | Path, output_dir: str | Path) -> dict:
    texts, labels = load_phishing_dataset(dataset_path)
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    lengths = pd.DataFrame({"characters": texts.str.len(), "words": texts.str.split().str.len(), "label": labels.map({0: "legitimate", 1: "phishing"})})
    lengths["label"].value_counts().plot(kind="bar", color=["#00B39B", "#D94F4F"])
    plt.title("Phishing corpus class balance")
    plt.ylabel("Rows")
    plt.tight_layout()
    plt.savefig(output / "phishing_class_balance.png", dpi=150)
    plt.close()
    fig, axes = plt.subplots(1, 2, figsize=(10, 4))
    sns.histplot(data=lengths, x="characters", hue="label", element="step", ax=axes[0])
    sns.boxplot(data=lengths, x="label", y="words", ax=axes[1])
    fig.tight_layout()
    fig.savefig(output / "phishing_text_lengths.png", dpi=150)
    plt.close(fig)
    correlation = lengths[["characters", "words", "label"]].assign(label=labels).corr(numeric_only=True)
    plt.figure(figsize=(5, 4))
    sns.heatmap(correlation, cmap="vlag", center=0, annot=True)
    plt.tight_layout()
    plt.savefig(output / "phishing_correlations.png", dpi=150)
    plt.close()
    return {
        "rows": int(len(texts)),
        "class_counts": {str(key): int(value) for key, value in labels.value_counts().items()},
        "mean_characters": float(lengths["characters"].mean()),
        "outputs": str(output),
    }
