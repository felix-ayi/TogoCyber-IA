"""Validated text/label input contract for public and locally curated messages."""

from pathlib import Path

import pandas as pd


def load_phishing_dataset(
    path: str | Path,
    require_both_classes: bool = True,
) -> tuple[pd.Series, pd.Series]:
    frame = pd.read_csv(path)
    frame.columns = frame.columns.astype(str).str.strip()
    if "text" not in frame.columns and "Email Text" in frame.columns:
        frame = frame.rename(columns={"Email Text": "text"})
    if "label" not in frame.columns and "Email Type" in frame.columns:
        frame = frame.rename(columns={"Email Type": "label"})
    missing = {"text", "label"} - set(frame.columns)
    if missing:
        raise ValueError(f"phishing dataset must contain columns: text,label (missing: {', '.join(sorted(missing))})")
    frame = frame.loc[:, ["text", "label"]].dropna()
    frame["text"] = frame["text"].astype(str).str.strip()
    frame = frame[frame["text"].ne("")]
    def label(value: object) -> int:
        normalized = str(value).strip().lower()
        if normalized in {"phishing email", "phishing"}:
            return 1
        if normalized in {"safe email", "legitimate email", "safe"}:
            return 0
        try:
            numeric = float(normalized)
        except ValueError:
            numeric = None
        if numeric in {0.0, 1.0}:
            return int(numeric)
        if normalized in {"1", "phishing", "phish", "smishing", "malicious", "spam"}:
            return 1
        if normalized in {"0", "legitimate", "benign", "ham", "safe", "normal"}:
            return 0
        raise ValueError(f"unrecognized phishing label: {value!r}")
    labels = frame["label"].map(label).astype("int8")
    if require_both_classes and labels.nunique() != 2:
        raise ValueError("phishing dataset must contain both legitimate and phishing classes")
    return frame["text"].reset_index(drop=True), labels.reset_index(drop=True)


def prepare_training_corpus(
    public_path: str | Path,
    annotations_path: str | Path,
    output_path: str | Path,
) -> dict[str, int | str]:
    """Merge 50–100 consented local annotations with a licensed public corpus."""
    annotations = pd.read_csv(annotations_path)
    annotations.columns = annotations.columns.astype(str).str.strip()
    required = {"text", "label", "source", "consent", "language_group"}
    missing = required - set(annotations.columns)
    if missing:
        raise ValueError(f"annotation file is missing required columns: {', '.join(sorted(missing))}")
    annotations = annotations.dropna(subset=list(required)).copy()
    annotations["text"] = annotations["text"].astype(str).str.strip()
    annotations["source"] = annotations["source"].astype(str).str.strip()
    consent = annotations["consent"].astype(str).str.strip().str.lower().isin({"true", "yes", "1", "oui"})
    local = annotations.loc[annotations["text"].ne("") & annotations["source"].ne("") & consent]
    if not 50 <= len(local) <= 100:
        raise ValueError(f"expected 50–100 complete, sourced, consented local examples; found {len(local)}")
    if not local["language_group"].astype(str).str.strip().eq("togolese_french").all():
        raise ValueError("local annotations must be manually tagged language_group='togolese_french'")
    local_texts, local_labels = load_phishing_dataset(annotations_path, require_both_classes=False)
    if len(local_texts) != len(local):
        raise ValueError("every retained local example must have valid text and a recognized class label")
    public_texts, public_labels = load_phishing_dataset(public_path)
    destination = Path(output_path)
    if destination.exists():
        raise FileExistsError(f"refusing to overwrite existing corpus: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    combined = pd.concat(
        [
            pd.DataFrame({"text": public_texts, "label": public_labels}),
            pd.DataFrame({"text": local_texts, "label": local_labels}),
        ],
        ignore_index=True,
    )
    combined.to_csv(destination, index=False, encoding="utf-8")
    return {"public_rows": len(public_texts), "togolese_rows": len(local_texts), "total_rows": len(combined), "output": str(destination)}