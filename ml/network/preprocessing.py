"""Network dataset loading and fixed CIC/UNSW canonical feature contract."""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from ml.common.preprocessing import CIC_COLUMNS, UNSW_COLUMNS, binary_labels, canonical_network_frame


def load_network_dataset(path: str | Path, dataset: str = "cic") -> tuple[pd.DataFrame, pd.Series]:
    source = Path(path)
    if not source.exists():
        raise FileNotFoundError(f"network dataset path does not exist: {source}")
    if source.is_dir():
        files = sorted(source.rglob("*.csv"))
    elif source.is_file() and source.suffix.lower() == ".csv":
        files = [source]
    else:
        raise ValueError("network dataset path must be a CSV file or a directory containing CSV files")
    if not files:
        raise FileNotFoundError(f"no CSV files found in network dataset path: {source}")

    label_column = "Label" if dataset.lower().startswith("cic") else "label"
    feature_frames = []
    label_frames = []
    for csv_path in files:
        header = pd.read_csv(csv_path, nrows=0, encoding_errors="replace")
        column_lookup = {str(column).strip().lower(): column for column in header.columns}
        required = set((CIC_COLUMNS if dataset.lower().startswith("cic") else UNSW_COLUMNS).values())
        required_lower = {column.lower() for column in required}
        optional_unsw = {"sport", "dsport"} if dataset.lower().startswith("unsw") else set()
        missing = (required_lower - optional_unsw | {label_column.lower()}) - set(column_lookup)
        # Keep this explicit so the error identifies a malformed CSV instead of
        # silently skipping a day from a multi-file CIC-IDS2017 directory.
        if missing:
            raise ValueError(f"{csv_path} is missing required columns: {', '.join(sorted(missing))}")
        use_columns = [
            column_lookup[name]
            for name in sorted(required_lower - optional_unsw | {label_column.lower()})
        ]
        frame = pd.read_csv(csv_path, usecols=use_columns, low_memory=False, encoding_errors="replace")
        frame.columns = frame.columns.astype(str).str.strip()
        features = canonical_network_frame(frame, dataset)
        labels = binary_labels(frame[label_column], non_benign_is_positive=dataset.lower().startswith("cic"))
        valid = features.notna().all(axis=1)
        count_features = [name for name in features.columns if name != "protocol_number"]
        valid &= (features[count_features] >= 0).all(axis=1)
        valid &= features["src_port"].between(0, 65535) & features["dst_port"].between(0, 65535)
        valid &= features["protocol_number"].between(0, 255)
        if valid.any():
            feature_frames.append(features.loc[valid])
            label_frames.append(labels.loc[valid])
    if not feature_frames:
        raise ValueError(f"no complete, valid network flows found in {source}")
    features = pd.concat(feature_frames, ignore_index=True)
    labels = pd.concat(label_frames, ignore_index=True)
    return features.reset_index(drop=True), labels.reset_index(drop=True)