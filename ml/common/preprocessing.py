"""Shared, leakage-safe preprocessing helpers and canonical network schema."""

from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd

NETWORK_FEATURES = (
    "duration",
    "src_bytes",
    "dst_bytes",
    "src_packets",
    "dst_packets",
    "src_port",
    "dst_port",
    "protocol_number",
    "flow_rate",
)

CIC_COLUMNS = {
    "duration": "Flow Duration",
    "src_bytes": "Total Length of Fwd Packets",
    "dst_bytes": "Total Length of Bwd Packets",
    "src_packets": "Total Fwd Packets",
    "dst_packets": "Total Backward Packets",
    "src_port": "Source Port",
    "dst_port": "Destination Port",
    "protocol_number": "Protocol",
    "flow_rate": "Flow Packets/s",
}

UNSW_COLUMNS = {
    "duration": "dur",
    "src_bytes": "sbytes",
    "dst_bytes": "dbytes",
    "src_packets": "spkts",
    "dst_packets": "dpkts",
    "src_port": "sport",
    "dst_port": "dsport",
    "protocol_number": "proto",
    "flow_rate": "rate",
}


def _protocol_number(value: Any) -> float:
    """Map transport protocol names to stable numeric identifiers."""
    if pd.isna(value):
        return 0.0
    text = str(value).strip().lower()
    known = {"icmp": 1.0, "tcp": 6.0, "udp": 17.0, "dccp": 33.0, "ipv6": 41.0, "gre": 47.0, "esp": 50.0, "ah": 51.0, "icmpv6": 58.0, "sctp": 132.0, "udplite": 136.0}
    if text in known:
        return known[text]
    try:
        return float(text)
    except ValueError:
        return float(sum(text.encode("utf-8")) % 256)


def canonical_network_frame(frame: pd.DataFrame, dataset: str = "cic") -> pd.DataFrame:
    """Convert CIC-IDS2017 or UNSW-NB15 columns to the versioned API feature schema."""
    dataset_key = dataset.strip().lower()
    mapping = {"cic": CIC_COLUMNS, "cic-ids2017": CIC_COLUMNS, "unsw": UNSW_COLUMNS, "unsw-nb15": UNSW_COLUMNS}.get(dataset_key)
    if mapping is None:
        raise ValueError("dataset must be 'cic' or 'unsw'")
    frame = frame.copy()
    frame.columns = frame.columns.astype(str).str.strip()
    optional_unsw = {"src_port", "dst_port"} if dataset_key in {"unsw", "unsw-nb15"} else set()
    missing = [
        source for feature, source in mapping.items()
        if source not in frame.columns and feature not in optional_unsw
    ]
    if missing:
        raise ValueError(f"{dataset_key} dataset is missing required columns: {', '.join(missing)}")

    result = pd.DataFrame(index=frame.index)
    for feature, source in mapping.items():
        if source not in frame.columns and feature in optional_unsw:
            result[feature] = 0.0
        else:
            values = frame[source]
            result[feature] = values.map(_protocol_number) if feature == "protocol_number" else pd.to_numeric(values, errors="coerce")
    if dataset_key in {"cic", "cic-ids2017"}:
        result["duration"] = result["duration"] / 1_000_000
    return result.loc[:, NETWORK_FEATURES].replace([np.inf, -np.inf], np.nan)


def network_features_from_mapping(values: dict[str, Any]) -> pd.DataFrame:
    """Validate and shape one request against the same feature contract as training."""
    missing = [name for name in NETWORK_FEATURES if name not in values]
    extra = sorted(set(values) - set(NETWORK_FEATURES))
    if missing or extra:
        details = []
        if missing:
            details.append(f"missing features: {', '.join(missing)}")
        if extra:
            details.append(f"unknown features: {', '.join(extra)}")
        raise ValueError("; ".join(details))
    row = pd.DataFrame([{name: values[name] for name in NETWORK_FEATURES}])
    row = row.apply(pd.to_numeric, errors="coerce")
    if row.isna().any().any() or not np.isfinite(row.to_numpy(dtype=float)).all():
        raise ValueError("all network feature values must be finite numbers")
    if (row.loc[:, [name for name in NETWORK_FEATURES if name != "protocol_number"]] < 0).any().any():
        raise ValueError("duration, byte/packet counts, ports, and packet rate must be non-negative")
    if (
        float(row.at[0, "src_port"]) > 65535
        or float(row.at[0, "dst_port"]) > 65535
        or float(row.at[0, "protocol_number"]) > 255
    ):
        raise ValueError("ports must be at most 65535 and protocol_number at most 255")
    return row


def binary_labels(series: pd.Series, non_benign_is_positive: bool = False) -> pd.Series:
    """Normalize common CIC and UNSW label conventions (0=benign, 1=malicious)."""
    def convert(value: Any) -> int:
        if isinstance(value, (int, float, np.integer, np.floating)) and not pd.isna(value):
            return int(float(value) != 0)
        label = str(value).strip().lower()
        try:
            numeric = float(label)
        except ValueError:
            numeric = None
        if numeric is not None:
            return int(numeric != 0)
        if label in {"0", "benign", "normal", "benign traffic", "false"}:
            return 0
        if label in {"1", "attack", "malicious", "true", "phishing", "phish", "smishing", "spam"}:
            return 1
        if non_benign_is_positive and label:
            return 1
        raise ValueError(f"unrecognized class label: {value!r}")
    return series.map(convert).astype("int8")