"""Download pinned, public demo datasets and verify their published SHA-256 hashes."""

from __future__ import annotations

import hashlib
import json
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
SOURCES = {
    "unsw_train": {
        "url": "https://huggingface.co/datasets/Mireu-Lab/UNSW-NB15/resolve/3eb02c4a0a29866b7abcb5ef77c45cf4fcc8f6b0/train.csv",
        "path": ROOT / "data" / "raw" / "unsw_nb15" / "train.csv",
        "sha256": "734fe6642edf758f7c94d7d9149426b49d202fe8e7bf0bef47392489c3c0a559",
    },
    "unsw_test": {
        "url": "https://huggingface.co/datasets/Mireu-Lab/UNSW-NB15/resolve/3eb02c4a0a29866b7abcb5ef77c45cf4fcc8f6b0/test.csv",
        "path": ROOT / "data" / "raw" / "unsw_nb15" / "test.csv",
        "sha256": "bec7dd5ec88dc2a0ccc7a07879d338395ed7421750f675fd0339e07dfe0648fa",
    },
    "phishing": {
        "url": "https://huggingface.co/datasets/zefang-liu/phishing-email-dataset/resolve/34085a032c123ca237f314a01a67909cdea35e34/Phishing_Email.csv",
        "path": ROOT / "data" / "raw" / "phishing" / "Phishing_Email.csv",
        "sha256": "18ef4fff1acb8986f0ab01e83ede6025420c829656af5a377560fce17e153b97",
    },
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download(name: str, source: dict[str, str | Path]) -> Path:
    destination = Path(source["path"])
    expected = str(source["sha256"])
    if destination.exists():
        actual = sha256(destination)
        if actual != expected:
            raise ValueError(f"{destination} already exists but its SHA-256 does not match the pinned source")
        print(f"Verified existing file: {destination.relative_to(ROOT)}")
        return destination
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".part")
    request = urllib.request.Request(
        str(source["url"]),
        headers={"User-Agent": "TogoCyber-AI-demo-dataset-loader/1.0"},
    )
    digest = hashlib.sha256()
    try:
        with urllib.request.urlopen(request, timeout=60) as response, temporary.open("wb") as output:
            while chunk := response.read(1024 * 1024):
                digest.update(chunk)
                output.write(chunk)
        actual = digest.hexdigest()
        if actual != expected:
            raise ValueError(f"{name}: downloaded SHA-256 {actual} does not match pinned SHA-256 {expected}")
        temporary.replace(destination)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    print(f"Downloaded and verified: {destination.relative_to(ROOT)}")
    return destination


def validate_sources(paths: dict[str, Path]) -> None:
    network_required = {"dur", "proto", "spkts", "dpkts", "sbytes", "dbytes", "rate", "label"}
    for key in ("unsw_train", "unsw_test"):
        columns = {str(column).strip().lower() for column in pd.read_csv(paths[key], nrows=0).columns}
        missing = network_required - columns
        if missing:
            raise ValueError(f"{key} CSV is missing UNSW columns: {', '.join(sorted(missing))}")
    phishing_columns = set(pd.read_csv(paths["phishing"], nrows=0).columns)
    if not {"Email Text", "Email Type"} <= phishing_columns:
        raise ValueError("phishing CSV must contain the pinned source columns 'Email Text' and 'Email Type'")
    labels = set(pd.read_csv(paths["phishing"], usecols=["Email Type"])["Email Type"].dropna().astype(str).str.strip())
    if not {"Safe Email", "Phishing Email"} <= labels:
        raise ValueError("phishing dataset does not contain both expected labels: Safe Email, Phishing Email")


def main() -> int:
    try:
        paths = {name: download(name, source) for name, source in SOURCES.items()}
        validate_sources(paths)
        manifest = {
            "downloaded_at_utc": datetime.now(timezone.utc).isoformat(),
            "notice": "Public demo mirrors; review their dataset cards and usage terms before redistribution or commercial use.",
            "datasets": {
                name: {
                    "url": str(source["url"]),
                    "sha256": str(source["sha256"]),
                    "file": str(Path(source["path"]).relative_to(ROOT)),
                }
                for name, source in SOURCES.items()
            },
        }
        manifest_path = ROOT / "data" / "raw" / "demo_sources.json"
        manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"Source validation passed. Manifest: {manifest_path.relative_to(ROOT)}")
        return 0
    except (OSError, ValueError, urllib.error.URLError, pd.errors.ParserError) as exc:
        print(f"Dataset download/validation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
