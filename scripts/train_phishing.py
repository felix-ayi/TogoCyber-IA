"""Command-line entry point for phishing model training."""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ml.phishing.train import train


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", default="data/raw/phishing.csv")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    try:
        report = train(args.data, seed=args.seed)
    except (FileNotFoundError, ValueError) as exc:
        parser.error(str(exc))
    print(report)


if __name__ == "__main__":
    main()