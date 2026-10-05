"""Command-line entry point for network model training."""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ml.network.train import train


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", default="data/raw/cic_ids2017", help="CIC/UNSW training CSV or directory of CSV files")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--max-rows", type=int, default=250_000, help="stratified sample limit; 0 trains on all rows")
    parser.add_argument("--dataset", choices=("cic", "unsw"), default="cic")
    parser.add_argument("--test-data", help="independent held-out UNSW CSV (required when dataset=unsw)")
    args = parser.parse_args()
    try:
        report = train(
            args.data,
            seed=args.seed,
            max_rows=args.max_rows or None,
            dataset=args.dataset,
            test_dataset_path=args.test_data,
        )
    except (FileNotFoundError, ValueError) as exc:
        parser.error(str(exc))
    print(report)


if __name__ == "__main__":
    main()