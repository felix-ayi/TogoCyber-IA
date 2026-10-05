"""Prepare a local training CSV from a licensed corpus and consented annotations."""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ml.phishing.preprocessing import prepare_training_corpus


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--public", default="data/raw/phishing.csv")
    parser.add_argument("--annotations", default="data/annotations/togolese_examples.csv")
    parser.add_argument("--output", default="data/raw/phishing_with_togolese.csv")
    args = parser.parse_args()
    try:
        report = prepare_training_corpus(args.public, args.annotations, args.output)
    except (FileNotFoundError, FileExistsError, ValueError) as exc:
        parser.error(str(exc))
    print(report)


if __name__ == "__main__":
    main()
