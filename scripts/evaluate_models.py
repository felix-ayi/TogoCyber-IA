"""Print saved model evaluation metadata without fabricating absent metrics."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ml.common.utils import REGISTRY_PATH


def main() -> None:
    if not REGISTRY_PATH.is_file() or REGISTRY_PATH.stat().st_size == 0:
        print("No trained model metadata. Train with the real datasets first.")
        return
    registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    if not registry:
        print("No trained model metadata. Train with the real datasets first.")
        return
    print(json.dumps(registry, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()