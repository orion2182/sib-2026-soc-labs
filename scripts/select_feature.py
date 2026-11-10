"""Select the active Spec Kit feature for this local checkout."""

from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPECS = ROOT / "specs"


def main() -> int:
    choices = sorted(p.name for p in SPECS.iterdir() if p.is_dir() and (p / "spec.md").is_file())
    if len(sys.argv) != 2 or sys.argv[1] not in choices:
        print("Usage: python3 scripts/select_feature.py <feature-name>")
        print("Available features:")
        for name in choices:
            print(f"  {name}")
        return 0 if len(sys.argv) == 2 and sys.argv[1] == "--list" else 2

    feature = sys.argv[1]
    selected = ROOT / ".specify" / "feature.json"
    selected.write_text(json.dumps({"feature_directory": f"specs/{feature}"}) + "\n", encoding="utf-8")
    print(f"Active Spec Kit feature: {feature}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
