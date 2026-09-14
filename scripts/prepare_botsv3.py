#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from threat_hunting_data.bots_preparation import prepare_botsv3_dataset


def main() -> None:
    parser = argparse.ArgumentParser(description="Profile and prepare the pre-indexed BOTS v3 Splunk dataset.")
    parser.add_argument("--source-archive", required=True, type=Path)
    parser.add_argument("--project-root", type=Path, default=PROJECT_ROOT)
    args = parser.parse_args()
    summary = prepare_botsv3_dataset(args.source_archive, args.project_root)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
