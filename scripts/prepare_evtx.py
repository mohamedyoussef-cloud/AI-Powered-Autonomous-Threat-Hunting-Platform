#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from threat_hunting_data.evtx_preparation import prepare_evtx_dataset


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare EVTX-ATTACK-SAMPLES using the repository-provided parsed CSV and raw file inventory.")
    parser.add_argument("--source-root", required=True, type=Path, help="Extracted EVTX-ATTACK-SAMPLES repository root")
    parser.add_argument("--project-root", type=Path, default=PROJECT_ROOT)
    parser.add_argument("--source-archive", type=Path, default=None, help="Optional original ZIP for checksum lineage")
    args = parser.parse_args()
    summary = prepare_evtx_dataset(args.source_root.resolve(), args.project_root.resolve(), args.source_archive.resolve() if args.source_archive else None)
    print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
