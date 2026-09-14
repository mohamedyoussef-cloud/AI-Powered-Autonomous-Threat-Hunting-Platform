#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def run(script: Path, *args: str) -> None:
    command = [sys.executable, str(script), *args]
    print("+", " ".join(command), flush=True)
    subprocess.run(command, check=True)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--project-root", type=Path, required=True)
    p.add_argument("--attack-zip", type=Path, required=True)
    p.add_argument("--sigma-zip", type=Path, required=True)
    args = p.parse_args()
    scripts = args.project_root / "scripts"
    common = ["--project-root", str(args.project_root)]
    run(scripts / "ingest_uploaded_sources.py", "--attack-zip", str(args.attack_zip), "--sigma-zip", str(args.sigma_zip), *common)
    run(scripts / "prepare_attack.py", *common)
    run(scripts / "prepare_sigma.py", *common)
    run(scripts / "build_coverage_report.py", *common)
    run(scripts / "validate_samples.py")
    run(scripts / "validate_processed.py")
    run(scripts / "bootstrap_check.py")


if __name__ == "__main__":
    main()
