#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "data" / "processed" / "telemetry" / "botsv3"


def csv_sum(path: Path, field: str) -> int:
    with path.open(newline="", encoding="utf-8") as stream:
        return sum(int(row[field]) for row in csv.DictReader(stream))


def main() -> None:
    summary = json.loads((BASE / "botsv3_source_summary.json").read_text(encoding="utf-8"))
    failures: list[str] = []
    checks = {
        "official_md5": summary["md5"] == "d7ccca99a01cff070dff3c139cdc10eb",
        "active_bucket_count": summary["active_bucket_count"] == 16,
        "manifest_event_count": summary["manifest_event_count"] == 2030269,
        "sourcetype_reconciliation": csv_sum(BASE / "sourcetype_profile.csv", "event_count") == summary["manifest_event_count"],
        "host_reconciliation": csv_sum(BASE / "host_profile.csv", "event_count") == summary["manifest_event_count"],
        "source_reconciliation": csv_sum(BASE / "source_profile.csv", "event_count") == summary["manifest_event_count"],
        "scenario_plus_admin": summary["scenario_telemetry_event_count"] + summary["administrative_event_count"] == summary["manifest_event_count"],
        "disabled_bucket_is_separate": summary["disabled_bucket_event_count"] == 2,
        "sourcetypes": summary["unique_sourcetypes"] == 107,
    }
    failures.extend(name for name, passed in checks.items() if not passed)
    result = {"checks": checks, "failure_count": len(failures), "failures": failures}
    (ROOT / "reports" / "botsv3_quality_validation.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
