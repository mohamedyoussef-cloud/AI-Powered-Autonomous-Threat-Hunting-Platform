from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
WORKSPACE_ROOT = PROJECT_ROOT.parent

DEFAULT_PROFILING_DIR = (
    WORKSPACE_ROOT
    / "datasets"
    / "processed"
    / "botsv3"
    / "profiling"
)


def as_int(value: str | None) -> int:
    if value is None or value == "":
        return 0
    return int(float(value))


def as_float(value: str | None):
    if value is None or value == "":
        return None
    try:
        return float(value)
    except ValueError:
        return None


def safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", value)


def infer_type(numeric_count: int, present_count: int) -> str:
    if present_count <= 0:
        return "unknown"

    if numeric_count == 0:
        return "non_numeric"

    if numeric_count == present_count:
        return "numeric"

    return "mixed_numeric_text"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build the BOTS v3 master field profile."
    )

    parser.add_argument(
        "--profiling-dir",
        type=Path,
        default=DEFAULT_PROFILING_DIR,
        help=(
            "BOTS profiling directory. Default: "
            "<workspace>/datasets/processed/botsv3/profiling"
        ),
    )

    args = parser.parse_args()

    profiling_dir = args.profiling_dir.resolve()
    profile_dir = profiling_dir / "field_profiles"

    search_inventory = (
        profiling_dir
        / "sourcetype_search_inventory.csv"
    )

    master_output = (
        profiling_dir
        / "botsv3_master_field_profile.csv"
    )

    summary_output = (
        profiling_dir
        / "botsv3_master_field_profile_summary.json"
    )

    if not search_inventory.exists():
        raise FileNotFoundError(
            f"Search inventory not found: {search_inventory}"
        )

    with search_inventory.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as f:
        inventory = list(csv.DictReader(f))

    if len(inventory) != 107:
        raise RuntimeError(
            "Expected 107 sourcetypes in search inventory, "
            f"found {len(inventory)}"
        )

    master_rows = []
    missing_profiles = []

    for sequence, inv in enumerate(
        inventory,
        start=1,
    ):
        sourcetype = inv["sourcetype"]
        search_rows = as_int(inv["search_rows"])
        unique_events = as_int(inv["unique_events"])

        profile_name = (
            f"{sequence:03d}_{safe_name(sourcetype)}.csv"
        )

        profile_path = (
            profile_dir / profile_name
        )

        if not profile_path.exists():
            missing_profiles.append(
                str(profile_path)
            )
            continue

        with profile_path.open(
            "r",
            encoding="utf-8-sig",
            newline="",
        ) as f:
            profile_rows = list(
                csv.DictReader(f)
            )

        if not profile_rows:
            raise RuntimeError(
                f"Empty profile: {profile_path}"
            )

        for row in profile_rows:
            present_count = as_int(
                row.get("count")
            )

            distinct_count = as_int(
                row.get("distinct_count")
            )

            numeric_count = as_int(
                row.get("numeric_count")
            )

            availability_pct = (
                (present_count / search_rows) * 100.0
                if search_rows > 0
                else 0.0
            )

            availability_pct = max(
                0.0,
                min(100.0, availability_pct),
            )

            missing_count = max(
                search_rows - present_count,
                0,
            )

            missingness_pct = (
                100.0 - availability_pct
            )

            numeric_coverage_pct = (
                (numeric_count / present_count) * 100.0
                if present_count > 0
                else 0.0
            )

            master_rows.append(
                {
                    "sourcetype": sourcetype,
                    "field": row.get("field", ""),
                    "search_rows": search_rows,
                    "unique_events": unique_events,
                    "field_present_count": present_count,
                    "availability_pct": round(
                        availability_pct,
                        6,
                    ),
                    "missing_count": missing_count,
                    "missingness_pct": round(
                        missingness_pct,
                        6,
                    ),
                    "distinct_count": distinct_count,
                    "cardinality_exact": row.get(
                        "is_exact",
                        "",
                    ),
                    "numeric_count": numeric_count,
                    "numeric_coverage_pct": round(
                        numeric_coverage_pct,
                        6,
                    ),
                    "min": row.get("min", ""),
                    "max": row.get("max", ""),
                    "mean": row.get("mean", ""),
                    "stdev": row.get("stdev", ""),
                    "inferred_type": infer_type(
                        numeric_count=numeric_count,
                        present_count=present_count,
                    ),
                }
            )

    if missing_profiles:
        raise RuntimeError(
            "Missing field profiles:\n"
            + "\n".join(missing_profiles)
        )

    fieldnames = [
        "sourcetype",
        "field",
        "search_rows",
        "unique_events",
        "field_present_count",
        "availability_pct",
        "missing_count",
        "missingness_pct",
        "distinct_count",
        "cardinality_exact",
        "numeric_count",
        "numeric_coverage_pct",
        "min",
        "max",
        "mean",
        "stdev",
        "inferred_type",
    ]

    with master_output.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as f:
        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames,
        )
        writer.writeheader()
        writer.writerows(master_rows)

    represented_sourcetypes = sorted(
        {
            row["sourcetype"]
            for row in master_rows
        }
    )

    invalid_availability = [
        row
        for row in master_rows
        if not (
            0
            <= row["availability_pct"]
            <= 100
        )
    ]

    invalid_missingness = [
        row
        for row in master_rows
        if not (
            0
            <= row["missingness_pct"]
            <= 100
        )
    ]

    summary = {
        "dataset": "BOTS v3",
        "sourcetypes_expected": 107,
        "sourcetypes_profiled": len(
            represented_sourcetypes
        ),
        "master_field_rows": len(
            master_rows
        ),
        "unique_searchable_events": sum(
            as_int(row["unique_events"])
            for row in inventory
        ),
        "search_time_rows": sum(
            as_int(row["search_rows"])
            for row in inventory
        ),
        "missing_profile_count": len(
            missing_profiles
        ),
        "invalid_availability_rows": len(
            invalid_availability
        ),
        "invalid_missingness_rows": len(
            invalid_missingness
        ),
        "status": (
            "PASS"
            if (
                len(represented_sourcetypes) == 107
                and not missing_profiles
                and not invalid_availability
                and not invalid_missingness
            )
            else "FAIL"
        ),
    }

    with summary_output.open(
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            summary,
            f,
            indent=2,
        )

    print(
        json.dumps(
            summary,
            indent=2,
        )
    )

    print()
    print(
        f"Master profile: {master_output}"
    )
    print(
        f"Summary:        {summary_output}"
    )


if __name__ == "__main__":
    main()
