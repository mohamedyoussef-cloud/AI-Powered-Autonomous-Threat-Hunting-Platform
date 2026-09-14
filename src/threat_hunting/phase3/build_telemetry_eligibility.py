import csv
import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]

PLATFORM_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "phase3"
    / "attack_platform_eligibility.csv"
)

TELEMETRY_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "telemetry"
    / "integrated"
    / "technique_telemetry_evidence_summary_v1_1.csv"
)

OUTPUT_DIR = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "phase3"
)

REPORT_DIR = (
    PROJECT_ROOT
    / "reports"
    / "phase3"
)

CSV_OUTPUT = OUTPUT_DIR / "attack_telemetry_eligibility.csv"
JSONL_OUTPUT = OUTPUT_DIR / "attack_telemetry_eligibility.jsonl"
SUMMARY_OUTPUT = REPORT_DIR / "telemetry_eligibility_summary.json"


STATUS_MAP = {
    "full_component_evidence": {
        "telemetry_class": "telemetry_supported_full",
        "telemetry_supported": True,
        "reason": (
            "Evidence is available for all referenced ATT&CK "
            "data components."
        ),
    },
    "partial_component_evidence": {
        "telemetry_class": "telemetry_supported_partial",
        "telemetry_supported": True,
        "reason": (
            "Some referenced ATT&CK data components have evidence, "
            "but coverage is incomplete."
        ),
    },
    "not_observed": {
        "telemetry_class": "collection_gap",
        "telemetry_supported": False,
        "reason": (
            "Required telemetry evidence was not observed in the "
            "prepared telemetry sources."
        ),
    },
    "requirement_unspecified": {
        "telemetry_class": "requirements_unknown",
        "telemetry_supported": False,
        "reason": (
            "ATT&CK telemetry requirements are not sufficiently "
            "specified for evidence assessment."
        ),
    },
}


def read_csv(path):
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def to_int(value):
    if value in (None, ""):
        return 0
    return int(float(value))


def to_float(value):
    if value in (None, ""):
        return None
    return float(value)


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    if not PLATFORM_FILE.exists():
        raise FileNotFoundError(
            f"Platform eligibility file not found: {PLATFORM_FILE}"
        )

    if not TELEMETRY_FILE.exists():
        raise FileNotFoundError(
            f"Telemetry summary file not found: {TELEMETRY_FILE}"
        )

    platform_rows = read_csv(PLATFORM_FILE)
    telemetry_rows = read_csv(TELEMETRY_FILE)

    telemetry_by_id = {
        row["technique_id"]: row
        for row in telemetry_rows
    }

    platform_eligible = [
        row
        for row in platform_rows
        if str(row.get("platform_eligible", "")).strip().lower() == "true"
    ]

    output_rows = []

    class_counts = {
        "telemetry_supported_full": 0,
        "telemetry_supported_partial": 0,
        "collection_gap": 0,
        "requirements_unknown": 0,
    }

    missing_telemetry_records = []
    unknown_statuses = []

    for platform_row in platform_eligible:
        technique_id = platform_row["technique_id"]

        telemetry = telemetry_by_id.get(technique_id)

        if telemetry is None:
            missing_telemetry_records.append(technique_id)
            continue

        raw_status = telemetry.get(
            "telemetry_evidence_status", ""
        ).strip()

        mapping = STATUS_MAP.get(raw_status)

        if mapping is None:
            unknown_statuses.append(
                {
                    "technique_id": technique_id,
                    "status": raw_status,
                }
            )
            continue

        telemetry_class = mapping["telemetry_class"]
        class_counts[telemetry_class] += 1

        row = {
            "technique_id": technique_id,
            "technique_name": telemetry.get("technique_name"),
            "platform_status": platform_row.get("platform_status"),
            "matched_platforms": platform_row.get("matched_platforms"),
            "telemetry_evidence_status": raw_status,
            "telemetry_class": telemetry_class,
            "telemetry_supported": mapping["telemetry_supported"],
            "continue_to_scoring": True,

            "data_components_referenced": to_int(
                telemetry.get("data_components_referenced")
            ),
            "data_components_with_any_evidence": to_int(
                telemetry.get(
                    "data_components_with_any_evidence"
                )
            ),
            "data_components_with_exact_event_evidence": to_int(
                telemetry.get(
                    "data_components_with_exact_event_evidence"
                )
            ),
            "data_components_source_only": to_int(
                telemetry.get("data_components_source_only")
            ),

            "component_evidence_coverage_pct": to_float(
                telemetry.get(
                    "component_evidence_coverage_pct"
                )
            ),
            "exact_event_component_coverage_pct": to_float(
                telemetry.get(
                    "exact_event_component_coverage_pct"
                )
            ),

            "evidence_sources": telemetry.get("evidence_sources"),
            "reason": mapping["reason"],
        }

        output_rows.append(row)

    validation_status = "PASS"

    if missing_telemetry_records:
        validation_status = "FAIL"

    if unknown_statuses:
        validation_status = "FAIL"

    if len(output_rows) != len(platform_eligible):
        validation_status = "FAIL"

    fieldnames = [
        "technique_id",
        "technique_name",
        "platform_status",
        "matched_platforms",
        "telemetry_evidence_status",
        "telemetry_class",
        "telemetry_supported",
        "continue_to_scoring",
        "data_components_referenced",
        "data_components_with_any_evidence",
        "data_components_with_exact_event_evidence",
        "data_components_source_only",
        "component_evidence_coverage_pct",
        "exact_event_component_coverage_pct",
        "evidence_sources",
        "reason",
    ]

    with CSV_OUTPUT.open(
        "w",
        encoding="utf-8",
        newline=""
    ) as f:
        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames
        )
        writer.writeheader()
        writer.writerows(output_rows)

    with JSONL_OUTPUT.open(
        "w",
        encoding="utf-8",
        newline="\n"
    ) as f:
        for row in output_rows:
            f.write(
                json.dumps(
                    row,
                    ensure_ascii=False
                )
                + "\n"
            )

    summary = {
        "phase": 3,
        "component": "telemetry_eligibility",
        "input_platform_eligible": len(platform_eligible),
        "output_records": len(output_rows),

        "hunt_ready": class_counts["telemetry_supported_full"],
        "limited_telemetry": class_counts[
            "limited_telemetry"
        ],
        "collection_gap": class_counts[
            "collection_gap"
        ],
        "requirements_unknown": class_counts[
            "requirements_unknown"
        ],

        "missing_telemetry_records": (
            missing_telemetry_records
        ),
        "unknown_statuses": unknown_statuses,

        "status": validation_status,
    }

    with SUMMARY_OUTPUT.open(
        "w",
        encoding="utf-8"
    ) as f:
        json.dump(
            summary,
            f,
            indent=2,
            ensure_ascii=False
        )

    print(
        f"Platform-compatible techniques : "
        f"{len(platform_eligible)}"
    )
    print(
        f"Hunt ready                     : "
        f"{class_counts['hunt_ready']}"
    )
    print(
        f"Limited telemetry              : "
        f"{class_counts['limited_telemetry']}"
    )
    print(
        f"Collection gap                 : "
        f"{class_counts['collection_gap']}"
    )
    print(
        f"Requirements unknown           : "
        f"{class_counts['requirements_unknown']}"
    )
    print(
        f"Continue to scoring            : "
        f"{len(output_rows)}"
    )
    print(
        f"Missing telemetry records      : "
        f"{len(missing_telemetry_records)}"
    )
    print(
        f"Unknown telemetry statuses     : "
        f"{len(unknown_statuses)}"
    )
    print(
        f"Validation                     : "
        f"{validation_status}"
    )
    print()
    print(f"CSV    : {CSV_OUTPUT}")
    print(f"JSONL  : {JSONL_OUTPUT}")
    print(f"Report : {SUMMARY_OUTPUT}")


if __name__ == "__main__":
    main()