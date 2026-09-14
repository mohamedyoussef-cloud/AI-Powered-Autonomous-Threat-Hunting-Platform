import csv
import json
from pathlib import Path
from collections import Counter


PROJECT_ROOT = Path(__file__).resolve().parents[3]

MASTER_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "environment"
    / "master_technique_eligibility_v0_1.csv"
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
    / "environment"
)

REPORT_DIR = (
    PROJECT_ROOT
    / "reports"
    / "environment"
)

CSV_OUTPUT = (
    OUTPUT_DIR
    / "master_telemetry_eligibility_v0_1.csv"
)

JSONL_OUTPUT = (
    OUTPUT_DIR
    / "master_telemetry_eligibility_v0_1.jsonl"
)

REPORT_OUTPUT = (
    REPORT_DIR
    / "master_telemetry_eligibility_v0_1_summary.json"
)


TELEMETRY_STATUS_MAP = {
    "full_component_evidence": {
        "telemetry_support_status": "supported_full",
        "telemetry_supported": True,
        "collection_gap": False,
        "requirements_unknown": False,
    },
    "partial_component_evidence": {
        "telemetry_support_status": "supported_partial",
        "telemetry_supported": True,
        "collection_gap": False,
        "requirements_unknown": False,
    },
    "not_observed": {
        "telemetry_support_status": "not_observed",
        "telemetry_supported": False,
        "collection_gap": True,
        "requirements_unknown": False,
    },
    "requirement_unspecified": {
        "telemetry_support_status": "requirements_unknown",
        "telemetry_supported": False,
        "collection_gap": False,
        "requirements_unknown": True,
    },
}


def read_csv(path):
    with path.open(
        "r",
        encoding="utf-8-sig",
        newline=""
    ) as f:
        return list(csv.DictReader(f))


def to_bool(value):
    return str(value).strip().lower() == "true"


def to_int(value):
    if value in (None, ""):
        return 0

    return int(float(value))


def to_float(value):
    if value in (None, ""):
        return None

    return float(value)


def main():
    if not MASTER_FILE.exists():
        raise FileNotFoundError(
            f"Missing master eligibility input: "
            f"{MASTER_FILE}"
        )

    if not TELEMETRY_FILE.exists():
        raise FileNotFoundError(
            f"Missing telemetry evidence input: "
            f"{TELEMETRY_FILE}"
        )

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    master_rows = read_csv(
        MASTER_FILE
    )

    telemetry_rows = read_csv(
        TELEMETRY_FILE
    )

    telemetry_by_id = {
        row["technique_id"]: row
        for row in telemetry_rows
    }

    output_rows = []

    missing_telemetry = []
    unknown_telemetry_statuses = []

    telemetry_counts_all = Counter()
    telemetry_counts_platform_eligible = Counter()
    current_hunt_counts = Counter()

    for master in master_rows:
        technique_id = master["technique_id"]

        telemetry = telemetry_by_id.get(
            technique_id
        )

        if telemetry is None:
            missing_telemetry.append(
                technique_id
            )
            continue

        evidence_status = (
            telemetry.get(
                "telemetry_evidence_status"
            )
            or ""
        ).strip()

        mapping = TELEMETRY_STATUS_MAP.get(
            evidence_status
        )

        if mapping is None:
            unknown_telemetry_statuses.append({
                "technique_id": technique_id,
                "status": evidence_status
            })

            mapping = {
                "telemetry_support_status": (
                    "unknown_status"
                ),
                "telemetry_supported": False,
                "collection_gap": False,
                "requirements_unknown": True,
            }

        platform_eligible = to_bool(
            master[
                "eligible_for_current_environment"
            ]
        )

        telemetry_support_status = mapping[
            "telemetry_support_status"
        ]

        telemetry_counts_all[
            telemetry_support_status
        ] += 1

        if platform_eligible:
            telemetry_counts_platform_eligible[
                telemetry_support_status
            ] += 1

        if not platform_eligible:
            current_hunt_status = (
                "ineligible_platform"
            )

            current_hunt_eligible = False

            current_hunt_reason = (
                "Technique does not match the "
                "currently discovered environment "
                "platforms."
            )

        elif mapping["collection_gap"]:
            current_hunt_status = (
                "collection_gap"
            )

            current_hunt_eligible = False

            current_hunt_reason = (
                "Technique matches the environment "
                "platform, but required telemetry "
                "evidence was not observed."
            )

        elif mapping["requirements_unknown"]:
            current_hunt_status = (
                "telemetry_requirements_unknown"
            )

            current_hunt_eligible = False

            current_hunt_reason = (
                "Technique matches the environment "
                "platform, but telemetry requirements "
                "cannot currently be evaluated."
            )

        elif mapping["telemetry_supported"]:
            current_hunt_status = (
                "eligible_for_prioritization"
            )

            current_hunt_eligible = True

            current_hunt_reason = (
                "Technique matches the dynamically "
                "discovered environment and has "
                "supporting telemetry evidence."
            )

        else:
            current_hunt_status = (
                "not_eligible"
            )

            current_hunt_eligible = False

            current_hunt_reason = (
                "Technique is not currently eligible "
                "for prioritization."
            )

        current_hunt_counts[
            current_hunt_status
        ] += 1

        output_rows.append({
            "technique_id": technique_id,
            "technique_name": master[
                "technique_name"
            ],
            "is_subtechnique": master[
                "is_subtechnique"
            ],
            "parent_technique_id": master[
                "parent_technique_id"
            ],
            "tactics": master[
                "tactics"
            ],
            "technique_platforms": master[
                "technique_platforms"
            ],
            "environment_platforms": master[
                "environment_platforms"
            ],
            "matched_platforms": master[
                "matched_platforms"
            ],
            "platform_eligibility_status": master[
                "platform_eligibility_status"
            ],
            "platform_eligible": (
                platform_eligible
            ),

            "telemetry_evidence_status": (
                evidence_status
            ),
            "telemetry_support_status": (
                telemetry_support_status
            ),
            "telemetry_supported": mapping[
                "telemetry_supported"
            ],
            "collection_gap": mapping[
                "collection_gap"
            ],
            "telemetry_requirements_unknown": (
                mapping[
                    "requirements_unknown"
                ]
            ),

            "data_components_referenced": (
                to_int(
                    telemetry.get(
                        "data_components_referenced"
                    )
                )
            ),
            "data_components_with_any_evidence": (
                to_int(
                    telemetry.get(
                        "data_components_with_any_evidence"
                    )
                )
            ),
            "data_components_with_exact_event_evidence": (
                to_int(
                    telemetry.get(
                        "data_components_with_exact_event_evidence"
                    )
                )
            ),
            "component_evidence_coverage_pct": (
                to_float(
                    telemetry.get(
                        "component_evidence_coverage_pct"
                    )
                )
            ),
            "exact_event_component_coverage_pct": (
                to_float(
                    telemetry.get(
                        "exact_event_component_coverage_pct"
                    )
                )
            ),
            "evidence_sources": telemetry.get(
                "evidence_sources",
                ""
            ),

            "current_hunt_status": (
                current_hunt_status
            ),
            "current_hunt_eligible": (
                current_hunt_eligible
            ),
            "current_hunt_reason": (
                current_hunt_reason
            ),

            "product_scope": "master_catalog"
        })

    output_rows.sort(
        key=lambda row: row["technique_id"]
    )

    validation_errors = []

    if len(master_rows) != 697:
        validation_errors.append(
            "Master catalog does not contain "
            "697 active techniques"
        )

    if len(output_rows) != len(master_rows):
        validation_errors.append(
            "Output count does not match "
            "master catalog count"
        )

    if missing_telemetry:
        validation_errors.append(
            f"{len(missing_telemetry)} techniques "
            f"missing telemetry evidence records"
        )

    if unknown_telemetry_statuses:
        validation_errors.append(
            f"{len(unknown_telemetry_statuses)} "
            f"unknown telemetry evidence statuses"
        )

    validation = (
        "PASS"
        if not validation_errors
        else "FAIL"
    )

    fields = [
        "technique_id",
        "technique_name",
        "is_subtechnique",
        "parent_technique_id",
        "tactics",
        "technique_platforms",
        "environment_platforms",
        "matched_platforms",
        "platform_eligibility_status",
        "platform_eligible",
        "telemetry_evidence_status",
        "telemetry_support_status",
        "telemetry_supported",
        "collection_gap",
        "telemetry_requirements_unknown",
        "data_components_referenced",
        "data_components_with_any_evidence",
        "data_components_with_exact_event_evidence",
        "component_evidence_coverage_pct",
        "exact_event_component_coverage_pct",
        "evidence_sources",
        "current_hunt_status",
        "current_hunt_eligible",
        "current_hunt_reason",
        "product_scope",
    ]

    with CSV_OUTPUT.open(
        "w",
        encoding="utf-8",
        newline=""
    ) as f:
        writer = csv.DictWriter(
            f,
            fieldnames=fields
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

    report = {
        "component": (
            "master_telemetry_eligibility"
        ),
        "version": "0.1",
        "product_mode": True,
        "master_catalog_techniques": len(
            master_rows
        ),
        "output_techniques": len(
            output_rows
        ),
        "telemetry_support_all_techniques": dict(
            telemetry_counts_all
        ),
        "telemetry_support_platform_eligible": dict(
            telemetry_counts_platform_eligible
        ),
        "current_hunt_status_counts": dict(
            current_hunt_counts
        ),
        "missing_telemetry_records": (
            missing_telemetry
        ),
        "unknown_telemetry_statuses": (
            unknown_telemetry_statuses
        ),
        "validation_errors": (
            validation_errors
        ),
        "status": validation
    }

    REPORT_OUTPUT.write_text(
        json.dumps(
            report,
            indent=2,
            ensure_ascii=False
        ),
        encoding="utf-8"
    )

    platform_eligible_count = sum(
        1
        for row in output_rows
        if row["platform_eligible"]
    )

    prioritization_count = sum(
        1
        for row in output_rows
        if row["current_hunt_eligible"]
    )

    print(
        "Dynamic Telemetry Eligibility v0.1"
    )
    print(
        "----------------------------------"
    )

    print(
        f"Master catalog          : "
        f"{len(master_rows)}"
    )

    print(
        f"Platform eligible       : "
        f"{platform_eligible_count}"
    )

    print()
    print(
        "Telemetry support within "
        "current platform:"
    )

    for key in [
        "supported_full",
        "supported_partial",
        "not_observed",
        "requirements_unknown",
        "unknown_status",
    ]:
        print(
            f"  {key:<22}: "
            f"{telemetry_counts_platform_eligible.get(key, 0)}"
        )

    print()

    print(
        f"Eligible prioritization : "
        f"{prioritization_count}"
    )

    print(
        f"Collection gaps         : "
        f"{current_hunt_counts.get('collection_gap', 0)}"
    )

    print(
        f"Requirements unknown    : "
        f"{current_hunt_counts.get('telemetry_requirements_unknown', 0)}"
    )

    print(
        f"Platform ineligible     : "
        f"{current_hunt_counts.get('ineligible_platform', 0)}"
    )

    print(
        f"Missing records         : "
        f"{len(missing_telemetry)}"
    )

    print(
        f"Unknown statuses        : "
        f"{len(unknown_telemetry_statuses)}"
    )

    print(
        f"Validation              : "
        f"{validation}"
    )

    print()
    print(f"CSV    : {CSV_OUTPUT}")
    print(f"JSONL  : {JSONL_OUTPUT}")
    print(f"Report : {REPORT_OUTPUT}")


if __name__ == "__main__":
    main()