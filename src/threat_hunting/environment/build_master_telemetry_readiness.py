import csv
import json
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]

INPUT_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "environment"
    / "master_telemetry_eligibility_v0_1.csv"
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
    / "master_telemetry_readiness_v0_1.csv"
)

JSONL_OUTPUT = (
    OUTPUT_DIR
    / "master_telemetry_readiness_v0_1.jsonl"
)

REPORT_OUTPUT = (
    REPORT_DIR
    / "master_telemetry_readiness_v0_1_summary.json"
)


COMPONENT_WEIGHT = 0.30
EXACT_EVENT_WEIGHT = 0.70


def read_csv(path):
    with path.open(
        "r",
        encoding="utf-8-sig",
        newline=""
    ) as f:
        return list(csv.DictReader(f))


def to_bool(value):
    return str(value).strip().lower() == "true"


def to_float(value):
    if value in (None, ""):
        return None

    return float(value)


def classify_readiness(score):
    if score is None:
        return "Unknown"

    if score >= 80:
        return "High"

    if score >= 50:
        return "Medium"

    return "Low"


def main():
    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"Missing input: {INPUT_FILE}"
        )

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    rows = read_csv(
        INPUT_FILE
    )

    output_rows = []

    class_counts_all = Counter()
    class_counts_hunt_eligible = Counter()

    scored_count = 0
    not_applicable_count = 0
    unknown_count = 0

    scored_values = []

    for row in rows:
        platform_eligible = to_bool(
            row["platform_eligible"]
        )

        hunt_eligible = to_bool(
            row["current_hunt_eligible"]
        )

        component_coverage = to_float(
            row[
                "component_evidence_coverage_pct"
            ]
        )

        exact_coverage = to_float(
            row[
                "exact_event_component_coverage_pct"
            ]
        )

        if not platform_eligible:
            readiness_score = None
            readiness_class = "Not Applicable"
            readiness_reason = (
                "Technique is not compatible with "
                "the currently discovered environment."
            )

            not_applicable_count += 1

        elif (
            component_coverage is None
            or exact_coverage is None
        ):
            readiness_score = None
            readiness_class = "Unknown"
            readiness_reason = (
                "Telemetry readiness cannot be calculated "
                "because required coverage values are unavailable."
            )

            unknown_count += 1

        else:
            readiness_score = round(
                (
                    COMPONENT_WEIGHT
                    * component_coverage
                )
                + (
                    EXACT_EVENT_WEIGHT
                    * exact_coverage
                ),
                2
            )

            readiness_class = classify_readiness(
                readiness_score
            )

            readiness_reason = (
                "Calculated from telemetry component "
                "coverage and exact-event component coverage."
            )

            scored_count += 1
            scored_values.append(
                readiness_score
            )

        class_counts_all[
            readiness_class
        ] += 1

        if hunt_eligible:
            class_counts_hunt_eligible[
                readiness_class
            ] += 1

        output_rows.append({
            "technique_id": row[
                "technique_id"
            ],
            "technique_name": row[
                "technique_name"
            ],

            "platform_eligible": (
                platform_eligible
            ),

            "current_hunt_eligible": (
                hunt_eligible
            ),

            "telemetry_support_status": row[
                "telemetry_support_status"
            ],

            "component_evidence_coverage_pct": (
                component_coverage
            ),

            "exact_event_component_coverage_pct": (
                exact_coverage
            ),

            "telemetry_readiness_score": (
                readiness_score
            ),

            "telemetry_readiness_class": (
                readiness_class
            ),

            "telemetry_readiness_reason": (
                readiness_reason
            ),

            "telemetry_readiness_formula": (
                "0.30 * component_evidence_coverage_pct "
                "+ 0.70 * exact_event_component_coverage_pct"
            ),

            "evidence_sources": row[
                "evidence_sources"
            ],

            "product_scope": (
                "master_catalog"
            )
        })

    output_rows.sort(
        key=lambda row: row["technique_id"]
    )

    validation_errors = []

    if len(rows) != 697:
        validation_errors.append(
            "Input does not contain 697 "
            "active ATT&CK techniques"
        )

    if len(output_rows) != 697:
        validation_errors.append(
            "Output does not contain 697 techniques"
        )

    validation = (
        "PASS"
        if not validation_errors
        else "FAIL"
    )

    fields = [
        "technique_id",
        "technique_name",
        "platform_eligible",
        "current_hunt_eligible",
        "telemetry_support_status",
        "component_evidence_coverage_pct",
        "exact_event_component_coverage_pct",
        "telemetry_readiness_score",
        "telemetry_readiness_class",
        "telemetry_readiness_reason",
        "telemetry_readiness_formula",
        "evidence_sources",
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
        writer.writerows(
            output_rows
        )

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
            "master_telemetry_readiness"
        ),
        "version": "0.1",
        "product_mode": True,

        "master_catalog_techniques": (
            len(rows)
        ),

        "scored_techniques": (
            scored_count
        ),

        "not_applicable_platform": (
            not_applicable_count
        ),

        "unknown_readiness": (
            unknown_count
        ),

        "readiness_class_counts_all": dict(
            class_counts_all
        ),

        "readiness_class_counts_current_hunt_eligible": dict(
            class_counts_hunt_eligible
        ),

        "minimum_score": (
            min(scored_values)
            if scored_values
            else None
        ),

        "maximum_score": (
            max(scored_values)
            if scored_values
            else None
        ),

        "mean_score": (
            round(
                sum(scored_values)
                / len(scored_values),
                2
            )
            if scored_values
            else None
        ),

        "formula": {
            "component_evidence_weight": (
                COMPONENT_WEIGHT
            ),
            "exact_event_component_weight": (
                EXACT_EVENT_WEIGHT
            )
        },

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

    print(
        "Master Telemetry Readiness v0.1"
    )

    print(
        "-------------------------------"
    )

    print(
        f"Master techniques       : "
        f"{len(rows)}"
    )

    print(
        f"Scored techniques       : "
        f"{scored_count}"
    )

    print(
        f"Not applicable platform : "
        f"{not_applicable_count}"
    )

    print(
        f"Unknown readiness       : "
        f"{unknown_count}"
    )

    print()

    print(
        "Current hunt-eligible readiness:"
    )

    for key in [
        "High",
        "Medium",
        "Low",
        "Unknown"
    ]:
        print(
            f"  {key:<8}: "
            f"{class_counts_hunt_eligible.get(key, 0)}"
        )

    print()

    if scored_values:
        print(
            f"Minimum score           : "
            f"{min(scored_values):.2f}"
        )

        print(
            f"Maximum score           : "
            f"{max(scored_values):.2f}"
        )

        print(
            f"Mean score              : "
            f"{sum(scored_values)/len(scored_values):.2f}"
        )

    print()

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