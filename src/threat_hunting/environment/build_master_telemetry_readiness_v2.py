from __future__ import annotations

import csv
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]


APPLICABILITY_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "environment"
    / "master_technique_applicability_v2.jsonl"
)

TELEMETRY_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "telemetry"
    / "resolved"
    / "technique_telemetry_evidence_v2_1.jsonl"
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

JSONL_OUTPUT = (
    OUTPUT_DIR
    / "master_telemetry_readiness_v2.jsonl"
)

CSV_OUTPUT = (
    OUTPUT_DIR
    / "master_telemetry_readiness_v2.csv"
)

REPORT_OUTPUT = (
    REPORT_DIR
    / "master_telemetry_readiness_v2_summary.json"
)


COMPONENT_WEIGHT = 0.30
EXACT_EVENT_WEIGHT = 0.70


def read_jsonl(path):
    rows = []

    with path.open(
        "r",
        encoding="utf-8",
    ) as f:

        for line_number, line in enumerate(
            f,
            start=1,
        ):

            line = line.strip()

            if not line:
                continue

            try:
                value = json.loads(line)

            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    f"Invalid JSONL at "
                    f"{path}:{line_number}: {exc}"
                ) from exc

            if not isinstance(value, dict):
                raise RuntimeError(
                    f"Expected JSON object at "
                    f"{path}:{line_number}"
                )

            rows.append(value)

    return rows


def readiness_band(score):
    if score is None:
        return "Unknown"

    if score >= 80:
        return "High"

    if score >= 50:
        return "Medium"

    if score > 0:
        return "Low"

    return "Gap"


def score_applicable(
    telemetry_status,
    component_pct,
    exact_pct,
):
    if telemetry_status == (
        "requirement_unspecified"
    ):

        return {
            "score": None,
            "band": "Unknown",
            "state": (
                "telemetry_requirement_unknown"
            ),
            "reason": (
                "ATT&CK telemetry requirements "
                "are unspecified. Readiness is "
                "preserved as unknown rather than "
                "scored as zero."
            ),
        }

    if telemetry_status == (
        "not_observed"
    ):

        return {
            "score": 0.0,
            "band": "Gap",
            "state": (
                "technique_collection_gap"
            ),
            "reason": (
                "Technique is applicable to the "
                "current environment, but no "
                "environment-grounded telemetry "
                "evidence was observed for its "
                "referenced ATT&CK data components."
            ),
        }

    if (
        component_pct is None
        or exact_pct is None
    ):

        return {
            "score": None,
            "band": "Unknown",
            "state": (
                "telemetry_measurement_unknown"
            ),
            "reason": (
                "Telemetry coverage metrics "
                "required for readiness scoring "
                "are unavailable."
            ),
        }

    score = round(
        COMPONENT_WEIGHT
        * float(component_pct)
        +
        EXACT_EVENT_WEIGHT
        * float(exact_pct),
        2,
    )

    return {
        "score": score,
        "band": readiness_band(
            score
        ),
        "state": (
            "telemetry_observed"
            if score > 0
            else "technique_collection_gap"
        ),
        "reason": (
            "Readiness is calculated from "
            "environment-grounded ATT&CK data "
            "component coverage and exact-event "
            "coverage."
        ),
    }


def main():

    for path in [
        APPLICABILITY_FILE,
        TELEMETRY_FILE,
    ]:

        if not path.exists():
            raise FileNotFoundError(
                f"Missing required input: {path}"
            )

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    applicability_rows = read_jsonl(
        APPLICABILITY_FILE
    )

    telemetry_rows = read_jsonl(
        TELEMETRY_FILE
    )

    validation_errors = []

    if len(applicability_rows) != 697:
        validation_errors.append(
            f"Applicability input must contain "
            f"697 techniques; found "
            f"{len(applicability_rows)}"
        )

    if len(telemetry_rows) != 697:
        validation_errors.append(
            f"Telemetry input must contain "
            f"697 techniques; found "
            f"{len(telemetry_rows)}"
        )

    app_map = {
        row["technique_id"]: row
        for row in applicability_rows
    }

    telemetry_map = {
        row["technique_id"]: row
        for row in telemetry_rows
    }

    if len(app_map) != len(
        applicability_rows
    ):
        validation_errors.append(
            "Duplicate technique IDs in "
            "applicability input"
        )

    if len(telemetry_map) != len(
        telemetry_rows
    ):
        validation_errors.append(
            "Duplicate technique IDs in "
            "telemetry input"
        )

    app_ids = set(
        app_map
    )

    telemetry_ids = set(
        telemetry_map
    )

    missing_telemetry = sorted(
        app_ids - telemetry_ids
    )

    extra_telemetry = sorted(
        telemetry_ids - app_ids
    )

    if missing_telemetry:
        validation_errors.append(
            "Missing telemetry techniques: "
            + ", ".join(
                missing_telemetry
            )
        )

    if extra_telemetry:
        validation_errors.append(
            "Unexpected telemetry techniques: "
            + ", ".join(
                extra_telemetry
            )
        )

    output_rows = []

    for technique_id in sorted(
        app_ids
    ):

        app = app_map[
            technique_id
        ]

        telemetry = telemetry_map[
            technique_id
        ]

        applicability_status = app.get(
            "applicability_status"
        )

        current_applicability = app.get(
            "current_environment_applicability"
        )

        prioritization_posture = app.get(
            "prioritization_posture"
        )

        environment_scope = telemetry.get(
            "environment_scope"
        )

        telemetry_status = telemetry.get(
            "telemetry_evidence_status"
        )

        component_pct = telemetry.get(
            "component_evidence_coverage_pct"
        )

        exact_pct = telemetry.get(
            "exact_event_component_coverage_pct"
        )

        # ---------------------------------------------
        # Cross-layer semantic consistency validation
        # ---------------------------------------------

        if current_applicability == "applicable":

            if environment_scope != (
                "current_environment_evaluable"
            ):

                validation_errors.append(
                    f"{technique_id}: applicable "
                    f"technique has telemetry scope "
                    f"{environment_scope}"
                )

        elif current_applicability == "unknown":

            if environment_scope != (
                "environment_presence_unknown"
            ):

                validation_errors.append(
                    f"{technique_id}: environment "
                    f"presence unknown but telemetry "
                    f"scope is {environment_scope}"
                )

        elif current_applicability == (
            "special_scope"
        ):

            if environment_scope != (
                "pre_attack_scope"
            ):

                validation_errors.append(
                    f"{technique_id}: PRE/special "
                    f"scope mismatch with telemetry "
                    f"scope {environment_scope}"
                )

        # ---------------------------------------------
        # Readiness classification
        # ---------------------------------------------

        if current_applicability == (
            "applicable"
        ):

            result = score_applicable(
                telemetry_status,
                component_pct,
                exact_pct,
            )

        elif current_applicability == (
            "unknown"
        ):

            result = {
                "score": None,
                "band": "Unknown",
                "state": (
                    "environment_presence_unknown"
                ),
                "reason": (
                    "Technique platform presence "
                    "is unknown in the current "
                    "environment. Telemetry readiness "
                    "is retained as unknown until "
                    "environment presence is resolved."
                ),
            }

        elif current_applicability == (
            "special_scope"
        ):

            result = {
                "score": None,
                "band": "Special Scope",
                "state": (
                    "pre_attack_special_scope"
                ),
                "reason": (
                    "Technique belongs to PRE "
                    "attack scope and is routed to "
                    "the PRE workflow rather than "
                    "runtime telemetry readiness."
                ),
            }

        else:

            result = {
                "score": None,
                "band": "Unknown",
                "state": (
                    "not_applicable_or_unresolved"
                ),
                "reason": (
                    "Technique is not currently "
                    "eligible for runtime telemetry "
                    "readiness scoring."
                ),
            }

        row = {
            "readiness_version": "2.0",

            "technique_id": (
                technique_id
            ),

            "technique_name": (
                telemetry.get(
                    "technique_name"
                )
                or app.get(
                    "technique_name"
                )
                or app.get(
                    "name"
                )
            ),

            "platforms": (
                telemetry.get(
                    "platforms"
                )
                or app.get(
                    "platforms"
                )
                or []
            ),

            "tactics": (
                telemetry.get(
                    "tactics"
                )
                or app.get(
                    "tactics"
                )
                or []
            ),

            "applicability_status": (
                applicability_status
            ),

            "current_environment_applicability": (
                current_applicability
            ),

            "prioritization_posture": (
                prioritization_posture
            ),

            "telemetry_environment_scope": (
                environment_scope
            ),

            "telemetry_evidence_status": (
                telemetry_status
            ),

            "data_components_referenced": (
                telemetry.get(
                    "data_components_referenced"
                )
            ),

            "data_components_with_any_evidence": (
                telemetry.get(
                    "data_components_with_any_evidence"
                )
            ),

            "data_components_with_exact_event_evidence": (
                telemetry.get(
                    "data_components_with_exact_event_evidence"
                )
            ),

            "data_components_source_only": (
                telemetry.get(
                    "data_components_source_only"
                )
            ),

            "data_components_requirement_unspecified": (
                telemetry.get(
                    "data_components_requirement_unspecified"
                )
            ),

            "component_evidence_coverage_pct": (
                component_pct
            ),

            "exact_event_component_coverage_pct": (
                exact_pct
            ),

            "readiness_component_weight": (
                COMPONENT_WEIGHT
            ),

            "readiness_exact_event_weight": (
                EXACT_EVENT_WEIGHT
            ),

            "telemetry_readiness_score": (
                result[
                    "score"
                ]
            ),

            "telemetry_readiness_band": (
                result[
                    "band"
                ]
            ),

            "telemetry_readiness_state": (
                result[
                    "state"
                ]
            ),

            "readiness_reason": (
                result[
                    "reason"
                ]
            ),

            "observed_platform_matches": (
                telemetry.get(
                    "observed_platform_matches"
                )
                or []
            ),

            "unknown_platform_matches": (
                telemetry.get(
                    "unknown_platform_matches"
                )
                or []
            ),

            "evidence_sources": (
                telemetry.get(
                    "evidence_sources"
                )
                or []
            ),

            "occurrence_claim": False,

            "input_applicability_version": (
                "2.0"
            ),

            "input_telemetry_resolver_version": (
                telemetry.get(
                    "resolver_version"
                )
            ),

            "interpretation": (
                "Telemetry readiness measures "
                "hunt observability for an "
                "applicable technique. It does "
                "not claim that the ATT&CK "
                "technique occurred."
            ),
        }

        output_rows.append(
            row
        )

    # ---------------------------------------------
    # Final validation
    # ---------------------------------------------

    if len(output_rows) != 697:
        validation_errors.append(
            f"Expected 697 readiness records; "
            f"found {len(output_rows)}"
        )

    output_ids = [
        row[
            "technique_id"
        ]
        for row in output_rows
    ]

    if len(output_ids) != len(
        set(output_ids)
    ):
        validation_errors.append(
            "Duplicate readiness technique IDs"
        )

    if any(
        row[
            "occurrence_claim"
        ]
        is not False
        for row in output_rows
    ):
        validation_errors.append(
            "Technique occurrence overclaim "
            "detected"
        )

    applicable_rows = [
        row
        for row in output_rows
        if row[
            "current_environment_applicability"
        ] == "applicable"
    ]

    unknown_rows = [
        row
        for row in output_rows
        if row[
            "current_environment_applicability"
        ] == "unknown"
    ]

    special_rows = [
        row
        for row in output_rows
        if row[
            "current_environment_applicability"
        ] == "special_scope"
    ]

    applicable_scored = [
        row
        for row in applicable_rows
        if row[
            "telemetry_readiness_score"
        ] is not None
    ]

    applicable_unscored = [
        row
        for row in applicable_rows
        if row[
            "telemetry_readiness_score"
        ] is None
    ]

    status_counter = Counter(
        row[
            "telemetry_evidence_status"
        ]
        for row in applicable_rows
    )

    band_counter = Counter(
        row[
            "telemetry_readiness_band"
        ]
        for row in output_rows
    )

    state_counter = Counter(
        row[
            "telemetry_readiness_state"
        ]
        for row in output_rows
    )

    numeric_scores = [
        float(
            row[
                "telemetry_readiness_score"
            ]
        )
        for row in applicable_scored
    ]

    validation_status = (
        "PASS"
        if not validation_errors
        else "FAIL"
    )

    # ---------------------------------------------
    # Write JSONL
    # ---------------------------------------------

    with JSONL_OUTPUT.open(
        "w",
        encoding="utf-8",
        newline="\n",
    ) as f:

        for row in output_rows:

            f.write(
                json.dumps(
                    row,
                    ensure_ascii=False,
                )
                + "\n"
            )

    # ---------------------------------------------
    # Write CSV
    # ---------------------------------------------

    csv_fields = [
        "technique_id",
        "technique_name",
        "platforms",
        "tactics",

        "applicability_status",
        "current_environment_applicability",
        "prioritization_posture",

        "telemetry_environment_scope",
        "telemetry_evidence_status",

        "data_components_referenced",
        "data_components_with_any_evidence",
        "data_components_with_exact_event_evidence",
        "data_components_source_only",
        "data_components_requirement_unspecified",

        "component_evidence_coverage_pct",
        "exact_event_component_coverage_pct",

        "telemetry_readiness_score",
        "telemetry_readiness_band",
        "telemetry_readiness_state",

        "observed_platform_matches",
        "unknown_platform_matches",
        "evidence_sources",

        "occurrence_claim",
        "readiness_reason",
    ]

    with CSV_OUTPUT.open(
        "w",
        encoding="utf-8-sig",
        newline="",
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=csv_fields,
        )

        writer.writeheader()

        for row in output_rows:

            csv_row = {
                field: row.get(
                    field
                )
                for field in csv_fields
            }

            for field in [
                "platforms",
                "tactics",
                "observed_platform_matches",
                "unknown_platform_matches",
                "evidence_sources",
            ]:

                csv_row[field] = (
                    " | ".join(
                        row.get(
                            field
                        )
                        or []
                    )
                )

            writer.writerow(
                csv_row
            )

    # ---------------------------------------------
    # Report
    # ---------------------------------------------

    report = {
        "component": (
            "master_telemetry_readiness"
        ),

        "version": "2.0",

        "generated_at_utc": (
            datetime.now(
                timezone.utc
            ).isoformat()
        ),

        "master_techniques": (
            len(output_rows)
        ),

        "current_environment_applicable": (
            len(applicable_rows)
        ),

        "applicable_scored": (
            len(applicable_scored)
        ),

        "applicable_unscored": (
            len(applicable_unscored)
        ),

        "environment_presence_unknown": (
            len(unknown_rows)
        ),

        "pre_attack_special_scope": (
            len(special_rows)
        ),

        "applicable_telemetry_status_counts": (
            dict(
                sorted(
                    status_counter.items()
                )
            )
        ),

        "readiness_band_counts": (
            dict(
                sorted(
                    band_counter.items()
                )
            )
        ),

        "readiness_state_counts": (
            dict(
                sorted(
                    state_counter.items()
                )
            )
        ),

        "scoring": {
            "component_weight": (
                COMPONENT_WEIGHT
            ),

            "exact_event_weight": (
                EXACT_EVENT_WEIGHT
            ),

            "formula": (
                "0.30 * component evidence "
                "coverage + 0.70 * exact-event "
                "component coverage"
            ),

            "requirement_unspecified_policy": (
                "Unknown, not zero"
            ),

            "environment_unknown_policy": (
                "Unscored until presence resolved"
            ),

            "pre_attack_policy": (
                "Special Scope, not runtime score"
            ),
        },

        "numeric_score_summary": {
            "count": (
                len(numeric_scores)
            ),

            "minimum": (
                round(
                    min(
                        numeric_scores
                    ),
                    2,
                )
                if numeric_scores
                else None
            ),

            "maximum": (
                round(
                    max(
                        numeric_scores
                    ),
                    2,
                )
                if numeric_scores
                else None
            ),

            "mean": (
                round(
                    sum(
                        numeric_scores
                    )
                    / len(
                        numeric_scores
                    ),
                    2,
                )
                if numeric_scores
                else None
            ),
        },

        "occurrence_claim": False,

        "input_applicability": (
            "master_technique_applicability_v2"
        ),

        "input_telemetry": (
            "technique_telemetry_evidence_v2_1"
        ),

        "validation_errors": (
            validation_errors
        ),

        "status": (
            validation_status
        ),
    }

    REPORT_OUTPUT.write_text(
        json.dumps(
            report,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    # ---------------------------------------------
    # Console
    # ---------------------------------------------

    print(
        "Master Telemetry Readiness v2.0"
    )

    print(
        "-------------------------------"
    )

    print(
        f"Master techniques        : "
        f"{len(output_rows)}"
    )

    print(
        f"Current applicable       : "
        f"{len(applicable_rows)}"
    )

    print(
        f"Applicable scored        : "
        f"{len(applicable_scored)}"
    )

    print(
        f"Applicable unscored      : "
        f"{len(applicable_unscored)}"
    )

    print(
        f"Environment unknown      : "
        f"{len(unknown_rows)}"
    )

    print(
        f"PRE special scope        : "
        f"{len(special_rows)}"
    )

    print()

    print(
        "Applicable telemetry status:"
    )

    for key, value in sorted(
        status_counter.items()
    ):

        print(
            f"  {key:<30} {value}"
        )

    print()

    print(
        "Readiness bands:"
    )

    for key, value in sorted(
        band_counter.items()
    ):

        print(
            f"  {key:<18} {value}"
        )

    print()

    print(
        "Readiness states:"
    )

    for key, value in sorted(
        state_counter.items()
    ):

        print(
            f"  {key:<36} {value}"
        )

    print()

    if numeric_scores:

        print(
            f"Score minimum            : "
            f"{min(numeric_scores):.2f}"
        )

        print(
            f"Score maximum            : "
            f"{max(numeric_scores):.2f}"
        )

        print(
            f"Score mean               : "
            f"{sum(numeric_scores) / len(numeric_scores):.2f}"
        )

        print()

    print(
        "Occurrence claimed       : NO"
    )

    print()

    print(
        f"Validation               : "
        f"{validation_status}"
    )

    if validation_errors:

        print()

        for error in validation_errors:

            print(
                " - " + error
            )

    print()

    print(
        f"JSONL  : {JSONL_OUTPUT}"
    )

    print(
        f"CSV    : {CSV_OUTPUT}"
    )

    print(
        f"Report : {REPORT_OUTPUT}"
    )


if __name__ == "__main__":
    main()