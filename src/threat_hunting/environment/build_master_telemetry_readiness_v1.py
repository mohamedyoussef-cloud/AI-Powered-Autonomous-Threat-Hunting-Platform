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
    / "master_technique_applicability_v1.jsonl"
)

TELEMETRY_SUMMARY_FILE = (
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
    / "master_telemetry_readiness_v1.csv"
)

JSONL_OUTPUT = (
    OUTPUT_DIR
    / "master_telemetry_readiness_v1.jsonl"
)

REPORT_OUTPUT = (
    REPORT_DIR
    / "master_telemetry_readiness_v1_summary.json"
)


COMPONENT_WEIGHT = 0.30
EXACT_EVENT_WEIGHT = 0.70


def read_jsonl(path):
    rows = []

    with path.open(
        "r",
        encoding="utf-8"
    ) as f:
        for line_number, line in enumerate(
            f,
            start=1
        ):
            line = line.strip()

            if not line:
                continue

            try:
                rows.append(
                    json.loads(line)
                )
            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    f"Invalid JSONL at "
                    f"{path}:{line_number}: {exc}"
                ) from exc

    return rows


def read_csv(path):
    with path.open(
        "r",
        encoding="utf-8-sig",
        newline=""
    ) as f:
        return list(
            csv.DictReader(f)
        )


def parse_float(value):
    if value is None:
        return None

    value = str(
        value
    ).strip()

    if not value:
        return None

    value = value.replace(
        "%",
        ""
    )

    try:
        return float(
            value
        )
    except ValueError:
        return None


def parse_int(value):
    if value is None:
        return None

    value = str(
        value
    ).strip()

    if not value:
        return None

    try:
        return int(
            float(value)
        )
    except ValueError:
        return None


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
    exact_pct
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
                "ATT&CK telemetry requirement is "
                "unspecified; readiness is preserved "
                "as unknown rather than scored zero."
            ),
        }

    if telemetry_status == "not_observed":
        return {
            "score": 0.0,
            "band": "Gap",
            "state": (
                "technique_collection_gap"
            ),
            "reason": (
                "Technique is applicable to the "
                "current environment but no telemetry "
                "evidence was observed for its "
                "referenced requirements."
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
                "Coverage metrics required for "
                "readiness scoring are unavailable."
            ),
        }

    score = round(
        COMPONENT_WEIGHT
        * component_pct
        +
        EXACT_EVENT_WEIGHT
        * exact_pct,
        2
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
            "Environment-specific telemetry "
            "readiness calculated from component "
            "and exact-event evidence coverage."
        ),
    }


def main():
    for path in [
        APPLICABILITY_FILE,
        TELEMETRY_SUMMARY_FILE,
    ]:
        if not path.exists():
            raise FileNotFoundError(
                f"Missing required input: {path}"
            )

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    applicability_rows = read_jsonl(
        APPLICABILITY_FILE
    )

    telemetry_rows = read_csv(
        TELEMETRY_SUMMARY_FILE
    )

    telemetry_map = {
        row["technique_id"]: row
        for row in telemetry_rows
    }

    validation_errors = []

    if len(applicability_rows) != 697:
        validation_errors.append(
            "Applicability input does not "
            "contain 697 techniques"
        )

    if len(telemetry_rows) != 697:
        validation_errors.append(
            "Telemetry summary does not "
            "contain 697 techniques"
        )

    applicability_ids = {
        row["technique_id"]
        for row in applicability_rows
    }

    telemetry_ids = set(
        telemetry_map
    )

    missing_telemetry = sorted(
        applicability_ids
        - telemetry_ids
    )

    extra_telemetry = sorted(
        telemetry_ids
        - applicability_ids
    )

    if missing_telemetry:
        validation_errors.append(
            "Techniques missing telemetry summary: "
            + ", ".join(
                missing_telemetry
            )
        )

    if extra_telemetry:
        validation_errors.append(
            "Unexpected techniques in telemetry "
            "summary: "
            + ", ".join(
                extra_telemetry
            )
        )

    output_rows = []

    for app_row in applicability_rows:
        technique_id = app_row[
            "technique_id"
        ]

        telemetry = telemetry_map.get(
            technique_id
        )

        if telemetry is None:
            continue

        component_pct = parse_float(
            telemetry.get(
                "component_evidence_coverage_pct"
            )
        )

        exact_pct = parse_float(
            telemetry.get(
                "exact_event_component_coverage_pct"
            )
        )

        evidence_status = (
            telemetry.get(
                "telemetry_evidence_status"
            )
            or ""
        ).strip()

        applicability_status = app_row[
            "applicability_status"
        ]

        environment_applicability = (
            app_row[
                "current_environment_applicability"
            ]
        )

        if applicability_status == (
            "observed_environment_applicable"
        ):
            scoring = score_applicable(
                evidence_status,
                component_pct,
                exact_pct
            )

            score_scope = (
                "current_environment"
            )

        elif applicability_status == (
            "environment_presence_unknown"
        ):
            scoring = {
                "score": None,
                "band": "Unknown",
                "state": (
                    "environment_presence_unknown"
                ),
                "reason": (
                    "Platform presence is unknown; "
                    "global telemetry evidence is "
                    "retained but environment-specific "
                    "readiness is not asserted."
                ),
            }

            score_scope = (
                "not_scored_presence_unknown"
            )

        elif applicability_status == (
            "pre_attack_scope"
        ):
            scoring = {
                "score": None,
                "band": "Special Scope",
                "state": (
                    "pre_attack_special_scope"
                ),
                "reason": (
                    "PRE techniques are routed to "
                    "the dedicated pre-attack workflow "
                    "instead of runtime telemetry "
                    "readiness scoring."
                ),
            }

            score_scope = (
                "pre_attack_special_scope"
            )

        elif applicability_status == (
            "known_present_collection_gap"
        ):
            scoring = score_applicable(
                evidence_status,
                component_pct,
                exact_pct
            )

            if scoring["score"] is None:
                scoring = {
                    "score": 0.0,
                    "band": "Gap",
                    "state": (
                        "technique_collection_gap"
                    ),
                    "reason": (
                        "Platform is known present "
                        "while required telemetry is "
                        "not available."
                    ),
                }

            score_scope = (
                "current_environment"
            )

        elif applicability_status == (
            "confirmed_not_present"
        ):
            scoring = {
                "score": None,
                "band": (
                    "Current Environment Excluded"
                ),
                "state": (
                    "confirmed_not_present"
                ),
                "reason": (
                    "Platform absence was confirmed "
                    "for the current environment only."
                ),
            }

            score_scope = (
                "current_environment_excluded"
            )

        else:
            scoring = {
                "score": None,
                "band": "Unknown",
                "state": (
                    "unhandled_applicability_state"
                ),
                "reason": (
                    "Applicability state is not "
                    "recognized by telemetry "
                    "readiness v1.0."
                ),
            }

            score_scope = "unknown"

        row = {
            "technique_id": technique_id,

            "technique_name": app_row[
                "technique_name"
            ],

            "is_subtechnique": app_row[
                "is_subtechnique"
            ],

            "parent_technique_id": (
                app_row[
                    "parent_technique_id"
                ]
            ),

            "tactics": app_row[
                "tactics"
            ],

            "attack_platforms": app_row[
                "attack_platforms"
            ],

            "product_supported": app_row[
                "product_supported"
            ],

            "applicability_status": (
                applicability_status
            ),

            "current_environment_applicability": (
                environment_applicability
            ),

            "observed_platform_matches": (
                app_row[
                    "observed_platform_matches"
                ]
            ),

            "unknown_platform_matches": (
                app_row[
                    "unknown_platform_matches"
                ]
            ),

            "telemetry_evidence_status": (
                evidence_status
            ),

            "data_components_referenced": (
                parse_int(
                    telemetry.get(
                        "data_components_referenced"
                    )
                )
            ),

            "data_components_with_any_evidence": (
                parse_int(
                    telemetry.get(
                        "data_components_with_any_evidence"
                    )
                )
            ),

            "data_components_with_exact_event_evidence": (
                parse_int(
                    telemetry.get(
                        "data_components_with_exact_event_evidence"
                    )
                )
            ),

            "data_components_source_only": (
                parse_int(
                    telemetry.get(
                        "data_components_source_only"
                    )
                )
            ),

            "component_evidence_coverage_pct": (
                component_pct
            ),

            "exact_event_component_coverage_pct": (
                exact_pct
            ),

            # Preserve the global evidence source
            # field even where environment readiness
            # cannot currently be scored.
            "evidence_sources": (
                telemetry.get(
                    "evidence_sources"
                )
            ),

            "readiness_formula": (
                "0.30_component_evidence"
                "+0.70_exact_event_evidence"
            ),

            "telemetry_readiness_score": (
                scoring["score"]
            ),

            "telemetry_readiness_band": (
                scoring["band"]
            ),

            "telemetry_readiness_state": (
                scoring["state"]
            ),

            "readiness_score_scope": (
                score_scope
            ),

            "readiness_reason": (
                scoring["reason"]
            ),
        }

        output_rows.append(
            row
        )

    ids = [
        row["technique_id"]
        for row in output_rows
    ]

    if len(output_rows) != 697:
        validation_errors.append(
            f"Expected 697 output rows, "
            f"found {len(output_rows)}"
        )

    if len(set(ids)) != len(ids):
        validation_errors.append(
            "Duplicate technique IDs detected"
        )

    # Unknown environment presence must never
    # silently become score zero.
    invalid_unknown_scores = [
        row["technique_id"]
        for row in output_rows
        if (
            row["applicability_status"]
            == "environment_presence_unknown"
            and row[
                "telemetry_readiness_score"
            ] is not None
        )
    ]

    if invalid_unknown_scores:
        validation_errors.append(
            "Environment-unknown techniques "
            "were incorrectly scored"
        )

    invalid_pre_scores = [
        row["technique_id"]
        for row in output_rows
        if (
            row["applicability_status"]
            == "pre_attack_scope"
            and row[
                "telemetry_readiness_score"
            ] is not None
        )
    ]

    if invalid_pre_scores:
        validation_errors.append(
            "PRE techniques were incorrectly "
            "given runtime telemetry scores"
        )

    # requirement_unspecified must remain unknown,
    # not zero.
    invalid_unspecified = [
        row["technique_id"]
        for row in output_rows
        if (
            row[
                "applicability_status"
            ]
            == "observed_environment_applicable"
            and row[
                "telemetry_evidence_status"
            ]
            == "requirement_unspecified"
            and row[
                "telemetry_readiness_score"
            ]
            is not None
        )
    ]

    if invalid_unspecified:
        validation_errors.append(
            "Requirement-unspecified techniques "
            "were incorrectly numerically scored"
        )

    scored_rows = [
        row
        for row in output_rows
        if row[
            "telemetry_readiness_score"
        ] is not None
    ]

    scores = [
        row[
            "telemetry_readiness_score"
        ]
        for row in scored_rows
    ]

    applicability_counter = Counter(
        row["applicability_status"]
        for row in output_rows
    )

    evidence_counter = Counter(
        row["telemetry_evidence_status"]
        for row in output_rows
    )

    state_counter = Counter(
        row["telemetry_readiness_state"]
        for row in output_rows
    )

    band_counter = Counter(
        row["telemetry_readiness_band"]
        for row in output_rows
    )

    applicable_rows = [
        row
        for row in output_rows
        if row["applicability_status"]
        == "observed_environment_applicable"
    ]

    applicable_scored = [
        row
        for row in applicable_rows
        if row[
            "telemetry_readiness_score"
        ] is not None
    ]

    applicable_unknown = [
        row
        for row in applicable_rows
        if row[
            "telemetry_readiness_score"
        ] is None
    ]

    validation_status = (
        "PASS"
        if not validation_errors
        else "FAIL"
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

    csv_fields = [
        "technique_id",
        "technique_name",
        "is_subtechnique",
        "parent_technique_id",
        "tactics",
        "attack_platforms",
        "product_supported",
        "applicability_status",
        "current_environment_applicability",
        "observed_platform_matches",
        "unknown_platform_matches",
        "telemetry_evidence_status",
        "data_components_referenced",
        "data_components_with_any_evidence",
        "data_components_with_exact_event_evidence",
        "data_components_source_only",
        "component_evidence_coverage_pct",
        "exact_event_component_coverage_pct",
        "evidence_sources",
        "readiness_formula",
        "telemetry_readiness_score",
        "telemetry_readiness_band",
        "telemetry_readiness_state",
        "readiness_score_scope",
        "readiness_reason",
    ]

    with CSV_OUTPUT.open(
        "w",
        encoding="utf-8-sig",
        newline=""
    ) as f:
        writer = csv.DictWriter(
            f,
            fieldnames=csv_fields
        )

        writer.writeheader()

        for row in output_rows:
            csv_row = dict(row)

            for field in [
                "tactics",
                "attack_platforms",
                "observed_platform_matches",
                "unknown_platform_matches",
            ]:
                csv_row[field] = "|".join(
                    str(value)
                    for value in (
                        csv_row[field]
                        or []
                    )
                )

            writer.writerow(
                csv_row
            )

    report = {
        "component": (
            "master_telemetry_readiness"
        ),

        "version": "1.0",

        "generated_at_utc": (
            datetime.now(
                timezone.utc
            ).isoformat()
        ),

        "formula": {
            "component_evidence_weight": (
                COMPONENT_WEIGHT
            ),
            "exact_event_weight": (
                EXACT_EVENT_WEIGHT
            ),
        },

        "master_techniques": len(
            output_rows
        ),

        "applicability_counts": dict(
            sorted(
                applicability_counter.items()
            )
        ),

        "telemetry_evidence_status_counts": (
            dict(
                sorted(
                    evidence_counter.items()
                )
            )
        ),

        "telemetry_readiness_state_counts": (
            dict(
                sorted(
                    state_counter.items()
                )
            )
        ),

        "readiness_band_counts": dict(
            sorted(
                band_counter.items()
            )
        ),

        "applicable_techniques": len(
            applicable_rows
        ),

        "applicable_scored": len(
            applicable_scored
        ),

        "applicable_unscored_requirement_unknown": (
            len(
                applicable_unknown
            )
        ),

        "total_numeric_scores": len(
            scores
        ),

        "score_min": (
            min(scores)
            if scores
            else None
        ),

        "score_max": (
            max(scores)
            if scores
            else None
        ),

        "score_mean": (
            round(
                sum(scores)
                / len(scores),
                2
            )
            if scores
            else None
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
            ensure_ascii=False
        ),
        encoding="utf-8"
    )

    print(
        "Master Telemetry Readiness v1.0"
    )
    print(
        "-------------------------------"
    )

    print(
        f"Master techniques        : "
        f"{len(output_rows)}"
    )

    print(
        f"Applicable techniques    : "
        f"{len(applicable_rows)}"
    )

    print(
        f"Applicable scored        : "
        f"{len(applicable_scored)}"
    )

    print(
        f"Applicable unscored      : "
        f"{len(applicable_unknown)}"
    )

    print()

    print(
        "Readiness states:"
    )

    for key, value in sorted(
        state_counter.items()
    ):
        print(
            f"  {key:<40} {value}"
        )

    print()

    print(
        "Readiness bands:"
    )

    for key, value in sorted(
        band_counter.items()
    ):
        print(
            f"  {key:<40} {value}"
        )

    print()

    if scores:
        print(
            f"Numeric score min        : "
            f"{min(scores):.2f}"
        )

        print(
            f"Numeric score max        : "
            f"{max(scores):.2f}"
        )

        print(
            f"Numeric score mean       : "
            f"{sum(scores) / len(scores):.2f}"
        )

    print()

    print(
        f"Validation               : "
        f"{validation_status}"
    )

    if validation_errors:
        print()

        print(
            "Validation errors:"
        )

        for error in validation_errors:
            print(
                " - " + error
            )

    print()

    print(
        f"CSV    : {CSV_OUTPUT}"
    )

    print(
        f"JSONL  : {JSONL_OUTPUT}"
    )

    print(
        f"Report : {REPORT_OUTPUT}"
    )


if __name__ == "__main__":
    main()