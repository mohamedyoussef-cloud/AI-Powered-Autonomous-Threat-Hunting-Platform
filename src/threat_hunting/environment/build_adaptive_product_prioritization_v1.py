import csv
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]

READINESS_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "environment"
    / "master_telemetry_readiness_v1.jsonl"
)

SIGMA_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "environment"
    / "master_sigma_knowledge_gap_v1.jsonl"
)

POLICY_FILE = (
    PROJECT_ROOT
    / "config"
    / "phase3"
    / "adaptive_prioritization_policy_product_v1.json"
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
    / "adaptive_product_prioritization_v1.jsonl"
)

CSV_OUTPUT = (
    OUTPUT_DIR
    / "adaptive_product_prioritization_v1.csv"
)

REPORT_OUTPUT = (
    REPORT_DIR
    / "adaptive_product_prioritization_v1_summary.json"
)


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


def renormalize_weights(
    nominal_weights,
    factor_scores
):
    available = {
        name: value
        for name, value in factor_scores.items()
        if value is not None
    }

    total_weight = sum(
        nominal_weights[name]
        for name in available
    )

    if total_weight <= 0:
        return {}

    return {
        name: (
            nominal_weights[name]
            / total_weight
        )
        for name in available
    }


def calculate_score(
    factor_scores,
    effective_weights
):
    if not effective_weights:
        return None

    return round(
        sum(
            factor_scores[name]
            * weight
            for name, weight
            in effective_weights.items()
        ),
        2
    )


def route_for_status(
    applicability_status,
    special_routes
):
    if applicability_status == (
        "observed_environment_applicable"
    ):
        return (
            "eligible_for_hunt_prioritization"
        )

    return special_routes.get(
        applicability_status,
        "retain_unresolved"
    )


def sort_value(value):
    if value is None:
        return -1.0

    return float(value)


def main():
    for path in [
        READINESS_FILE,
        SIGMA_FILE,
        POLICY_FILE,
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

    readiness_rows = read_jsonl(
        READINESS_FILE
    )

    sigma_rows = read_jsonl(
        SIGMA_FILE
    )

    policy = json.loads(
        POLICY_FILE.read_text(
            encoding="utf-8"
        )
    )

    nominal_weights = policy[
        "nominal_weights"
    ]

    minimum_factors = int(
        policy[
            "minimum_available_factors"
        ]
    )

    special_routes = policy[
        "special_routes"
    ]

    readiness_map = {
        row["technique_id"]: row
        for row in readiness_rows
    }

    sigma_map = {
        row["technique_id"]: row
        for row in sigma_rows
    }

    validation_errors = []

    if len(readiness_rows) != 697:
        validation_errors.append(
            f"Expected 697 readiness rows, "
            f"found {len(readiness_rows)}"
        )

    if len(sigma_rows) != 697:
        validation_errors.append(
            f"Expected 697 Sigma rows, "
            f"found {len(sigma_rows)}"
        )

    readiness_ids = set(
        readiness_map
    )

    sigma_ids = set(
        sigma_map
    )

    if readiness_ids != sigma_ids:
        validation_errors.append(
            "Technique ID mismatch between "
            "readiness and Sigma master inputs"
        )

    if round(
        sum(
            nominal_weights.values()
        ),
        8
    ) != 1.0:
        validation_errors.append(
            "Nominal prioritization weights "
            "do not sum to 1.0"
        )

    expected_factors = {
        "telemetry_readiness",
        "asset_criticality",
        "incident_history_relevance",
        "detection_coverage_gap",
    }

    if set(
        nominal_weights
    ) != expected_factors:
        validation_errors.append(
            "Unexpected nominal factor set"
        )

    output_rows = []

    for technique_id in sorted(
        readiness_ids
    ):
        readiness = readiness_map[
            technique_id
        ]

        sigma = sigma_map[
            technique_id
        ]

        applicability_status = (
            readiness[
                "applicability_status"
            ]
        )

        telemetry_score = (
            readiness.get(
                "telemetry_readiness_score"
            )
        )

        # Current lab/reference environment does
        # not provide technique-specific asset
        # criticality or incident-history scores.
        asset_score = None
        incident_score = None

        # Client deployed detection coverage is
        # also unavailable. Use the prepared Sigma
        # corpus knowledge-gap proxy explicitly as
        # the fallback detection-gap factor.
        client_detection_gap_score = None

        sigma_gap_score = float(
            sigma[
                "sigma_detection_knowledge_gap_score"
            ]
        )

        if (
            client_detection_gap_score
            is not None
        ):
            detection_gap_score = (
                client_detection_gap_score
            )

            detection_gap_source = (
                "client_detection_coverage"
            )

            is_client_detection_coverage = (
                True
            )

        else:
            detection_gap_score = (
                sigma_gap_score
            )

            detection_gap_source = (
                "prepared_sigma_corpus_proxy"
            )

            is_client_detection_coverage = (
                False
            )

        factor_scores = {
            "telemetry_readiness": (
                float(telemetry_score)
                if telemetry_score
                is not None
                else None
            ),

            "asset_criticality": (
                asset_score
            ),

            "incident_history_relevance": (
                incident_score
            ),

            "detection_coverage_gap": (
                detection_gap_score
            ),
        }

        available_factor_count = sum(
            1
            for value in factor_scores.values()
            if value is not None
        )

        effective_weights = (
            renormalize_weights(
                nominal_weights,
                factor_scores
            )
        )

        route = route_for_status(
            applicability_status,
            special_routes
        )

        priority_score = None
        score_status = "not_scored"

        if applicability_status == (
            "observed_environment_applicable"
        ):
            if (
                available_factor_count
                >= minimum_factors
            ):
                priority_score = (
                    calculate_score(
                        factor_scores,
                        effective_weights
                    )
                )

                score_status = "scored"

            else:
                route = (
                    "retain_unscored_insufficient_factors"
                )

                score_status = (
                    "insufficient_factors"
                )

        elif applicability_status == (
            "known_present_collection_gap"
        ):
            route = (
                "route_to_collection_gap_workflow"
            )

        elif applicability_status == (
            "environment_presence_unknown"
        ):
            route = (
                "retain_unscored_until_presence_known"
            )

        elif applicability_status == (
            "pre_attack_scope"
        ):
            route = (
                "route_to_pre_attack_workflow"
            )

        row = {
            "technique_id": technique_id,

            "technique_name": (
                readiness[
                    "technique_name"
                ]
            ),

            "is_subtechnique": (
                readiness[
                    "is_subtechnique"
                ]
            ),

            "parent_technique_id": (
                readiness[
                    "parent_technique_id"
                ]
            ),

            "tactics": (
                readiness[
                    "tactics"
                ]
            ),

            "attack_platforms": (
                readiness[
                    "attack_platforms"
                ]
            ),

            "product_supported": (
                readiness[
                    "product_supported"
                ]
            ),

            "applicability_status": (
                applicability_status
            ),

            "prioritization_route": route,

            "available_factor_count": (
                available_factor_count
            ),

            "telemetry_readiness_score": (
                telemetry_score
            ),

            "asset_criticality_score": (
                asset_score
            ),

            "incident_history_relevance_score": (
                incident_score
            ),

            "client_detection_gap_score": (
                client_detection_gap_score
            ),

            "sigma_detection_knowledge_gap_score": (
                sigma_gap_score
            ),

            "sigma_detection_knowledge_gap_class": (
                sigma[
                    "sigma_detection_knowledge_gap_class"
                ]
            ),

            "sigma_rule_count": (
                sigma[
                    "sigma_rule_count"
                ]
            ),

            "detection_gap_factor_score": (
                detection_gap_score
            ),

            "detection_gap_source": (
                detection_gap_source
            ),

            "is_client_detection_coverage": (
                is_client_detection_coverage
            ),

            "nominal_weights": dict(
                nominal_weights
            ),

            "effective_weights": {
                name: round(
                    weight,
                    6
                )
                for name, weight
                in effective_weights.items()
            },

            "priority_score": (
                priority_score
            ),

            "priority_rank": None,

            "priority_score_status": (
                score_status
            ),

            "exact_event_component_coverage_pct": (
                readiness.get(
                    "exact_event_component_coverage_pct"
                )
            ),

            "component_evidence_coverage_pct": (
                readiness.get(
                    "component_evidence_coverage_pct"
                )
            ),

            "priority_interpretation": (
                "Priority score uses only available "
                "factors. Missing factors are excluded "
                "and remaining nominal weights are "
                "renormalized. Sigma detection gap is "
                "a prepared-corpus knowledge proxy, "
                "not client deployed coverage."
            ),
        }

        output_rows.append(
            row
        )

    ranked_rows = [
        row
        for row in output_rows
        if row["priority_score"] is not None
    ]

    ranked_rows.sort(
        key=lambda row: (
            -sort_value(
                row["priority_score"]
            ),
            -sort_value(
                row[
                    "detection_gap_factor_score"
                ]
            ),
            -sort_value(
                row[
                    "telemetry_readiness_score"
                ]
            ),
            -sort_value(
                row[
                    "exact_event_component_coverage_pct"
                ]
            ),
            row["technique_id"],
        )
    )

    for rank, row in enumerate(
        ranked_rows,
        start=1
    ):
        row["priority_rank"] = rank

    applicable_rows = [
        row
        for row in output_rows
        if row["applicability_status"]
        == "observed_environment_applicable"
    ]

    unknown_rows = [
        row
        for row in output_rows
        if row["applicability_status"]
        == "environment_presence_unknown"
    ]

    pre_rows = [
        row
        for row in output_rows
        if row["applicability_status"]
        == "pre_attack_scope"
    ]

    if len(output_rows) != 697:
        validation_errors.append(
            f"Expected 697 output rows, "
            f"found {len(output_rows)}"
        )

    if len(applicable_rows) != 571:
        validation_errors.append(
            f"Expected 571 currently applicable "
            f"techniques, found "
            f"{len(applicable_rows)}"
        )

    if len(ranked_rows) != len(
        applicable_rows
    ):
        validation_errors.append(
            "Not every currently applicable "
            "technique received a priority score"
        )

    wrongly_ranked = [
        row["technique_id"]
        for row in output_rows
        if (
            row["priority_rank"]
            is not None
            and row[
                "applicability_status"
            ]
            != "observed_environment_applicable"
        )
    ]

    if wrongly_ranked:
        validation_errors.append(
            "Non-current-environment techniques "
            "were incorrectly ranked"
        )

    # Current environment should have exactly
    # telemetry + Sigma proxy as its two available
    # factors until client context is connected.
    invalid_current_weights = []

    for row in ranked_rows:
        weights = row[
            "effective_weights"
        ]

        expected = {
            "telemetry_readiness": 0.5,
            "detection_coverage_gap": 0.5,
        }

        if weights != expected:
            invalid_current_weights.append(
                row["technique_id"]
            )

    if invalid_current_weights:
        validation_errors.append(
            "Unexpected effective weights for "
            "current reference environment"
        )

    if any(
        row[
            "is_client_detection_coverage"
        ]
        for row in output_rows
    ):
        validation_errors.append(
            "Sigma proxy was incorrectly marked "
            "as client detection coverage"
        )

    scores = [
        row["priority_score"]
        for row in ranked_rows
    ]

    route_counter = Counter(
        row["prioritization_route"]
        for row in output_rows
    )

    factor_count_counter = Counter(
        row["available_factor_count"]
        for row in ranked_rows
    )

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
        "prioritization_route",
        "available_factor_count",
        "telemetry_readiness_score",
        "asset_criticality_score",
        "incident_history_relevance_score",
        "client_detection_gap_score",
        "sigma_detection_knowledge_gap_score",
        "sigma_detection_knowledge_gap_class",
        "sigma_rule_count",
        "detection_gap_factor_score",
        "detection_gap_source",
        "is_client_detection_coverage",
        "effective_weights",
        "priority_score",
        "priority_rank",
        "priority_score_status",
        "exact_event_component_coverage_pct",
        "component_evidence_coverage_pct",
        "priority_interpretation",
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
            csv_row = dict(
                row
            )

            csv_row["tactics"] = "|".join(
                row["tactics"] or []
            )

            csv_row["attack_platforms"] = (
                "|".join(
                    row[
                        "attack_platforms"
                    ]
                    or []
                )
            )

            csv_row["effective_weights"] = (
                json.dumps(
                    row[
                        "effective_weights"
                    ],
                    ensure_ascii=False,
                    sort_keys=True
                )
            )

            writer.writerow({
                field: csv_row.get(
                    field
                )
                for field in csv_fields
            })

    top_20 = [
        {
            "rank": row[
                "priority_rank"
            ],
            "technique_id": row[
                "technique_id"
            ],
            "technique_name": row[
                "technique_name"
            ],
            "priority_score": row[
                "priority_score"
            ],
            "telemetry_readiness_score": (
                row[
                    "telemetry_readiness_score"
                ]
            ),
            "sigma_gap_score": row[
                "sigma_detection_knowledge_gap_score"
            ],
            "sigma_rule_count": row[
                "sigma_rule_count"
            ],
        }
        for row in ranked_rows[:20]
    ]

    report = {
        "component": (
            "adaptive_product_prioritization"
        ),

        "version": "1.0",

        "generated_at_utc": (
            datetime.now(
                timezone.utc
            ).isoformat()
        ),

        "master_techniques": len(
            output_rows
        ),

        "current_environment_applicable": (
            len(applicable_rows)
        ),

        "ranked_techniques": len(
            ranked_rows
        ),

        "environment_presence_unknown": (
            len(unknown_rows)
        ),

        "pre_attack_scope": len(
            pre_rows
        ),

        "factor_availability": {
            "telemetry_readiness": True,
            "asset_criticality": False,
            "incident_history_relevance": False,
            "client_detection_coverage": False,
            "sigma_gap_proxy": True,
        },

        "current_effective_weights": {
            "telemetry_readiness": 0.5,
            "detection_coverage_gap": 0.5,
        },

        "detection_gap_source": (
            "prepared_sigma_corpus_proxy"
        ),

        "is_client_detection_coverage": (
            False
        ),

        "ranked_available_factor_counts": (
            dict(
                sorted(
                    factor_count_counter.items()
                )
            )
        ),

        "prioritization_route_counts": dict(
            sorted(
                route_counter.items()
            )
        ),

        "priority_score_min": (
            min(scores)
            if scores
            else None
        ),

        "priority_score_max": (
            max(scores)
            if scores
            else None
        ),

        "priority_score_mean": (
            round(
                sum(scores)
                / len(scores),
                2
            )
            if scores
            else None
        ),

        "top_20": top_20,

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
        "Adaptive Product Prioritization v1.0"
    )

    print(
        "------------------------------------"
    )

    print(
        f"Master techniques        : "
        f"{len(output_rows)}"
    )

    print(
        f"Current-env applicable   : "
        f"{len(applicable_rows)}"
    )

    print(
        f"Ranked techniques        : "
        f"{len(ranked_rows)}"
    )

    print(
        f"Environment unknown      : "
        f"{len(unknown_rows)}"
    )

    print(
        f"PRE special scope        : "
        f"{len(pre_rows)}"
    )

    print()

    print(
        "Current factor availability:"
    )

    print(
        "  Telemetry Readiness          : YES"
    )

    print(
        "  Asset Criticality            : NO"
    )

    print(
        "  Incident History             : NO"
    )

    print(
        "  Client Detection Coverage    : NO"
    )

    print(
        "  Sigma Gap Proxy              : YES"
    )

    print()

    print(
        "Effective weights:"
    )

    print(
        "  Telemetry Readiness          : 0.500"
    )

    print(
        "  Detection Gap                : 0.500"
    )

    print()

    if scores:
        print(
            f"Priority score min       : "
            f"{min(scores):.2f}"
        )

        print(
            f"Priority score max       : "
            f"{max(scores):.2f}"
        )

        print(
            f"Priority score mean      : "
            f"{sum(scores)/len(scores):.2f}"
        )

    print()

    print(
        "Top 20:"
    )

    for row in ranked_rows[:20]:
        print(
            f"  {row['priority_rank']:>2}. "
            f"{row['technique_id']:<10} "
            f"{row['priority_score']:>6.2f}  "
            f"{row['technique_name']}"
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