from __future__ import annotations

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
    / "master_telemetry_readiness_v2.jsonl"
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
    / "adaptive_prioritization_policy_product_v2.json"
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
    / "adaptive_product_prioritization_v2.jsonl"
)

CSV_OUTPUT = (
    OUTPUT_DIR
    / "adaptive_product_prioritization_v2.csv"
)

REPORT_OUTPUT = (
    REPORT_DIR
    / "adaptive_product_prioritization_v2_summary.json"
)


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

            rows.append(value)

    return rows


def renormalize_weights(
    nominal_weights,
    factor_scores,
):
    available = {
        name: score
        for name, score
        in factor_scores.items()
        if score is not None
    }

    total_weight = sum(
        nominal_weights[name]
        for name in available
    )

    if total_weight <= 0:
        return {}

    return {
        name: round(
            nominal_weights[name]
            / total_weight,
            8,
        )
        for name in available
    }


def calculate_score(
    factor_scores,
    effective_weights,
):
    if not effective_weights:
        return None

    return round(
        sum(
            float(
                factor_scores[name]
            )
            * float(weight)
            for name, weight
            in effective_weights.items()
        ),
        2,
    )


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
        exist_ok=True,
    )

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True,
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

    routes = policy[
        "routes"
    ]

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

    readiness_map = {
        row["technique_id"]: row
        for row in readiness_rows
    }

    sigma_map = {
        row["technique_id"]: row
        for row in sigma_rows
    }

    if set(readiness_map) != set(
        sigma_map
    ):
        validation_errors.append(
            "Technique ID mismatch between "
            "readiness and Sigma inputs"
        )

    if round(
        sum(
            nominal_weights.values()
        ),
        8,
    ) != 1.0:

        validation_errors.append(
            "Nominal weights do not sum to 1.0"
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
            "Unexpected prioritization factor set"
        )

    # Sigma v1 is retained only for its global
    # prepared-corpus knowledge-gap fields.
    # Its environment/applicability fields are NOT
    # authoritative for v2 prioritization.
    for technique_id, sigma in (
        sigma_map.items()
    ):

        if sigma.get(
            "gap_source"
        ) != "prepared_sigma_corpus_proxy":

            validation_errors.append(
                f"{technique_id}: unexpected "
                f"Sigma gap source"
            )

        if sigma.get(
            "is_client_detection_coverage"
        ) is not False:

            validation_errors.append(
                f"{technique_id}: Sigma proxy "
                f"incorrectly marked as client "
                f"detection coverage"
            )

    output_rows = []

    for technique_id in sorted(
        readiness_map
    ):

        readiness = readiness_map[
            technique_id
        ]

        sigma = sigma_map[
            technique_id
        ]

        current_applicability = (
            readiness.get(
                "current_environment_applicability"
            )
        )

        readiness_state = readiness.get(
            "telemetry_readiness_state"
        )

        telemetry_score = readiness.get(
            "telemetry_readiness_score"
        )

        sigma_gap_score = float(
            sigma[
                "sigma_detection_knowledge_gap_score"
            ]
        )

        # Not available yet from the current
        # reference environment.
        asset_score = None
        incident_score = None

        client_detection_gap_score = None

        if (
            client_detection_gap_score
            is not None
        ):

            detection_gap_score = (
                float(
                    client_detection_gap_score
                )
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
                float(
                    telemetry_score
                )
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
            value is not None
            for value in factor_scores.values()
        )

        effective_weights = (
            renormalize_weights(
                nominal_weights,
                factor_scores,
            )
        )

        priority_score = None
        score_status = "not_scored"
        rank_eligible = False

        if (
            current_applicability
            == "applicable"
            and readiness_state
            == "telemetry_observed"
        ):

            route = routes[
                "hunt"
            ]

            if (
                available_factor_count
                >= minimum_factors
            ):

                priority_score = (
                    calculate_score(
                        factor_scores,
                        effective_weights,
                    )
                )

                score_status = "scored"
                rank_eligible = True

            else:

                route = (
                    "retain_unscored_"
                    "insufficient_factors"
                )

                score_status = (
                    "insufficient_factors"
                )

        elif (
            current_applicability
            == "applicable"
            and readiness_state
            == "technique_collection_gap"
        ):

            route = routes[
                "collection_gap"
            ]

            # Do not use the normal hunt-priority
            # formula for collection remediation.
            priority_score = None

            score_status = (
                "collection_gap_"
                "not_scored_as_hunt"
            )

            rank_eligible = False

        elif (
            current_applicability
            == "unknown"
        ):

            route = routes[
                "environment_unknown"
            ]

            score_status = (
                "environment_presence_unknown"
            )

        elif (
            current_applicability
            == "special_scope"
        ):

            route = routes[
                "pre_attack"
            ]

            score_status = (
                "pre_attack_special_scope"
            )

        else:

            route = routes[
                "unresolved"
            ]

            score_status = "unresolved"

        output_rows.append({
            "prioritization_version": "2.0",

            "technique_id": (
                technique_id
            ),

            "technique_name": (
                readiness.get(
                    "technique_name"
                )
            ),

            "platforms": (
                readiness.get(
                    "platforms"
                )
                or []
            ),

            "tactics": (
                readiness.get(
                    "tactics"
                )
                or []
            ),

            "applicability_status": (
                readiness.get(
                    "applicability_status"
                )
            ),

            "current_environment_applicability": (
                current_applicability
            ),

            "telemetry_readiness_score": (
                telemetry_score
            ),

            "telemetry_readiness_band": (
                readiness.get(
                    "telemetry_readiness_band"
                )
            ),

            "telemetry_readiness_state": (
                readiness_state
            ),

            "sigma_rule_count": (
                sigma.get(
                    "sigma_rule_count"
                )
            ),

            "sigma_knowledge_coverage_score": (
                sigma.get(
                    "sigma_knowledge_coverage_score"
                )
            ),

            "sigma_detection_knowledge_gap_score": (
                sigma_gap_score
            ),

            "sigma_detection_knowledge_gap_class": (
                sigma.get(
                    "sigma_detection_knowledge_gap_class"
                )
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

            "asset_criticality_score": (
                asset_score
            ),

            "incident_history_relevance_score": (
                incident_score
            ),

            "factor_scores": (
                factor_scores
            ),

            "nominal_weights": (
                nominal_weights
            ),

            "effective_weights": (
                effective_weights
            ),

            "available_factor_count": (
                available_factor_count
            ),

            "priority_score": (
                priority_score
            ),

            "score_status": (
                score_status
            ),

            "priority_route": (
                route
            ),

            "runtime_hunt_rank_eligible": (
                rank_eligible
            ),

            "runtime_hunt_rank": None,

            "occurrence_claim": False,

            "interpretation": (
                "Priority score ranks currently "
                "huntable techniques only. "
                "Collection gaps remain applicable "
                "but are routed to telemetry "
                "collection remediation. Sigma "
                "knowledge gap is a prepared-corpus "
                "proxy and is not deployed client "
                "detection coverage."
            ),
        })

    # --------------------------------------------
    # Assign runtime hunt ranks only.
    # --------------------------------------------

    hunt_rows = [
        row
        for row in output_rows
        if row[
            "runtime_hunt_rank_eligible"
        ]
    ]

    hunt_rows.sort(
        key=lambda row: (
            -float(
                row[
                    "priority_score"
                ]
            ),
            row[
                "technique_id"
            ],
        )
    )

    for rank, row in enumerate(
        hunt_rows,
        start=1,
    ):
        row[
            "runtime_hunt_rank"
        ] = rank

    # --------------------------------------------
    # Validation
    # --------------------------------------------

    if len(output_rows) != 697:
        validation_errors.append(
            f"Expected 697 output rows, "
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
            "Duplicate technique IDs"
        )

    collection_rows = [
        row
        for row in output_rows
        if row[
            "priority_route"
        ]
        == routes[
            "collection_gap"
        ]
    ]

    unknown_rows = [
        row
        for row in output_rows
        if row[
            "priority_route"
        ]
        == routes[
            "environment_unknown"
        ]
    ]

    pre_rows = [
        row
        for row in output_rows
        if row[
            "priority_route"
        ]
        == routes[
            "pre_attack"
        ]
    ]

    # Collection gaps must never leak into
    # the runtime hunt ranking.
    if any(
        row[
            "runtime_hunt_rank_eligible"
        ]
        for row in collection_rows
    ):

        validation_errors.append(
            "Collection gap leaked into "
            "runtime hunt ranking"
        )

    if any(
        row[
            "priority_score"
        ]
        is not None
        for row in collection_rows
    ):

        validation_errors.append(
            "Collection gap received "
            "normal hunt priority score"
        )

    if any(
        row[
            "occurrence_claim"
        ]
        is not False
        for row in output_rows
    ):

        validation_errors.append(
            "Technique occurrence overclaim"
        )

    ranked_rows = sorted(
        hunt_rows,
        key=lambda row: (
            row[
                "runtime_hunt_rank"
            ]
        ),
    )

    expected_ranks = list(
        range(
            1,
            len(
                ranked_rows
            )
            + 1,
        )
    )

    actual_ranks = [
        row[
            "runtime_hunt_rank"
        ]
        for row in ranked_rows
    ]

    if actual_ranks != expected_ranks:
        validation_errors.append(
            "Runtime hunt ranks are not "
            "contiguous"
        )

    route_counter = Counter(
        row[
            "priority_route"
        ]
        for row in output_rows
    )

    score_status_counter = Counter(
        row[
            "score_status"
        ]
        for row in output_rows
    )

    numeric_scores = [
        float(
            row[
                "priority_score"
            ]
        )
        for row in hunt_rows
        if row[
            "priority_score"
        ]
        is not None
    ]

    validation_status = (
        "PASS"
        if not validation_errors
        else "FAIL"
    )

    # --------------------------------------------
    # Write JSONL
    # --------------------------------------------

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

    # --------------------------------------------
    # Write CSV
    # --------------------------------------------

    csv_fields = [
        "technique_id",
        "technique_name",
        "platforms",
        "tactics",

        "current_environment_applicability",

        "telemetry_readiness_score",
        "telemetry_readiness_band",
        "telemetry_readiness_state",

        "sigma_rule_count",
        "sigma_detection_knowledge_gap_score",
        "sigma_detection_knowledge_gap_class",

        "detection_gap_source",
        "is_client_detection_coverage",

        "asset_criticality_score",
        "incident_history_relevance_score",

        "available_factor_count",
        "priority_score",
        "score_status",
        "priority_route",

        "runtime_hunt_rank_eligible",
        "runtime_hunt_rank",

        "occurrence_claim",
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

    # --------------------------------------------
    # Report
    # --------------------------------------------

    report = {
        "component": (
            "adaptive_product_prioritization"
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

        "runtime_hunt_ranked": (
            len(hunt_rows)
        ),

        "collection_gap_routed": (
            len(collection_rows)
        ),

        "environment_unknown_routed": (
            len(unknown_rows)
        ),

        "pre_attack_routed": (
            len(pre_rows)
        ),

        "route_counts": dict(
            sorted(
                route_counter.items()
            )
        ),

        "score_status_counts": dict(
            sorted(
                score_status_counter.items()
            )
        ),

        "factor_availability": {
            "telemetry_readiness": True,
            "asset_criticality": False,
            "incident_history_relevance": False,
            "client_detection_coverage": False,
            "sigma_detection_knowledge_gap_proxy": True,
        },

        "effective_current_hunt_weights": {
            "telemetry_readiness": 0.5,
            "detection_coverage_gap": 0.5,
        },

        "detection_gap_source": (
            "prepared_sigma_corpus_proxy"
        ),

        "is_client_detection_coverage": (
            False
        ),

        "runtime_priority_score_summary": {
            "count": (
                len(
                    numeric_scores
                )
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

        "collection_gap_policy": (
            "Applicable techniques with zero "
            "telemetry readiness are routed to "
            "collection remediation and excluded "
            "from normal runtime hunt ranking."
        ),

        "input_readiness": (
            "master_telemetry_readiness_v2"
        ),

        "sigma_proxy_input": (
            "master_sigma_knowledge_gap_v1"
        ),

        "sigma_environment_fields_used": (
            False
        ),

        "occurrence_claim": False,

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

    # --------------------------------------------
    # Console
    # --------------------------------------------

    print(
        "Adaptive Product Prioritization v2.0"
    )

    print(
        "------------------------------------"
    )

    print(
        f"Master techniques        : "
        f"{len(output_rows)}"
    )

    print(
        f"Runtime hunt ranked      : "
        f"{len(hunt_rows)}"
    )

    print(
        f"Collection gap routed    : "
        f"{len(collection_rows)}"
    )

    print(
        f"Environment unknown      : "
        f"{len(unknown_rows)}"
    )

    print(
        f"PRE routed               : "
        f"{len(pre_rows)}"
    )

    print()

    print(
        "Routes:"
    )

    for key, value in sorted(
        route_counter.items()
    ):

        print(
            f"  {key:<40} {value}"
        )

    print()

    print(
        "Current available factors:"
    )

    print(
        "  Telemetry readiness       : YES"
    )

    print(
        "  Asset criticality         : NO"
    )

    print(
        "  Incident history          : NO"
    )

    print(
        "  Client detection coverage : NO"
    )

    print(
        "  Sigma gap proxy           : YES"
    )

    print()

    print(
        "Effective hunt weights:"
    )

    print(
        "  telemetry_readiness : 0.50"
    )

    print(
        "  detection_gap       : 0.50"
    )

    print()

    print(
        "Sigma proxy is client "
        "coverage: NO"
    )

    print(
        "Collection gaps in hunt "
        "ranking: NO"
    )

    print(
        "Occurrence claimed: NO"
    )

    print()

    if numeric_scores:

        print(
            f"Priority minimum        : "
            f"{min(numeric_scores):.2f}"
        )

        print(
            f"Priority maximum        : "
            f"{max(numeric_scores):.2f}"
        )

        print(
            f"Priority mean           : "
            f"{sum(numeric_scores) / len(numeric_scores):.2f}"
        )

        print()

    print(
        "Top 20 runtime hunt priorities:"
    )

    for row in ranked_rows[:20]:

        print(
            f"  {row['runtime_hunt_rank']:>3} "
            f"{row['technique_id']:<12} "
            f"{row['priority_score']:>6.2f} "
            f"{row['technique_name']}"
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