from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]

MASTER_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "phase3"
    / "master_hypothesis_context_v2.jsonl"
)

POLICY_FILE = (
    PROJECT_ROOT
    / "config"
    / "phase3"
    / "hypothesis_router_policy_v1.json"
)

OUTPUT_DIR = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "phase3"
    / "router"
)

REPORT_DIR = (
    PROJECT_ROOT
    / "reports"
    / "phase3"
)

INDEX_OUTPUT = (
    OUTPUT_DIR
    / "hypothesis_router_index_v1.jsonl"
)

RUNTIME_OUTPUT = (
    OUTPUT_DIR
    / "runtime_hunt_queue_v1.jsonl"
)

COLLECTION_OUTPUT = (
    OUTPUT_DIR
    / "collection_gap_queue_v1.jsonl"
)

ENVIRONMENT_OUTPUT = (
    OUTPUT_DIR
    / "environment_resolution_queue_v1.jsonl"
)

PRE_OUTPUT = (
    OUTPUT_DIR
    / "pre_attack_queue_v1.jsonl"
)

TOP20_OUTPUT = (
    OUTPUT_DIR
    / "runtime_hunt_queue_v1_top20.jsonl"
)

REPORT_OUTPUT = (
    REPORT_DIR
    / "hypothesis_router_v1_summary.json"
)


QUEUE_FILES = {
    "runtime_hunt": RUNTIME_OUTPUT,
    "collection_gap_resolution": COLLECTION_OUTPUT,
    "environment_resolution": ENVIRONMENT_OUTPUT,
    "pre_attack_hunt": PRE_OUTPUT,
}


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


def read_json(path):
    return json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )


def write_jsonl(path, rows):
    with path.open(
        "w",
        encoding="utf-8",
        newline="\n",
    ) as f:

        for row in rows:
            f.write(
                json.dumps(
                    row,
                    ensure_ascii=False,
                )
                + "\n"
            )


def sort_queue(route, rows):

    if route == "runtime_hunt":

        return sorted(
            rows,
            key=lambda row: int(
                row[
                    "context"
                ][
                    "prioritization"
                ][
                    "runtime_hunt_rank"
                ]
            ),
        )

    return sorted(
        rows,
        key=lambda row: (
            row["technique_id"]
        ),
    )


def main():

    for path in [
        MASTER_FILE,
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

    contexts = read_jsonl(
        MASTER_FILE
    )

    policy = read_json(
        POLICY_FILE
    )

    routes_policy = policy[
        "routes"
    ]

    global_constraints = policy[
        "global_constraints"
    ]

    validation_errors = []

    if len(contexts) != 697:
        validation_errors.append(
            f"Expected 697 master contexts, "
            f"found {len(contexts)}"
        )

    technique_ids = [
        row.get(
            "technique_id"
        )
        for row in contexts
    ]

    if len(technique_ids) != len(
        set(technique_ids)
    ):
        validation_errors.append(
            "Duplicate technique IDs in "
            "master context"
        )

    route_queues = {
        route: []
        for route in routes_policy
    }

    index_rows = []

    for context in contexts:

        technique_id = context[
            "technique_id"
        ]

        route = context.get(
            "route"
        )

        route_policy = routes_policy.get(
            route
        )

        if route_policy is None:
            validation_errors.append(
                f"{technique_id}: unsupported "
                f"route {route}"
            )
            continue

        context_task = (
            context.get(
                "llm_task",
                {}
            ).get(
                "task_mode"
            )
        )

        expected_task = route_policy[
            "task_mode"
        ]

        if context_task != expected_task:
            validation_errors.append(
                f"{technique_id}: task mode "
                f"mismatch. Context={context_task}, "
                f"Policy={expected_task}"
            )

        prioritization = context.get(
            "prioritization",
            {}
        )

        runtime_rank = prioritization.get(
            "runtime_hunt_rank"
        )

        priority_score = prioritization.get(
            "priority_score"
        )

        if route == "runtime_hunt":

            if runtime_rank is None:
                validation_errors.append(
                    f"{technique_id}: runtime "
                    f"route missing hunt rank"
                )

            if priority_score is None:
                validation_errors.append(
                    f"{technique_id}: runtime "
                    f"route missing priority score"
                )

        else:

            if runtime_rank is not None:
                validation_errors.append(
                    f"{technique_id}: non-runtime "
                    f"route has runtime hunt rank"
                )

        constraints = context.get(
            "grounding_constraints",
            {}
        )

        if constraints.get(
            "technique_occurrence_observed"
        ) is not False:

            validation_errors.append(
                f"{technique_id}: occurrence "
                f"overclaim"
            )

        sigma_client = (
            context.get(
                "sigma_knowledge",
                {}
            ).get(
                "is_client_detection_coverage"
            )
        )

        if sigma_client is not False:
            validation_errors.append(
                f"{technique_id}: Sigma proxy "
                f"incorrectly treated as client "
                f"coverage"
            )

        dispatch = {
            "router_version": "1.0",

            "technique_id": technique_id,

            "technique_name": (
                context.get(
                    "technique",
                    {}
                ).get(
                    "technique_name"
                )
            ),

            "route": route,

            "model_task_mode": (
                expected_task
            ),

            "llm_dispatch_allowed": (
                bool(
                    route_policy[
                        "llm_dispatch_allowed"
                    ]
                )
            ),

            "hypothesis_generation_allowed": (
                bool(
                    route_policy[
                        "hypothesis_generation_allowed"
                    ]
                )
            ),

            "runtime_hunt_candidate": (
                bool(
                    route_policy[
                        "runtime_hunt_candidate"
                    ]
                )
            ),

            "requires_detection_eligibility_after_task": (
                bool(
                    route_policy[
                        "requires_detection_eligibility_after_task"
                    ]
                )
            ),

            "downstream_workflow": (
                route_policy[
                    "downstream_workflow"
                ]
            ),

            "runtime_hunt_rank": (
                runtime_rank
            ),

            "priority_score": (
                priority_score
            ),

            "router_queue_position": None,

            "sigma_generation_allowed_here": (
                False
            ),

            "occurrence_claim_allowed": (
                False
            ),

            "context": context,
        }

        route_queues[
            route
        ].append(
            dispatch
        )

    # -------------------------------------------------
    # Sort and assign queue positions.
    #
    # For non-runtime queues, queue_position is only
    # deterministic processing order, NOT threat rank.
    # -------------------------------------------------

    for route in route_queues:

        route_queues[
            route
        ] = sort_queue(
            route,
            route_queues[
                route
            ],
        )

        for position, row in enumerate(
            route_queues[
                route
            ],
            start=1,
        ):
            row[
                "router_queue_position"
            ] = position

    runtime_rows = route_queues[
        "runtime_hunt"
    ]

    runtime_ranks = [
        row[
            "runtime_hunt_rank"
        ]
        for row in runtime_rows
    ]

    expected_runtime_ranks = list(
        range(
            1,
            len(runtime_rows) + 1,
        )
    )

    if runtime_ranks != (
        expected_runtime_ranks
    ):
        validation_errors.append(
            "Runtime hunt ranks are not "
            "contiguous"
        )

    # -------------------------------------------------
    # Route semantic validation.
    # -------------------------------------------------

    for row in route_queues[
        "collection_gap_resolution"
    ]:

        state = (
            row[
                "context"
            ][
                "telemetry"
            ].get(
                "readiness_state"
            )
        )

        if state != (
            "technique_collection_gap"
        ):
            validation_errors.append(
                f"{row['technique_id']}: "
                f"collection route without "
                f"collection gap state"
            )

    for row in route_queues[
        "environment_resolution"
    ]:

        applicability = (
            row[
                "context"
            ][
                "environment"
            ].get(
                "current_environment_applicability"
            )
        )

        if applicability != "unknown":
            validation_errors.append(
                f"{row['technique_id']}: "
                f"environment resolution route "
                f"without unknown applicability"
            )

    for row in route_queues[
        "pre_attack_hunt"
    ]:

        applicability = (
            row[
                "context"
            ][
                "environment"
            ].get(
                "current_environment_applicability"
            )
        )

        if applicability != "special_scope":
            validation_errors.append(
                f"{row['technique_id']}: "
                f"PRE route without "
                f"special_scope applicability"
            )

    # -------------------------------------------------
    # Build compact router index.
    # -------------------------------------------------

    for route in routes_policy:

        for row in route_queues[
            route
        ]:

            index_rows.append({
                "router_version": "1.0",

                "technique_id": (
                    row[
                        "technique_id"
                    ]
                ),

                "technique_name": (
                    row[
                        "technique_name"
                    ]
                ),

                "route": route,

                "model_task_mode": (
                    row[
                        "model_task_mode"
                    ]
                ),

                "router_queue_position": (
                    row[
                        "router_queue_position"
                    ]
                ),

                "runtime_hunt_rank": (
                    row[
                        "runtime_hunt_rank"
                    ]
                ),

                "priority_score": (
                    row[
                        "priority_score"
                    ]
                ),

                "llm_dispatch_allowed": (
                    row[
                        "llm_dispatch_allowed"
                    ]
                ),

                "hypothesis_generation_allowed": (
                    row[
                        "hypothesis_generation_allowed"
                    ]
                ),

                "runtime_hunt_candidate": (
                    row[
                        "runtime_hunt_candidate"
                    ]
                ),

                "requires_detection_eligibility_after_task": (
                    row[
                        "requires_detection_eligibility_after_task"
                    ]
                ),

                "downstream_workflow": (
                    row[
                        "downstream_workflow"
                    ]
                ),

                "sigma_generation_allowed_here": (
                    False
                ),

                "occurrence_claim_allowed": (
                    False
                ),
            })

    if len(index_rows) != 697:
        validation_errors.append(
            f"Expected 697 router index rows, "
            f"found {len(index_rows)}"
        )

    index_ids = [
        row[
            "technique_id"
        ]
        for row in index_rows
    ]

    if len(index_ids) != len(
        set(index_ids)
    ):
        validation_errors.append(
            "Duplicate router index technique IDs"
        )

    # -------------------------------------------------
    # Policy constraints.
    # -------------------------------------------------

    if global_constraints.get(
        "occurrence_claim_allowed"
    ) is not False:

        validation_errors.append(
            "Router policy permits occurrence "
            "claims"
        )

    if global_constraints.get(
        "sigma_generation_allowed_in_router"
    ) is not False:

        validation_errors.append(
            "Router policy incorrectly permits "
            "Sigma generation"
        )

    route_counter = Counter(
        row[
            "route"
        ]
        for row in index_rows
    )

    validation_status = (
        "PASS"
        if not validation_errors
        else "FAIL"
    )

    # -------------------------------------------------
    # Write outputs.
    # -------------------------------------------------

    write_jsonl(
        INDEX_OUTPUT,
        sorted(
            index_rows,
            key=lambda row: (
                row[
                    "technique_id"
                ]
            ),
        ),
    )

    for route, path in (
        QUEUE_FILES.items()
    ):

        write_jsonl(
            path,
            route_queues[
                route
            ],
        )

    write_jsonl(
        TOP20_OUTPUT,
        runtime_rows[:20],
    )

    report = {
        "component": (
            "hypothesis_router"
        ),

        "version": "1.0",

        "generated_at_utc": (
            datetime.now(
                timezone.utc
            ).isoformat()
        ),

        "master_context_records": (
            len(contexts)
        ),

        "router_index_records": (
            len(index_rows)
        ),

        "route_counts": dict(
            sorted(
                route_counter.items()
            )
        ),

        "runtime_rank_contiguous": (
            runtime_ranks
            == expected_runtime_ranks
        ),

        "llm_dispatch": {
            route: bool(
                routes_policy[
                    route
                ][
                    "llm_dispatch_allowed"
                ]
            )
            for route in routes_policy
        },

        "hypothesis_generation_routes": [
            route
            for route, config
            in routes_policy.items()
            if config[
                "hypothesis_generation_allowed"
            ]
        ],

        "runtime_hunt_candidate_routes": [
            route
            for route, config
            in routes_policy.items()
            if config[
                "runtime_hunt_candidate"
            ]
        ],

        "semantics": {
            "llm_dispatch_allowed": (
                "The route may be processed by "
                "the configured LLM task mode."
            ),

            "runtime_hunt_candidate": (
                "The route may proceed through "
                "the runtime hunt pipeline after "
                "hypothesis generation and later "
                "downstream gates."
            ),

            "router_queue_position": (
                "Processing order. For runtime_hunt "
                "it follows runtime_hunt_rank. For "
                "other routes it is deterministic "
                "ordering and is not a threat "
                "priority score."
            ),

            "sigma_generation": (
                "Never performed by the router."
            ),

            "occurrence_claim": False,
        },

        "model_calls_performed": False,

        "router_ready_for_model_dispatch": (
            validation_status
            == "PASS"
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

    print(
        "Hypothesis Router v1.0"
    )

    print(
        "----------------------"
    )

    print(
        f"Master contexts         : "
        f"{len(contexts)}"
    )

    print(
        f"Router index            : "
        f"{len(index_rows)}"
    )

    print()

    print(
        "Queues:"
    )

    for route, count in sorted(
        route_counter.items()
    ):

        print(
            f"  {route:<32} {count}"
        )

    print()

    print(
        "LLM task modes:"
    )

    for route in routes_policy:

        print(
            f"  {route:<32} "
            f"{routes_policy[route]['task_mode']}"
        )

    print()

    print(
        "Runtime rank contiguous : "
        + (
            "YES"
            if runtime_ranks
            == expected_runtime_ranks
            else "NO"
        )
    )

    print(
        "Model calls performed    : NO"
    )

    print(
        "Sigma generation         : NO"
    )

    print(
        "Occurrence claims        : DISALLOWED"
    )

    print()

    print(
        f"Validation              : "
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
        f"Index       : {INDEX_OUTPUT}"
    )

    print(
        f"Runtime     : {RUNTIME_OUTPUT}"
    )

    print(
        f"Collection  : {COLLECTION_OUTPUT}"
    )

    print(
        f"Environment : {ENVIRONMENT_OUTPUT}"
    )

    print(
        f"PRE         : {PRE_OUTPUT}"
    )

    print(
        f"Top20 QA    : {TOP20_OUTPUT}"
    )

    print(
        f"Report      : {REPORT_OUTPUT}"
    )


if __name__ == "__main__":
    main()