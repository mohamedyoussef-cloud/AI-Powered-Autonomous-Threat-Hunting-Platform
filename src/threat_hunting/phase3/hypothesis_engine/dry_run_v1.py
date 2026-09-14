from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[4]

PHASE3_DIR = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "phase3"
)

ROUTER_DIR = PHASE3_DIR / "router"

MASTER_FILE = (
    PHASE3_DIR
    / "master_hypothesis_context_v2.jsonl"
)

ROUTER_INDEX_FILE = (
    ROUTER_DIR
    / "hypothesis_router_index_v1.jsonl"
)

ROUTER_POLICY_FILE = (
    PROJECT_ROOT
    / "config"
    / "phase3"
    / "hypothesis_router_policy_v1.json"
)

PROVIDER_FILE = (
    PROJECT_ROOT
    / "config"
    / "phase3"
    / "llm_provider.local_qwen3_8b.json"
)

TASK_CONTRACT_FILE = (
    PROJECT_ROOT
    / "config"
    / "phase3"
    / "hypothesis_engine_task_contracts_v1.json"
)

OUTPUT_DIR = (
    PHASE3_DIR
    / "hypothesis_engine"
)

REPORT_DIR = (
    PROJECT_ROOT
    / "reports"
    / "phase3"
)

DISPATCH_MANIFEST = (
    OUTPUT_DIR
    / "hypothesis_engine_dispatch_manifest_v1.jsonl"
)

REPORT_OUTPUT = (
    REPORT_DIR
    / "hypothesis_engine_v1_dry_run_summary.json"
)


QUEUE_FILES = {
    "runtime_hunt":
        ROUTER_DIR / "runtime_hunt_queue_v1.jsonl",

    "collection_gap_resolution":
        ROUTER_DIR / "collection_gap_queue_v1.jsonl",

    "environment_resolution":
        ROUTER_DIR / "environment_resolution_queue_v1.jsonl",

    "pre_attack_hunt":
        ROUTER_DIR / "pre_attack_queue_v1.jsonl",
}


SYSTEM_PROMPT = """
You are the reasoning engine of an autonomous threat hunting product.

Use only the supplied grounded context.

Mandatory constraints:
- Never claim that an ATT&CK technique occurred.
- Never invent indicators, hosts, users, IPs, domains, files, processes, or events.
- Never invent missing telemetry.
- Telemetry availability proves observability only, not attack activity.
- Preserve unknown asset criticality as unknown.
- Preserve unknown incident history as unknown.
- Preserve unknown client detection coverage as unknown.
- Sigma knowledge coverage is not client detection coverage.
- Never generate Sigma in this stage.
- Never generate SIEM queries in this stage.
- Follow the task-specific output contract.
- Return structured JSON only.
""".strip()


def read_json(path: Path):
    return json.loads(
        path.read_text(
            encoding="utf-8-sig"
        )
    )


def read_jsonl(path: Path):
    rows = []

    with path.open(
        "r",
        encoding="utf-8-sig",
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
                    f"Invalid JSONL: "
                    f"{path}:{line_number}: {exc}"
                ) from exc

            if not isinstance(value, dict):
                raise RuntimeError(
                    f"Expected JSON object: "
                    f"{path}:{line_number}"
                )

            rows.append(value)

    return rows


def write_jsonl(path: Path, rows):
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


def compact_component(component):
    return {
        "component_id":
            component.get("component_id"),

        "component_name":
            component.get("component_name"),

        "evidence_status":
            component.get(
                "global_best_evidence_status"
            ),

        "current_environment_grounded":
            component.get(
                "current_environment_grounded"
            ),

        "current_environment_exact_event":
            component.get(
                "current_environment_exact_event"
            ),

        "current_environment_platform_matches":
            component.get(
                "current_environment_platform_matches",
                [],
            ),

        "requirement_unspecified":
            component.get(
                "requirement_unspecified",
                False,
            ),
    }


def build_prompt_context(record):
    context = record["context"]

    technique = context["technique"]
    environment = context["environment"]
    telemetry = context["telemetry"]
    sigma = context["sigma_knowledge"]

    components = [
        compact_component(component)
        for component
        in telemetry.get(
            "component_evaluations",
            [],
        )
    ]

    return {
        "technique": {
            "technique_id":
                technique["technique_id"],

            "technique_name":
                technique["technique_name"],

            "description":
                technique["description"],

            "tactics":
                technique.get("tactics", []),

            "platforms":
                technique.get("platforms", []),

            "data_components":
                technique.get(
                    "data_components",
                    [],
                ),

            "detection_strategy_ids":
                technique.get(
                    "detection_strategy_ids",
                    [],
                ),

            "analytic_ids":
                technique.get(
                    "analytic_ids",
                    [],
                ),
        },

        "environment": {
            "current_environment_applicability":
                environment.get(
                    "current_environment_applicability"
                ),

            "applicability_status":
                environment.get(
                    "applicability_status"
                ),

            "observed_platform_matches":
                environment.get(
                    "technique_observed_platform_matches",
                    [],
                ),

            "unknown_platform_matches":
                environment.get(
                    "technique_unknown_platform_matches",
                    [],
                ),

            "asset_inventory_available":
                environment.get(
                    "asset_inventory_available"
                ),

            "asset_criticality_available":
                environment.get(
                    "asset_criticality_available"
                ),

            "incident_history_available":
                environment.get(
                    "incident_history_available"
                ),

            "client_detection_coverage_available":
                environment.get(
                    "client_detection_coverage_available"
                ),
        },

        "telemetry": {
            "evidence_status":
                telemetry.get(
                    "evidence_status"
                ),

            "readiness_score":
                telemetry.get(
                    "readiness_score"
                ),

            "readiness_band":
                telemetry.get(
                    "readiness_band"
                ),

            "readiness_state":
                telemetry.get(
                    "readiness_state"
                ),

            "components":
                components,
        },

        "sigma_knowledge": {
            "mapped_rule_count":
                sigma.get(
                    "mapped_rule_count"
                ),

            "knowledge_gap_score":
                sigma.get(
                    "knowledge_gap_score"
                ),

            "knowledge_gap_class":
                sigma.get(
                    "knowledge_gap_class"
                ),

            "is_client_detection_coverage":
                sigma.get(
                    "is_client_detection_coverage"
                ),
        },

        "grounding_constraints":
            context["grounding_constraints"],
    }


def validate_record(
    record,
    expected_route,
    route_policy,
    task_contract,
):
    errors = []

    technique_id = record.get(
        "technique_id"
    )

    context = record.get(
        "context",
        {},
    )

    if record.get("route") != expected_route:
        errors.append(
            "route_mismatch"
        )

    expected_task = route_policy[
        "task_mode"
    ]

    if record.get(
        "model_task_mode"
    ) != expected_task:
        errors.append(
            "router_task_mode_mismatch"
        )

    if task_contract.get(
        "route"
    ) != expected_route:
        errors.append(
            "contract_route_mismatch"
        )

    if context.get(
        "technique_id"
    ) != technique_id:
        errors.append(
            "context_technique_id_mismatch"
        )

    if context.get(
        "route"
    ) != expected_route:
        errors.append(
            "context_route_mismatch"
        )

    if record.get(
        "llm_dispatch_allowed"
    ) is not True:
        errors.append(
            "llm_dispatch_not_allowed"
        )

    for field in [
        "hypothesis_generation_allowed",
        "runtime_hunt_candidate",
        "requires_detection_eligibility_after_task",
        "downstream_workflow",
    ]:
        expected_value = route_policy[
            field
        ]

        actual_value = record.get(
            field
        )

        if actual_value != expected_value:
            errors.append(
                f"{field}_mismatch"
            )

    if record.get(
        "sigma_generation_allowed_here"
    ) is not False:
        errors.append(
            "sigma_generation_allowed"
        )

    if record.get(
        "occurrence_claim_allowed"
    ) is not False:
        errors.append(
            "occurrence_claim_allowed"
        )

    llm_task = context.get(
        "llm_task",
        {},
    )

    if llm_task.get(
        "task_mode"
    ) != expected_task:
        errors.append(
            "context_llm_task_mismatch"
        )

    expected_fields = set(
        task_contract[
            "required_output_fields"
        ]
    )

    actual_fields = set(
        llm_task.get(
            "required_output_fields",
            [],
        )
    )

    if expected_fields != actual_fields:
        errors.append(
            "required_output_fields_mismatch"
        )

    constraints = context.get(
        "grounding_constraints",
        {},
    )

    mandatory_true = [
        "must_not_claim_occurrence",
        "must_not_invent_indicators",
        "must_not_invent_missing_telemetry",
        "required_telemetry_must_be_grounded_in_attack_data_components",
        "must_preserve_unknown_asset_context",
        "must_preserve_unknown_incident_history",
        "must_preserve_unknown_client_detection_coverage",
        "sigma_proxy_is_not_client_detection_coverage",
        "source_availability_does_not_imply_activity",
        "broad_capability_does_not_imply_attack_data_component",
        "detection_generation_requires_separate_eligibility_gate",
        "do_not_generate_sigma_in_hypothesis_stage",
    ]

    for key in mandatory_true:
        if constraints.get(key) is not True:
            errors.append(
                f"grounding_constraint_failed:{key}"
            )

    if constraints.get(
        "technique_occurrence_observed"
    ) is not False:
        errors.append(
            "technique_occurrence_overclaim"
        )

    technique = context.get(
        "technique",
        {},
    )

    telemetry = context.get(
        "telemetry",
        {},
    )

    technique_components = set(
        technique.get(
            "data_components",
            [],
        )
    )

    evaluated_components = {
        component.get(
            "component_id"
        )
        for component
        in telemetry.get(
            "component_evaluations",
            [],
        )
        if component.get(
            "component_id"
        )
    }

    if technique_components != evaluated_components:
        errors.append(
            "data_component_set_mismatch"
        )

    environment = context.get(
        "environment",
        {},
    )

    if expected_route == "runtime_hunt":
        if environment.get(
            "current_environment_applicability"
        ) != "applicable":
            errors.append(
                "runtime_not_applicable"
            )

        if record.get(
            "runtime_hunt_rank"
        ) is None:
            errors.append(
                "runtime_rank_missing"
            )

    elif expected_route == "collection_gap_resolution":
        if telemetry.get(
            "readiness_state"
        ) != "technique_collection_gap":
            errors.append(
                "collection_gap_state_mismatch"
            )

        if record.get(
            "runtime_hunt_rank"
        ) is not None:
            errors.append(
                "non_runtime_has_rank"
            )

    elif expected_route == "environment_resolution":
        if environment.get(
            "current_environment_applicability"
        ) != "unknown":
            errors.append(
                "environment_resolution_state_mismatch"
            )

        if record.get(
            "runtime_hunt_rank"
        ) is not None:
            errors.append(
                "non_runtime_has_rank"
            )

    elif expected_route == "pre_attack_hunt":
        if environment.get(
            "current_environment_applicability"
        ) != "special_scope":
            errors.append(
                "pre_attack_scope_mismatch"
            )

        if record.get(
            "runtime_hunt_rank"
        ) is not None:
            errors.append(
                "non_runtime_has_rank"
            )

    return errors


def main():
    required_files = [
        MASTER_FILE,
        ROUTER_INDEX_FILE,
        ROUTER_POLICY_FILE,
        PROVIDER_FILE,
        TASK_CONTRACT_FILE,
        *QUEUE_FILES.values(),
    ]

    for path in required_files:
        if not path.exists():
            raise FileNotFoundError(
                f"Missing input: {path}"
            )

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    master_rows = read_jsonl(
        MASTER_FILE
    )

    router_index = read_jsonl(
        ROUTER_INDEX_FILE
    )

    router_policy = read_json(
        ROUTER_POLICY_FILE
    )

    provider = read_json(
        PROVIDER_FILE
    )

    contracts = read_json(
        TASK_CONTRACT_FILE
    )

    policy_routes = router_policy[
        "routes"
    ]

    task_contracts = contracts[
        "tasks"
    ]

    errors = []
    manifest = []

    master_ids = {
        row["technique_id"]
        for row in master_rows
    }

    index_ids = {
        row["technique_id"]
        for row in router_index
    }

    if len(master_rows) != len(
        master_ids
    ):
        errors.append(
            "duplicate_master_technique_ids"
        )

    if len(router_index) != len(
        index_ids
    ):
        errors.append(
            "duplicate_router_index_technique_ids"
        )

    if master_ids != index_ids:
        errors.append(
            "master_router_index_id_set_mismatch"
        )

    index_route_counts = Counter(
        row["route"]
        for row in router_index
    )

    queue_route_counts = {}
    queue_ids = set()

    runtime_ranks = []

    for route, queue_file in (
        QUEUE_FILES.items()
    ):
        if route not in policy_routes:
            errors.append(
                f"route_missing_from_policy:{route}"
            )
            continue

        route_policy = policy_routes[
            route
        ]

        task_mode = route_policy[
            "task_mode"
        ]

        task_contract = task_contracts.get(
            task_mode
        )

        if task_contract is None:
            errors.append(
                f"task_contract_missing:{task_mode}"
            )
            continue

        rows = read_jsonl(
            queue_file
        )

        queue_route_counts[
            route
        ] = len(rows)

        expected_count = (
            index_route_counts.get(
                route,
                0,
            )
        )

        if len(rows) != expected_count:
            errors.append(
                f"queue_count_mismatch:"
                f"{route}:"
                f"expected={expected_count}:"
                f"actual={len(rows)}"
            )

        positions = [
            row.get(
                "router_queue_position"
            )
            for row in rows
        ]

        if positions != list(
            range(
                1,
                len(rows) + 1,
            )
        ):
            errors.append(
                f"queue_position_not_contiguous:{route}"
            )

        for record in rows:
            technique_id = record[
                "technique_id"
            ]

            if technique_id in queue_ids:
                errors.append(
                    f"duplicate_queue_technique:"
                    f"{technique_id}"
                )

            queue_ids.add(
                technique_id
            )

            record_errors = validate_record(
                record,
                route,
                route_policy,
                task_contract,
            )

            for error in record_errors:
                errors.append(
                    f"{technique_id}:{error}"
                )

            if route == "runtime_hunt":
                runtime_ranks.append(
                    record[
                        "runtime_hunt_rank"
                    ]
                )

            prompt_context = (
                build_prompt_context(
                    record
                )
            )

            manifest.append({
                "engine_version": "1.0",

                "technique_id":
                    technique_id,

                "technique_name":
                    record.get(
                        "technique_name"
                    ),

                "route":
                    route,

                "task_mode":
                    task_mode,

                "router_queue_position":
                    record.get(
                        "router_queue_position"
                    ),

                "runtime_hunt_rank":
                    record.get(
                        "runtime_hunt_rank"
                    ),

                "requires_detection_eligibility_after_task":
                    record.get(
                        "requires_detection_eligibility_after_task"
                    ),

                "provider": {
                    "provider":
                        provider.get(
                            "provider"
                        ),

                    "model":
                        provider.get(
                            "inference_model"
                        ),

                    "base_url":
                        provider.get(
                            "base_url"
                        ),
                },

                "messages": [
                    {
                        "role": "system",
                        "content": SYSTEM_PROMPT,
                    },
                    {
                        "role": "user",
                        "content": json.dumps(
                            {
                                "task_mode":
                                    task_mode,

                                "objective":
                                    record[
                                        "context"
                                    ][
                                        "llm_task"
                                    ][
                                        "objective"
                                    ],

                                "required_output_fields":
                                    task_contract[
                                        "required_output_fields"
                                    ],

                                "grounded_context":
                                    prompt_context,
                            },
                            ensure_ascii=False,
                        ),
                    },
                ],

                "model_call_performed":
                    False,
            })

    if queue_ids != index_ids:
        errors.append(
            "router_index_queue_id_set_mismatch"
        )

    expected_runtime_ranks = list(
        range(
            1,
            len(runtime_ranks) + 1,
        )
    )

    runtime_rank_contiguous = (
        runtime_ranks
        == expected_runtime_ranks
    )

    if not runtime_rank_contiguous:
        errors.append(
            "runtime_rank_not_contiguous"
        )

    global_constraints = (
        router_policy[
            "global_constraints"
        ]
    )

    if global_constraints.get(
        "occurrence_claim_allowed"
    ) is not False:
        errors.append(
            "router_policy_allows_occurrence_claim"
        )

    if global_constraints.get(
        "sigma_generation_allowed_in_router"
    ) is not False:
        errors.append(
            "router_policy_allows_sigma"
        )

    if len(manifest) != len(
        router_index
    ):
        errors.append(
            "dispatch_manifest_count_mismatch"
        )

    validation_status = (
        "PASS"
        if not errors
        else "FAIL"
    )

    write_jsonl(
        DISPATCH_MANIFEST,
        manifest,
    )

    report = {
        "component":
            "hypothesis_engine",

        "version":
            "1.0",

        "mode":
            "dry_run",

        "generated_at_utc":
            datetime.now(
                timezone.utc
            ).isoformat(),

        "master_context_records":
            len(master_rows),

        "router_index_records":
            len(router_index),

        "dispatch_manifest_records":
            len(manifest),

        "route_counts":
            dict(
                sorted(
                    queue_route_counts.items()
                )
            ),

        "runtime_rank_contiguous":
            runtime_rank_contiguous,

        "provider":
            provider.get(
                "provider"
            ),

        "model":
            provider.get(
                "inference_model"
            ),

        "base_url":
            provider.get(
                "base_url"
            ),

        "model_calls_performed":
            False,

        "sigma_generation":
            False,

        "validation_errors":
            errors,

        "status":
            validation_status,
    }

    REPORT_OUTPUT.write_text(
        json.dumps(
            report,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    print(
        "Hypothesis Engine v1.0 - DRY RUN"
    )

    print(
        "--------------------------------"
    )

    print(
        f"Master contexts          : "
        f"{len(master_rows)}"
    )

    print(
        f"Router index             : "
        f"{len(router_index)}"
    )

    print(
        f"Dispatch manifest        : "
        f"{len(manifest)}"
    )

    print()

    print("Routes:")

    for route, count in sorted(
        queue_route_counts.items()
    ):
        print(
            f"  {route:<32} {count}"
        )

    print()

    print(
        "Runtime rank contiguous  : "
        + (
            "YES"
            if runtime_rank_contiguous
            else "NO"
        )
    )

    print(
        f"Provider                 : "
        f"{provider.get('provider')}"
    )

    print(
        f"Model                    : "
        f"{provider.get('inference_model')}"
    )

    print(
        "Model calls performed    : NO"
    )

    print(
        "Sigma generation         : NO"
    )

    print(
        f"Validation errors        : "
        f"{len(errors)}"
    )

    print()

    print(
        f"Validation               : "
        f"{validation_status}"
    )

    if errors:
        print()
        print("Validation errors:")

        for error in errors[:50]:
            print(
                " - " + error
            )

        if len(errors) > 50:
            print(
                f" ... plus "
                f"{len(errors) - 50} more"
            )

    print()
    print(
        f"Manifest : {DISPATCH_MANIFEST}"
    )

    print(
        f"Report   : {REPORT_OUTPUT}"
    )


if __name__ == "__main__":
    main()
