from __future__ import annotations

import hashlib
import json
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


PROJECT_ROOT = Path(__file__).resolve().parents[4]

PHASE3_DIR = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "phase3"
)

HYPOTHESIS_DIR = (
    PHASE3_DIR
    / "hypothesis_engine"
)

ROUTER_DIR = (
    PHASE3_DIR
    / "router"
)

ELIGIBILITY_DIR = (
    PHASE3_DIR
    / "detection_eligibility"
)

REPORT_DIR = (
    PROJECT_ROOT
    / "reports"
    / "phase3"
)

SCHEMA_FILE = (
    PROJECT_ROOT
    / "schemas"
    / "phase3"
    / "detection_eligibility"
    / "eligibility_output_v1.schema.json"
)

MASTER_FILE = (
    PHASE3_DIR
    / "master_hypothesis_context_v2.jsonl"
)

ROUTER_FILE = (
    ROUTER_DIR
    / "hypothesis_router_index_v1.jsonl"
)

OUTPUT_FILES = {
    "runtime_hunt":
        HYPOTHESIS_DIR
        / "runtime_hunt_outputs_v1.jsonl",

    "collection_gap_resolution":
        HYPOTHESIS_DIR
        / "collection_gap_outputs_v1.jsonl",

    "environment_resolution":
        HYPOTHESIS_DIR
        / "environment_resolution_outputs_v1.jsonl",

    "pre_attack_hunt":
        HYPOTHESIS_DIR
        / "pre_attack_outputs_v1.jsonl",
}

DECISION_OUTPUT = (
    ELIGIBILITY_DIR
    / "detection_eligibility_outputs_v1.jsonl"
)

INDEX_OUTPUT = (
    ELIGIBILITY_DIR
    / "detection_eligibility_index_v1.jsonl"
)

ERROR_OUTPUT = (
    ELIGIBILITY_DIR
    / "detection_eligibility_errors_v1.jsonl"
)

SUMMARY_OUTPUT = (
    REPORT_DIR
    / "detection_eligibility_gate_v1_summary.json"
)


CONTRACT_VERSION = "1.0"
RULES_VERSION = "1.0"
GATE_VERSION = "1.0"


SUPPORTED_ROUTES = {
    "runtime_hunt",
    "collection_gap_resolution",
    "environment_resolution",
    "pre_attack_hunt",
}


EXPECTED_TASK_MODES = {
    "runtime_hunt":
        "generate_runtime_hunt_hypothesis",

    "collection_gap_resolution":
        "resolve_collection_gap",

    "environment_resolution":
        "resolve_environment_presence",

    "pre_attack_hunt":
        "generate_pre_attack_hypothesis",
}


EXPECTED_ELIGIBILITY_FLAG = {
    "runtime_hunt": True,
    "collection_gap_resolution": False,
    "environment_resolution": False,
    "pre_attack_hunt": True,
}


DOWNSTREAM_ACTIONS = {
    "ELIGIBLE_FOR_DETECTION":
        "DETECTION_PLAN",

    "COLLECTION_BLOCKED":
        "COLLECTION_GAP_RESOLUTION",

    "ENVIRONMENT_BLOCKED":
        "ENVIRONMENT_RESOLUTION",

    "EXTERNAL_HUNT_ONLY":
        "EXTERNAL_HUNT_WORKFLOW",

    "NOT_ELIGIBLE":
        "NO_DETECTION_GENERATION",
}


def utc_now() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(
            path.read_text(
                encoding="utf-8-sig"
            )
        )
    except Exception as exc:
        raise RuntimeError(
            f"Failed to read JSON: {path}: {exc}"
        ) from exc


def read_jsonl(
    path: Path,
) -> list[dict[str, Any]]:
    rows = []

    try:
        handle = path.open(
            "r",
            encoding="utf-8-sig",
        )
    except OSError as exc:
        raise RuntimeError(
            f"Failed to open JSONL: {path}: {exc}"
        ) from exc

    with handle:
        for line_number, line in enumerate(
            handle,
            start=1,
        ):
            line = line.strip()

            if not line:
                continue

            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    f"Invalid JSONL:"
                    f"{path}:{line_number}:"
                    f"{exc}"
                ) from exc

            if not isinstance(row, dict):
                raise RuntimeError(
                    f"JSONL record is not object:"
                    f"{path}:{line_number}"
                )

            rows.append(row)

    return rows


def build_unique_index(
    rows: list[dict[str, Any]],
    name: str,
) -> dict[str, dict[str, Any]]:
    index = {}

    for row in rows:
        technique_id = row.get(
            "technique_id"
        )

        if not technique_id:
            raise RuntimeError(
                f"{name}: record missing technique_id"
            )

        if technique_id in index:
            raise RuntimeError(
                f"{name}: duplicate technique_id:"
                f"{technique_id}"
            )

        index[technique_id] = row

    return index


def canonical_json(
    value: Any,
) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode(
        "utf-8"
    )


def build_input_fingerprint(
    master: dict[str, Any],
    router: dict[str, Any],
    output: dict[str, Any],
) -> str:
    digest = hashlib.sha256()

    digest.update(
        canonical_json(
            {
                "master_context": master,
                "router_record": router,
                "hypothesis_output": output,
            }
        )
    )

    return (
        "sha256:"
        + digest.hexdigest()
    )


def atomic_write_jsonl(
    path: Path,
    rows: list[dict[str, Any]],
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temp_path = path.with_suffix(
        path.suffix + ".tmp"
    )

    with temp_path.open(
        "w",
        encoding="utf-8",
        newline="\n",
    ) as handle:
        for row in rows:
            handle.write(
                json.dumps(
                    row,
                    ensure_ascii=False,
                )
                + "\n"
            )

    os.replace(
        temp_path,
        path,
    )


def atomic_write_json(
    path: Path,
    value: dict[str, Any],
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temp_path = path.with_suffix(
        path.suffix + ".tmp"
    )

    temp_path.write_text(
        json.dumps(
            value,
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    os.replace(
        temp_path,
        path,
    )


def component_map(
    context: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    components = (
        context
        .get("telemetry", {})
        .get(
            "component_evaluations",
            [],
        )
    )

    result = {}

    for component in components:
        component_id = component.get(
            "component_id"
        )

        if not component_id:
            continue

        if component_id in result:
            raise ValueError(
                "duplicate_component_evaluation:"
                f"{component_id}"
            )

        result[component_id] = component

    return result


def source_versions(
    context: dict[str, Any],
    router: dict[str, Any],
    output: dict[str, Any],
) -> dict[str, str]:
    technique = context.get(
        "technique",
        {}
    )

    telemetry = context.get(
        "telemetry",
        {}
    )

    environment = context.get(
        "environment",
        {}
    )

    values = {
        "attack_version":
            technique.get("attack_version"),

        "master_context_version":
            context.get("context_version"),

        "router_version":
            router.get("router_version"),

        "hypothesis_engine_version":
            output.get("engine_version"),

        "telemetry_resolver_version":
            telemetry.get("resolver_version"),

        "environment_profile_version":
            environment.get("profile_version"),
    }

    for name, value in values.items():
        if not isinstance(value, str) or not value:
            raise ValueError(
                f"missing_source_version:{name}"
            )

    return values


def decision_context(
    context: dict[str, Any],
) -> dict[str, Any]:
    environment = context.get(
        "environment",
        {}
    )

    telemetry = context.get(
        "telemetry",
        {}
    )

    return {
        "current_environment_applicability":
            environment.get(
                "current_environment_applicability"
            ),

        "applicability_status":
            environment.get(
                "applicability_status"
            ),

        "telemetry_readiness_state":
            telemetry.get(
                "readiness_state"
            ),
    }


def validate_product_grounding_invariants(
    context: dict[str, Any],
) -> None:
    constraints = context.get(
        "grounding_constraints",
        {}
    )

    expected_true = [
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

    for name in expected_true:
        if constraints.get(name) is not True:
            raise ValueError(
                f"grounding_invariant_not_preserved:{name}"
            )

    sigma_knowledge = context.get(
        "sigma_knowledge",
        {}
    )

    if (
        sigma_knowledge.get(
            "is_client_detection_coverage"
        )
        is not False
    ):
        raise ValueError(
            "sigma_proxy_client_coverage_invariant_failed"
        )


def grounding_assertions(
    context: dict[str, Any],
) -> dict[str, bool]:
    constraints = context.get(
        "grounding_constraints",
        {}
    )

    occurrence = constraints.get(
        "technique_occurrence_observed"
    )

    if occurrence is not False:
        raise ValueError(
            "technique_occurrence_state_not_false"
        )

    return {
        "technique_occurrence_observed":
            occurrence,

        "telemetry_evidence_proves_occurrence":
            False,

        "sigma_proxy_is_client_detection_coverage":
            False,
    }


def base_record(
    *,
    context: dict[str, Any],
    router: dict[str, Any],
    output: dict[str, Any],
    generated_at: str,
    fingerprint: str,
) -> dict[str, Any]:
    return {
        "contract_version":
            CONTRACT_VERSION,

        "rules_version":
            RULES_VERSION,

        "gate_version":
            GATE_VERSION,

        "generated_at_utc":
            generated_at,

        "technique_id":
            output["technique_id"],

        "technique_name":
            output["technique_name"],

        "source_route":
            output["route"],

        "source_task_mode":
            output["task_mode"],

        "router_queue_position":
            output.get(
                "router_queue_position"
            ),

        "runtime_hunt_rank":
            output.get(
                "runtime_hunt_rank"
            ),

        "processing_status":
            "SUCCESS",

        "eligibility_decision":
            None,

        "reason_codes":
            [],

        "error_codes":
            [],

        "decision_context":
            decision_context(
                context
            ),

        "required_data_components":
            [],

        "component_assessments":
            [],

        "downstream_action":
            None,

        "source_versions":
            source_versions(
                context,
                router,
                output,
            ),

        "grounding_assertions":
            grounding_assertions(
                context
            ),

        "input_fingerprint":
            fingerprint,
    }


def make_component_assessment(
    component: dict[str, Any],
    *,
    effect: str,
) -> dict[str, Any]:
    return {
        "component_id":
            component["component_id"],

        "component_name":
            component["component_name"],

        "required_by_hypothesis":
            True,

        "current_environment_grounded":
            component.get(
                "current_environment_grounded"
            ),

        "current_environment_exact_event":
            component.get(
                "current_environment_exact_event"
            ),

        "requirement_unspecified":
            component.get(
                "requirement_unspecified"
            ),

        "global_best_evidence_status":
            component.get(
                "global_best_evidence_status"
            ),

        "eligibility_effect":
            effect,
    }


def validate_common_record(
    context: dict[str, Any],
    router: dict[str, Any],
    output: dict[str, Any],
) -> None:
    technique_id = output.get(
        "technique_id"
    )

    technique_name = output.get(
        "technique_name"
    )

    route = output.get(
        "route"
    )

    if route not in SUPPORTED_ROUTES:
        raise ValueError(
            f"unsupported_route:{route}"
        )

    if output.get("status") != "PASS":
        raise ValueError(
            "input_not_final_pass"
        )

    validation = output.get(
        "validation",
        {}
    )

    if validation.get(
        "schema_valid"
    ) is not True:
        raise ValueError(
            "input_schema_not_valid"
        )

    if validation.get(
        "grounding_valid"
    ) is not True:
        raise ValueError(
            "input_grounding_not_valid"
        )

    if validation.get(
        "errors"
    ):
        raise ValueError(
            "input_validation_errors_present"
        )

    context_technique = context.get(
        "technique",
        {}
    )

    if context.get(
        "technique_id"
    ) != technique_id:
        raise ValueError(
            "master_technique_id_mismatch"
        )

    if router.get(
        "technique_id"
    ) != technique_id:
        raise ValueError(
            "router_technique_id_mismatch"
        )

    if (
        context_technique.get(
            "technique_name"
        )
        != technique_name
    ):
        raise ValueError(
            "master_technique_name_mismatch"
        )

    if (
        router.get(
            "technique_name"
        )
        != technique_name
    ):
        raise ValueError(
            "router_technique_name_mismatch"
        )

    if context.get(
        "route"
    ) != route:
        raise ValueError(
            "master_route_mismatch"
        )

    if router.get(
        "route"
    ) != route:
        raise ValueError(
            "router_route_mismatch"
        )

    expected_task_mode = (
        EXPECTED_TASK_MODES[
            route
        ]
    )

    if output.get(
        "task_mode"
    ) != expected_task_mode:
        raise ValueError(
            "output_task_mode_mismatch"
        )

    if router.get(
        "model_task_mode"
    ) != expected_task_mode:
        raise ValueError(
            "router_task_mode_mismatch"
        )

    expected_flag = (
        EXPECTED_ELIGIBILITY_FLAG[
            route
        ]
    )

    if (
        output.get(
            "requires_detection_eligibility_after_task"
        )
        is not expected_flag
    ):
        raise ValueError(
            "output_eligibility_flag_mismatch"
        )

    if (
        router.get(
            "requires_detection_eligibility_after_task"
        )
        is not expected_flag
    ):
        raise ValueError(
            "router_eligibility_flag_mismatch"
        )

    if (
        output.get(
            "router_queue_position"
        )
        != router.get(
            "router_queue_position"
        )
    ):
        raise ValueError(
            "router_queue_position_mismatch"
        )

    if (
        output.get(
            "runtime_hunt_rank"
        )
        != router.get(
            "runtime_hunt_rank"
        )
    ):
        raise ValueError(
            "runtime_hunt_rank_mismatch"
        )

    if router.get(
        "sigma_generation_allowed_here"
    ) is not False:
        raise ValueError(
            "router_sigma_generation_invariant_failed"
        )

    if router.get(
        "occurrence_claim_allowed"
    ) is not False:
        raise ValueError(
            "router_occurrence_claim_invariant_failed"
        )

    validate_product_grounding_invariants(
        context
    )


def evaluate_runtime(
    record: dict[str, Any],
    context: dict[str, Any],
    output: dict[str, Any],
) -> None:
    environment = context[
        "environment"
    ]

    telemetry = context[
        "telemetry"
    ]

    if (
        environment.get(
            "current_environment_applicability"
        )
        != "applicable"
    ):
        raise ValueError(
            "runtime_environment_applicability_contradiction"
        )

    if (
        environment.get(
            "applicability_status"
        )
        != "observed_environment_applicable"
    ):
        raise ValueError(
            "runtime_applicability_status_contradiction"
        )

    if (
        telemetry.get(
            "readiness_state"
        )
        != "telemetry_observed"
    ):
        raise ValueError(
            "runtime_telemetry_state_contradiction"
        )

    attack_components = set(
        context[
            "technique"
        ].get(
            "data_components",
            [],
        )
    )

    evaluations = component_map(
        context
    )

    required = (
        output
        .get("model_output", {})
        .get(
            "required_telemetry",
            [],
        )
    )

    if not required:
        raise ValueError(
            "runtime_required_telemetry_empty"
        )

    required_ids = []
    assessments = []
    blocked_reasons = set()

    for item in required:
        component_id = item.get(
            "component_id"
        )

        component_name = item.get(
            "component_name"
        )

        if component_id not in attack_components:
            raise ValueError(
                "required_component_outside_attack_mapping:"
                f"{component_id}"
            )

        evaluation = evaluations.get(
            component_id
        )

        if evaluation is None:
            raise ValueError(
                "required_component_evaluation_missing:"
                f"{component_id}"
            )

        if (
            component_name
            != evaluation.get(
                "component_name"
            )
        ):
            raise ValueError(
                "required_component_name_mismatch:"
                f"{component_id}"
            )

        required_ids.append(
            component_id
        )

        blocked = False

        if (
            evaluation.get(
                "requirement_unspecified"
            )
            is True
        ):
            blocked = True
            blocked_reasons.add(
                "REQUIRED_COMPONENT_REQUIREMENT_UNSPECIFIED"
            )

        if (
            evaluation.get(
                "current_environment_grounded"
            )
            is not True
        ):
            blocked = True
            blocked_reasons.add(
                "REQUIRED_COMPONENT_NOT_ENVIRONMENT_GROUNDED"
            )

        assessments.append(
            make_component_assessment(
                evaluation,
                effect=(
                    "COLLECTION_BLOCKER"
                    if blocked
                    else "SATISFIED"
                ),
            )
        )

    if len(required_ids) != len(
        set(required_ids)
    ):
        raise ValueError(
            "duplicate_required_component"
        )

    record[
        "required_data_components"
    ] = required_ids

    record[
        "component_assessments"
    ] = assessments

    if blocked_reasons:
        record[
            "eligibility_decision"
        ] = "COLLECTION_BLOCKED"

        record[
            "reason_codes"
        ] = sorted(
            blocked_reasons
        )

    else:
        record[
            "eligibility_decision"
        ] = "ELIGIBLE_FOR_DETECTION"

        record[
            "reason_codes"
        ] = [
            "RUNTIME_REQUIRED_COMPONENTS_ENVIRONMENT_GROUNDED"
        ]


def evaluate_collection_gap(
    record: dict[str, Any],
    context: dict[str, Any],
) -> None:
    environment = context[
        "environment"
    ]

    telemetry = context[
        "telemetry"
    ]

    if (
        environment.get(
            "current_environment_applicability"
        )
        != "applicable"
    ):
        raise ValueError(
            "collection_route_environment_contradiction"
        )

    if (
        telemetry.get(
            "readiness_state"
        )
        != "technique_collection_gap"
    ):
        raise ValueError(
            "collection_route_readiness_contradiction"
        )

    record[
        "required_data_components"
    ] = list(
        context[
            "technique"
        ].get(
            "data_components",
            [],
        )
    )

    record[
        "eligibility_decision"
    ] = "COLLECTION_BLOCKED"

    record[
        "reason_codes"
    ] = [
        "EXISTING_COLLECTION_GAP"
    ]


def evaluate_environment_resolution(
    record: dict[str, Any],
    context: dict[str, Any],
) -> None:
    environment = context[
        "environment"
    ]

    if (
        environment.get(
            "current_environment_applicability"
        )
        != "unknown"
    ):
        raise ValueError(
            "environment_route_applicability_contradiction"
        )

    if (
        environment.get(
            "applicability_status"
        )
        != "environment_presence_unknown"
    ):
        raise ValueError(
            "environment_route_status_contradiction"
        )

    record[
        "required_data_components"
    ] = list(
        context[
            "technique"
        ].get(
            "data_components",
            [],
        )
    )

    record[
        "eligibility_decision"
    ] = "ENVIRONMENT_BLOCKED"

    record[
        "reason_codes"
    ] = [
        "ENVIRONMENT_PRESENCE_UNRESOLVED"
    ]


def evaluate_pre_attack(
    record: dict[str, Any],
    context: dict[str, Any],
    output: dict[str, Any],
) -> None:
    environment = context[
        "environment"
    ]

    if (
        environment.get(
            "current_environment_applicability"
        )
        != "special_scope"
    ):
        raise ValueError(
            "pre_attack_applicability_contradiction"
        )

    if (
        environment.get(
            "applicability_status"
        )
        != "pre_attack_scope"
    ):
        raise ValueError(
            "pre_attack_status_contradiction"
        )

    external_refs = (
        output
        .get("model_output", {})
        .get(
            "required_external_evidence",
            [],
        )
    )

    attack_components = set(
        context[
            "technique"
        ].get(
            "data_components",
            [],
        )
    )

    evaluations = component_map(
        context
    )

    required_ids = []
    seen_ids = set()
    assessments = []

    for item in external_refs:
        component_id = item.get(
            "component_id"
        )

        component_name = item.get(
            "component_name"
        )

        if not component_id:
            raise ValueError(
                "external_component_id_missing"
            )

        # External evidence must still be grounded
        # in the MITRE ATT&CK Data Components
        # mapped to the technique.
        if component_id not in attack_components:
            raise ValueError(
                "external_component_outside_attack_mapping:"
                f"{component_id}"
            )

        evaluation = evaluations.get(
            component_id
        )

        if evaluation is None:
            raise ValueError(
                "external_component_evaluation_missing:"
                f"{component_id}"
            )

        expected_name = evaluation.get(
            "component_name"
        )

        if (
            component_name
            and expected_name
            and component_name != expected_name
        ):
            raise ValueError(
                "external_component_name_mismatch:"
                f"{component_id}"
            )

        # A PRE-Attack hypothesis may reference the
        # same ATT&CK Data Component multiple times
        # for different external evidence needs.
        #
        # The eligibility artifact stores a normalized
        # component set, so identical component IDs
        # are deterministically deduplicated.
        if component_id in seen_ids:
            continue

        seen_ids.add(
            component_id
        )

        required_ids.append(
            component_id
        )

        assessments.append(
            make_component_assessment(
                evaluation,
                effect="NOT_EVALUATED",
            )
        )

    record[
        "required_data_components"
    ] = required_ids

    record[
        "component_assessments"
    ] = assessments

    record[
        "eligibility_decision"
    ] = "EXTERNAL_HUNT_ONLY"

    record[
        "reason_codes"
    ] = [
        "PRE_ATTACK_EXTERNAL_SCOPE"
    ]


def evaluate_record(
    context: dict[str, Any],
    router: dict[str, Any],
    output: dict[str, Any],
    generated_at: str,
) -> dict[str, Any]:
    validate_common_record(
        context,
        router,
        output,
    )

    fingerprint = (
        build_input_fingerprint(
            context,
            router,
            output,
        )
    )

    record = base_record(
        context=context,
        router=router,
        output=output,
        generated_at=generated_at,
        fingerprint=fingerprint,
    )

    route = output[
        "route"
    ]

    if route == "runtime_hunt":
        evaluate_runtime(
            record,
            context,
            output,
        )

    elif route == (
        "collection_gap_resolution"
    ):
        evaluate_collection_gap(
            record,
            context,
        )

    elif route == (
        "environment_resolution"
    ):
        evaluate_environment_resolution(
            record,
            context,
        )

    elif route == "pre_attack_hunt":
        evaluate_pre_attack(
            record,
            context,
            output,
        )

    else:
        raise ValueError(
            f"unsupported_route:{route}"
        )

    decision = record[
        "eligibility_decision"
    ]

    record[
        "downstream_action"
    ] = DOWNSTREAM_ACTIONS[
        decision
    ]

    return record


def build_index_record(
    record: dict[str, Any],
) -> dict[str, Any]:
    return {
        "gate_version":
            record["gate_version"],

        "technique_id":
            record["technique_id"],

        "technique_name":
            record["technique_name"],

        "source_route":
            record["source_route"],

        "runtime_hunt_rank":
            record["runtime_hunt_rank"],

        "processing_status":
            record["processing_status"],

        "eligibility_decision":
            record["eligibility_decision"],

        "reason_codes":
            record["reason_codes"],

        "downstream_action":
            record["downstream_action"],

        "input_fingerprint":
            record["input_fingerprint"],
    }


def main() -> int:
    required_files = [
        MASTER_FILE,
        ROUTER_FILE,
        SCHEMA_FILE,
        *OUTPUT_FILES.values(),
    ]

    for path in required_files:
        if not path.exists():
            raise FileNotFoundError(
                f"Missing required input: {path}"
            )

    schema = read_json(
        SCHEMA_FILE
    )

    schema_validator = (
        Draft202012Validator(
            schema,
            format_checker=FormatChecker(),
        )
    )

    master_rows = read_jsonl(
        MASTER_FILE
    )

    router_rows = read_jsonl(
        ROUTER_FILE
    )

    output_rows = []

    for route, path in OUTPUT_FILES.items():
        for row in read_jsonl(path):
            if row.get("route") != route:
                raise RuntimeError(
                    "Output file route mismatch:"
                    f"{path}:"
                    f"{row.get('technique_id')}:"
                    f"{row.get('route')}"
                )

            output_rows.append(
                row
            )

    master = build_unique_index(
        master_rows,
        "master_context",
    )

    router = build_unique_index(
        router_rows,
        "router_index",
    )

    outputs = build_unique_index(
        output_rows,
        "hypothesis_outputs",
    )

    master_ids = set(
        master
    )

    router_ids = set(
        router
    )

    output_ids = set(
        outputs
    )

    if not (
        master_ids
        == router_ids
        == output_ids
    ):
        raise RuntimeError(
            "Authoritative artifact technique sets "
            "do not match. "
            f"master={len(master_ids)} "
            f"router={len(router_ids)} "
            f"outputs={len(output_ids)}"
        )

    generated_at = utc_now()

    decision_rows = []
    error_rows = []

    # Stable ordering:
    # runtime ranked first, then remaining routes
    # by router queue position and technique ID.
    ordered_outputs = sorted(
        output_rows,
        key=lambda row: (
            {
                "runtime_hunt": 0,
                "collection_gap_resolution": 1,
                "environment_resolution": 2,
                "pre_attack_hunt": 3,
            }[
                row["route"]
            ],
            (
                row.get(
                    "runtime_hunt_rank"
                )
                if row.get(
                    "runtime_hunt_rank"
                )
                is not None
                else row.get(
                    "router_queue_position"
                )
                or 0
            ),
            row["technique_id"],
        ),
    )

    for output in ordered_outputs:
        technique_id = output[
            "technique_id"
        ]

        context = master[
            technique_id
        ]

        router_record = router[
            technique_id
        ]

        try:
            record = evaluate_record(
                context,
                router_record,
                output,
                generated_at,
            )

            schema_errors = sorted(
                schema_validator.iter_errors(
                    record
                ),
                key=lambda error: (
                    list(error.path)
                ),
            )

            if schema_errors:
                formatted = []

                for error in schema_errors:
                    path = ".".join(
                        str(value)
                        for value in error.path
                    )

                    formatted.append(
                        "schema:"
                        f"{path or '<root>'}:"
                        f"{error.message}"
                    )

                raise ValueError(
                    "|".join(
                        formatted
                    )
                )

            decision_rows.append(
                record
            )

        except Exception as exc:
            error_rows.append(
                {
                    "gate_version":
                        GATE_VERSION,

                    "generated_at_utc":
                        generated_at,

                    "technique_id":
                        output.get(
                            "technique_id"
                        ),

                    "technique_name":
                        output.get(
                            "technique_name"
                        ),

                    "source_route":
                        output.get(
                            "route"
                        ),

                    "error":
                        str(exc),

                    "input_fingerprint":
                        build_input_fingerprint(
                            context,
                            router_record,
                            output,
                        ),
                }
            )

    index_rows = [
        build_index_record(
            record
        )
        for record in decision_rows
    ]

    decision_counts = Counter(
        record[
            "eligibility_decision"
        ]
        for record in decision_rows
    )

    route_counts = Counter(
        record[
            "source_route"
        ]
        for record in decision_rows
    )

    summary = {
        "gate_version":
            GATE_VERSION,

        "contract_version":
            CONTRACT_VERSION,

        "rules_version":
            RULES_VERSION,

        "generated_at_utc":
            generated_at,

        "input_counts": {
            "master_context":
                len(master_rows),

            "router_index":
                len(router_rows),

            "hypothesis_outputs":
                len(output_rows),
        },

        "processed_successfully":
            len(decision_rows),

        "processing_errors":
            len(error_rows),

        "decision_counts":
            dict(
                sorted(
                    decision_counts.items()
                )
            ),

        "route_counts":
            dict(
                sorted(
                    route_counts.items()
                )
            ),

        "output_files": {
            "decisions":
                str(
                    DECISION_OUTPUT.relative_to(
                        PROJECT_ROOT
                    )
                ),

            "index":
                str(
                    INDEX_OUTPUT.relative_to(
                        PROJECT_ROOT
                    )
                ),

            "errors":
                str(
                    ERROR_OUTPUT.relative_to(
                        PROJECT_ROOT
                    )
                ),
        },
    }

    # Atomic commit only after the full run.
    atomic_write_jsonl(
        DECISION_OUTPUT,
        decision_rows,
    )

    atomic_write_jsonl(
        INDEX_OUTPUT,
        index_rows,
    )

    atomic_write_jsonl(
        ERROR_OUTPUT,
        error_rows,
    )

    atomic_write_json(
        SUMMARY_OUTPUT,
        summary,
    )

    print(
        "===== DETECTION ELIGIBILITY GATE v1.0 ====="
    )

    print(
        f"Master contexts       : {len(master_rows)}"
    )

    print(
        f"Router records        : {len(router_rows)}"
    )

    print(
        f"Hypothesis outputs    : {len(output_rows)}"
    )

    print()

    print(
        f"Successful decisions  : {len(decision_rows)}"
    )

    print(
        f"Processing errors     : {len(error_rows)}"
    )

    print()

    print(
        "Decisions:"
    )

    for decision in [
        "ELIGIBLE_FOR_DETECTION",
        "COLLECTION_BLOCKED",
        "ENVIRONMENT_BLOCKED",
        "EXTERNAL_HUNT_ONLY",
        "NOT_ELIGIBLE",
    ]:
        print(
            f"{decision:<26}: "
            f"{decision_counts.get(decision, 0)}"
        )

    print()

    print(
        f"Decision output       : {DECISION_OUTPUT}"
    )

    print(
        f"Eligibility index     : {INDEX_OUTPUT}"
    )

    print(
        f"Error queue           : {ERROR_OUTPUT}"
    )

    print(
        f"Summary               : {SUMMARY_OUTPUT}"
    )

    if error_rows:
        print()
        print(
            "Gate completed with processing errors."
        )

        return 2

    print()
    print(
        "Detection Eligibility Gate v1.0: PASS"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
