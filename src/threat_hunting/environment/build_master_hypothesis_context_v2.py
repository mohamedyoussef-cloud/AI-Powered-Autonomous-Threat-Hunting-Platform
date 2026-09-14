from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]


ATTACK_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "knowledge"
    / "attack_techniques_active.jsonl"
)

PRIORITY_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "environment"
    / "adaptive_product_prioritization_v2.jsonl"
)

READINESS_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "environment"
    / "master_telemetry_readiness_v2.jsonl"
)

TELEMETRY_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "telemetry"
    / "resolved"
    / "technique_telemetry_evidence_v2_1.jsonl"
)

SIGMA_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "environment"
    / "master_sigma_knowledge_gap_v1.jsonl"
)

ENVIRONMENT_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "environment"
    / "environment_profile_product_v2.json"
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


MASTER_OUTPUT = (
    OUTPUT_DIR
    / "master_hypothesis_context_v2.jsonl"
)

RUNTIME_OUTPUT = (
    OUTPUT_DIR
    / "hypothesis_context_runtime_hunt_v2.jsonl"
)

COLLECTION_GAP_OUTPUT = (
    OUTPUT_DIR
    / "hypothesis_context_collection_gap_v2.jsonl"
)

ENVIRONMENT_OUTPUT = (
    OUTPUT_DIR
    / "hypothesis_context_environment_resolution_v2.jsonl"
)

PRE_OUTPUT = (
    OUTPUT_DIR
    / "hypothesis_context_pre_attack_v2.jsonl"
)

TOP20_OUTPUT = (
    OUTPUT_DIR
    / "hypothesis_context_runtime_hunt_v2_top20.jsonl"
)

REPORT_OUTPUT = (
    REPORT_DIR
    / "master_hypothesis_context_v2_summary.json"
)


ROUTE_MAP = {
    "eligible_for_hunt_prioritization":
        "runtime_hunt",

    "route_to_collection_gap_workflow":
        "collection_gap_resolution",

    "conditional_environment_resolution":
        "environment_resolution",

    "route_to_pre_attack_workflow":
        "pre_attack_hunt",
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


def llm_task_for_route(route):

    if route == "runtime_hunt":

        return {
            "task_mode": (
                "generate_runtime_hunt_hypothesis"
            ),

            "objective": (
                "Generate an explainable threat "
                "hunting hypothesis for a technique "
                "that is currently applicable and "
                "telemetry-observable."
            ),

            "required_output_fields": [
                "hypothesis",
                "rationale",
                "investigation_focus",
                "required_telemetry",
                "known_collection_limitations",
                "confidence"
            ],

            "execution_allowed": True,
        }

    if route == (
        "collection_gap_resolution"
    ):

        return {
            "task_mode": (
                "resolve_collection_gap"
            ),

            "objective": (
                "Explain which ATT&CK telemetry "
                "requirements are currently missing "
                "or unsupported and what collection "
                "capabilities must be added before "
                "runtime hunting."
            ),

            "required_output_fields": [
                "collection_gap",
                "affected_data_components",
                "required_collection",
                "current_evidence_limitations",
                "next_action"
            ],

            "execution_allowed": False,
        }

    if route == (
        "environment_resolution"
    ):

        return {
            "task_mode": (
                "resolve_environment_presence"
            ),

            "objective": (
                "Determine what environment or "
                "asset evidence is required to "
                "establish whether the technique's "
                "platform is present before runtime "
                "hunt applicability is asserted."
            ),

            "required_output_fields": [
                "unresolved_platforms",
                "required_environment_evidence",
                "resolution_questions",
                "next_action"
            ],

            "execution_allowed": False,
        }

    if route == "pre_attack_hunt":

        return {
            "task_mode": (
                "generate_pre_attack_hypothesis"
            ),

            "objective": (
                "Generate a PRE-attack investigation "
                "hypothesis using appropriate "
                "external, intelligence, or "
                "pre-compromise evidence rather than "
                "runtime endpoint telemetry scoring."
            ),

            "required_output_fields": [
                "hypothesis",
                "rationale",
                "investigation_focus",
                "required_external_evidence",
                "limitations",
                "confidence"
            ],

            "execution_allowed": True,
        }

    raise RuntimeError(
        f"Unsupported hypothesis route: {route}"
    )


def main():

    required_files = [
        ATTACK_FILE,
        PRIORITY_FILE,
        READINESS_FILE,
        TELEMETRY_FILE,
        SIGMA_FILE,
        ENVIRONMENT_FILE,
    ]

    for path in required_files:

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

    attack_rows = read_jsonl(
        ATTACK_FILE
    )

    priority_rows = read_jsonl(
        PRIORITY_FILE
    )

    readiness_rows = read_jsonl(
        READINESS_FILE
    )

    telemetry_rows = read_jsonl(
        TELEMETRY_FILE
    )

    sigma_rows = read_jsonl(
        SIGMA_FILE
    )

    environment = json.loads(
        ENVIRONMENT_FILE.read_text(
            encoding="utf-8"
        )
    )


    validation_errors = []


    input_sets = {
        "ATT&CK": attack_rows,
        "priority": priority_rows,
        "readiness": readiness_rows,
        "telemetry": telemetry_rows,
        "Sigma": sigma_rows,
    }

    for name, rows in input_sets.items():

        if len(rows) != 697:

            validation_errors.append(
                f"{name} input expected 697 "
                f"records, found {len(rows)}"
            )


    attack_map = {
        row["technique_id"]: row
        for row in attack_rows
    }

    priority_map = {
        row["technique_id"]: row
        for row in priority_rows
    }

    readiness_map = {
        row["technique_id"]: row
        for row in readiness_rows
    }

    telemetry_map = {
        row["technique_id"]: row
        for row in telemetry_rows
    }

    sigma_map = {
        row["technique_id"]: row
        for row in sigma_rows
    }


    master_ids = set(
        attack_map
    )

    for name, mapping in [
        ("priority", priority_map),
        ("readiness", readiness_map),
        ("telemetry", telemetry_map),
        ("Sigma", sigma_map),
    ]:

        if set(mapping) != master_ids:

            validation_errors.append(
                f"Technique ID mismatch: {name}"
            )


    observed_platforms = sorted(
        environment.get(
            "observed_platforms",
            []
        )
    )

    unknown_platforms = sorted(
        environment.get(
            "unknown_platform_presence",
            []
        )
    )

    contexts = []


    for technique_id in sorted(
        master_ids
    ):

        attack = attack_map[
            technique_id
        ]

        priority = priority_map[
            technique_id
        ]

        readiness = readiness_map[
            technique_id
        ]

        telemetry = telemetry_map[
            technique_id
        ]

        sigma = sigma_map[
            technique_id
        ]


        priority_route = priority.get(
            "priority_route"
        )

        route = ROUTE_MAP.get(
            priority_route
        )

        if route is None:

            validation_errors.append(
                f"{technique_id}: unsupported "
                f"priority route {priority_route}"
            )

            route = "environment_resolution"


        runtime_rank = priority.get(
            "runtime_hunt_rank"
        )

        priority_score = priority.get(
            "priority_score"
        )


        asset_score = priority.get(
            "asset_criticality_score"
        )

        incident_score = priority.get(
            "incident_history_relevance_score"
        )

        client_detection_available = (
            priority.get(
                "is_client_detection_coverage"
            )
            is True
        )


        context = {
            "context_version": "2.0",

            "context_scope": (
                "master_product_hypothesis_context"
            ),

            "technique_id": (
                technique_id
            ),

            "route": route,

            "route_source": (
                priority_route
            ),

            "product_master_record": True,


            "technique": {
                "technique_id": (
                    technique_id
                ),

                "technique_name": (
                    attack.get(
                        "name"
                    )
                ),

                "description": (
                    attack.get(
                        "description"
                    )
                ),

                "is_subtechnique": bool(
                    attack.get(
                        "is_subtechnique",
                        False,
                    )
                ),

                "parent_technique_id": (
                    attack.get(
                        "parent_technique_id"
                    )
                ),

                "tactics": sorted(
                    attack.get(
                        "tactics"
                    )
                    or []
                ),

                "platforms": sorted(
                    attack.get(
                        "platforms"
                    )
                    or []
                ),

                "data_components": sorted(
                    attack.get(
                        "data_components"
                    )
                    or []
                ),

                "detection_strategy_ids": (
                    attack.get(
                        "detection_strategy_ids"
                    )
                    or []
                ),

                "analytic_ids": (
                    attack.get(
                        "analytic_ids"
                    )
                    or []
                ),

                "attack_version": (
                    attack.get(
                        "attack_version"
                    )
                ),
            },


            "environment": {
                "environment_id": (
                    environment.get(
                        "environment_id"
                    )
                ),

                "profile_version": (
                    environment.get(
                        "profile_version"
                    )
                ),

                "observed_platforms": (
                    observed_platforms
                ),

                "unknown_platform_presence": (
                    unknown_platforms
                ),

                "technique_observed_platform_matches": (
                    telemetry.get(
                        "observed_platform_matches"
                    )
                    or []
                ),

                "technique_unknown_platform_matches": (
                    telemetry.get(
                        "unknown_platform_matches"
                    )
                    or []
                ),

                "current_environment_applicability": (
                    readiness.get(
                        "current_environment_applicability"
                    )
                ),

                "applicability_status": (
                    readiness.get(
                        "applicability_status"
                    )
                ),

                "asset_inventory_available": (
                    False
                ),

                "asset_criticality_available": (
                    asset_score is not None
                ),

                "incident_history_available": (
                    incident_score is not None
                ),

                "client_detection_coverage_available": (
                    client_detection_available
                ),
            },


            "telemetry": {
                "resolver_version": (
                    telemetry.get(
                        "resolver_version"
                    )
                ),

                "environment_scope": (
                    telemetry.get(
                        "environment_scope"
                    )
                ),

                "evidence_status": (
                    telemetry.get(
                        "telemetry_evidence_status"
                    )
                ),

                "readiness_score": (
                    readiness.get(
                        "telemetry_readiness_score"
                    )
                ),

                "readiness_band": (
                    readiness.get(
                        "telemetry_readiness_band"
                    )
                ),

                "readiness_state": (
                    readiness.get(
                        "telemetry_readiness_state"
                    )
                ),

                "component_evidence_coverage_pct": (
                    telemetry.get(
                        "component_evidence_coverage_pct"
                    )
                ),

                "exact_event_component_coverage_pct": (
                    telemetry.get(
                        "exact_event_component_coverage_pct"
                    )
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

                "evidence_sources": (
                    telemetry.get(
                        "evidence_sources"
                    )
                    or []
                ),

                "component_evaluations": (
                    telemetry.get(
                        "component_evaluations"
                    )
                    or []
                ),

                "evidence_interpretation": (
                    "Telemetry evidence represents "
                    "observability and collection "
                    "support only. It does not prove "
                    "that the ATT&CK technique "
                    "occurred."
                ),
            },


            "sigma_knowledge": {
                "mapped_rule_count": (
                    sigma.get(
                        "sigma_rule_count"
                    )
                ),

                "knowledge_coverage_score": (
                    sigma.get(
                        "sigma_knowledge_coverage_score"
                    )
                ),

                "knowledge_gap_score": (
                    sigma.get(
                        "sigma_detection_knowledge_gap_score"
                    )
                ),

                "knowledge_gap_class": (
                    sigma.get(
                        "sigma_detection_knowledge_gap_class"
                    )
                ),

                "gap_source": (
                    sigma.get(
                        "gap_source"
                    )
                ),

                "is_client_detection_coverage": (
                    False
                ),

                "zero_rule_semantics": (
                    "A zero rule count means no "
                    "mapped rules were found in the "
                    "current prepared Sigma corpus. "
                    "It does not mean that no Sigma "
                    "rules exist globally."
                ),
            },


            "prioritization": {
                "runtime_hunt_rank": (
                    runtime_rank
                ),

                "runtime_hunt_rank_eligible": (
                    priority.get(
                        "runtime_hunt_rank_eligible"
                    )
                ),

                "priority_score": (
                    priority_score
                ),

                "score_status": (
                    priority.get(
                        "score_status"
                    )
                ),

                "available_factor_count": (
                    priority.get(
                        "available_factor_count"
                    )
                ),

                "factor_scores": (
                    priority.get(
                        "factor_scores"
                    )
                ),

                "effective_weights": (
                    priority.get(
                        "effective_weights"
                    )
                ),

                "asset_criticality_score": (
                    asset_score
                ),

                "incident_history_relevance_score": (
                    incident_score
                ),

                "detection_gap_source": (
                    priority.get(
                        "detection_gap_source"
                    )
                ),

                "detection_gap_is_client_coverage": (
                    False
                ),
            },


            "grounding_constraints": {
                "technique_occurrence_observed": (
                    False
                ),

                "must_not_claim_occurrence": (
                    True
                ),

                "must_not_invent_indicators": (
                    True
                ),

                "must_not_invent_missing_telemetry": (
                    True
                ),

                "required_telemetry_must_be_grounded_in_attack_data_components": (
                    True
                ),

                "must_preserve_unknown_asset_context": (
                    asset_score is None
                ),

                "must_preserve_unknown_incident_history": (
                    incident_score is None
                ),

                "must_preserve_unknown_client_detection_coverage": (
                    not client_detection_available
                ),

                "sigma_proxy_is_not_client_detection_coverage": (
                    True
                ),

                "source_availability_does_not_imply_activity": (
                    True
                ),

                "broad_capability_does_not_imply_attack_data_component": (
                    True
                ),

                "detection_generation_requires_separate_eligibility_gate": (
                    True
                ),

                "do_not_generate_sigma_in_hypothesis_stage": (
                    True
                ),
            },


            "llm_task": (
                llm_task_for_route(
                    route
                )
            ),
        }


        # -----------------------------------------
        # Route invariants
        # -----------------------------------------

        if route == "runtime_hunt":

            if readiness.get(
                "current_environment_applicability"
            ) != "applicable":

                validation_errors.append(
                    f"{technique_id}: runtime hunt "
                    f"but not applicable"
                )

            if readiness.get(
                "telemetry_readiness_state"
            ) != "telemetry_observed":

                validation_errors.append(
                    f"{technique_id}: runtime hunt "
                    f"without telemetry_observed"
                )

            if runtime_rank is None:

                validation_errors.append(
                    f"{technique_id}: runtime hunt "
                    f"missing rank"
                )

            if priority_score is None:

                validation_errors.append(
                    f"{technique_id}: runtime hunt "
                    f"missing priority score"
                )


        elif route == (
            "collection_gap_resolution"
        ):

            if readiness.get(
                "current_environment_applicability"
            ) != "applicable":

                validation_errors.append(
                    f"{technique_id}: collection gap "
                    f"must remain applicable"
                )

            if readiness.get(
                "telemetry_readiness_state"
            ) != "technique_collection_gap":

                validation_errors.append(
                    f"{technique_id}: collection "
                    f"gap route without collection "
                    f"gap readiness state"
                )

            if runtime_rank is not None:

                validation_errors.append(
                    f"{technique_id}: collection gap "
                    f"incorrectly has runtime rank"
                )


        elif route == (
            "environment_resolution"
        ):

            if readiness.get(
                "current_environment_applicability"
            ) != "unknown":

                validation_errors.append(
                    f"{technique_id}: environment "
                    f"resolution route but "
                    f"applicability is not unknown"
                )

            if runtime_rank is not None:

                validation_errors.append(
                    f"{technique_id}: environment "
                    f"resolution incorrectly ranked"
                )


        elif route == "pre_attack_hunt":

            if readiness.get(
                "current_environment_applicability"
            ) != "special_scope":

                validation_errors.append(
                    f"{technique_id}: PRE route "
                    f"without special_scope"
                )

            if runtime_rank is not None:

                validation_errors.append(
                    f"{technique_id}: PRE technique "
                    f"incorrectly has runtime rank"
                )


        if sigma.get(
            "is_client_detection_coverage"
        ) is not False:

            validation_errors.append(
                f"{technique_id}: Sigma proxy "
                f"misclassified as client coverage"
            )


        if telemetry.get(
            "occurrence_claim"
        ) is not False:

            validation_errors.append(
                f"{technique_id}: telemetry "
                f"occurrence overclaim"
            )


        contexts.append(
            context
        )


    # ---------------------------------------------
    # Master validation
    # ---------------------------------------------

    if len(contexts) != 697:

        validation_errors.append(
            f"Expected 697 master contexts, "
            f"found {len(contexts)}"
        )


    context_ids = [
        row[
            "technique_id"
        ]
        for row in contexts
    ]

    if len(context_ids) != len(
        set(context_ids)
    ):

        validation_errors.append(
            "Duplicate master hypothesis contexts"
        )


    route_counter = Counter(
        row[
            "route"
        ]
        for row in contexts
    )


    runtime_rows = [
        row
        for row in contexts
        if row[
            "route"
        ] == "runtime_hunt"
    ]

    collection_rows = [
        row
        for row in contexts
        if row[
            "route"
        ] == "collection_gap_resolution"
    ]

    environment_rows = [
        row
        for row in contexts
        if row[
            "route"
        ] == "environment_resolution"
    ]

    pre_rows = [
        row
        for row in contexts
        if row[
            "route"
        ] == "pre_attack_hunt"
    ]


    runtime_rows.sort(
        key=lambda row: int(
            row[
                "prioritization"
            ][
                "runtime_hunt_rank"
            ]
        )
    )


    actual_ranks = [
        row[
            "prioritization"
        ][
            "runtime_hunt_rank"
        ]
        for row in runtime_rows
    ]

    expected_ranks = list(
        range(
            1,
            len(runtime_rows) + 1,
        )
    )

    if actual_ranks != expected_ranks:

        validation_errors.append(
            "Runtime hunt ranks are not "
            "contiguous"
        )


    # No route may disappear from the master
    # context merely because the current
    # environment has no items in that route.
    expected_route_names = {
        "runtime_hunt",
        "collection_gap_resolution",
        "environment_resolution",
        "pre_attack_hunt",
    }

    if not set(
        route_counter
    ).issubset(
        expected_route_names
    ):

        validation_errors.append(
            "Unexpected master context route"
        )


    occurrence_overclaims = [
        row["technique_id"]
        for row in contexts
        if (
            row[
                "grounding_constraints"
            ][
                "technique_occurrence_observed"
            ]
            is not False
        )
    ]

    if occurrence_overclaims:

        validation_errors.append(
            "Technique occurrence overclaim "
            "detected in master contexts"
        )


    # ---------------------------------------------
    # Write master + derived route queues
    # ---------------------------------------------

    write_jsonl(
        MASTER_OUTPUT,
        contexts,
    )

    write_jsonl(
        RUNTIME_OUTPUT,
        runtime_rows,
    )

    write_jsonl(
        COLLECTION_GAP_OUTPUT,
        collection_rows,
    )

    write_jsonl(
        ENVIRONMENT_OUTPUT,
        environment_rows,
    )

    write_jsonl(
        PRE_OUTPUT,
        pre_rows,
    )

    write_jsonl(
        TOP20_OUTPUT,
        runtime_rows[:20],
    )


    validation_status = (
        "PASS"
        if not validation_errors
        else "FAIL"
    )


    report = {
        "component": (
            "master_hypothesis_context"
        ),

        "version": "2.0",

        "generated_at_utc": (
            datetime.now(
                timezone.utc
            ).isoformat()
        ),

        "master_attack_techniques": (
            len(
                attack_rows
            )
        ),

        "master_contexts_generated": (
            len(
                contexts
            )
        ),

        "route_counts": dict(
            sorted(
                route_counter.items()
            )
        ),

        "runtime_hunt_contexts": (
            len(
                runtime_rows
            )
        ),

        "collection_gap_contexts": (
            len(
                collection_rows
            )
        ),

        "environment_resolution_contexts": (
            len(
                environment_rows
            )
        ),

        "pre_attack_contexts": (
            len(
                pre_rows
            )
        ),

        "observed_environment_platforms": (
            observed_platforms
        ),

        "unknown_environment_platforms": (
            unknown_platforms
        ),

        "runtime_rank_contiguous": (
            actual_ranks
            == expected_ranks
        ),

        "first_runtime_hunt": (
            {
                "rank": (
                    runtime_rows[0][
                        "prioritization"
                    ][
                        "runtime_hunt_rank"
                    ]
                ),

                "technique_id": (
                    runtime_rows[0][
                        "technique_id"
                    ]
                ),

                "technique_name": (
                    runtime_rows[0][
                        "technique"
                    ][
                        "technique_name"
                    ]
                ),
            }
            if runtime_rows
            else None
        ),

        "last_runtime_hunt": (
            {
                "rank": (
                    runtime_rows[-1][
                        "prioritization"
                    ][
                        "runtime_hunt_rank"
                    ]
                ),

                "technique_id": (
                    runtime_rows[-1][
                        "technique_id"
                    ]
                ),

                "technique_name": (
                    runtime_rows[-1][
                        "technique"
                    ][
                        "technique_name"
                    ]
                ),
            }
            if runtime_rows
            else None
        ),

        "grounding_policy": {
            "occurrence_claim_allowed": False,

            "invent_missing_telemetry_allowed": (
                False
            ),

            "invent_asset_context_allowed": (
                False
            ),

            "invent_incident_history_allowed": (
                False
            ),

            "invent_client_detection_coverage_allowed": (
                False
            ),

            "sigma_proxy_is_client_coverage": (
                False
            ),

            "detection_eligibility": (
                "separate_gate"
            ),

            "sigma_generation_in_hypothesis_stage": (
                False
            ),
        },

        "inputs": {
            "attack": (
                "attack_techniques_active"
            ),

            "environment": (
                "environment_profile_product_v2"
            ),

            "readiness": (
                "master_telemetry_readiness_v2"
            ),

            "telemetry": (
                "technique_telemetry_evidence_v2_1"
            ),

            "prioritization": (
                "adaptive_product_prioritization_v2"
            ),

            "sigma_proxy": (
                "master_sigma_knowledge_gap_v1"
            ),
        },

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
        "Master Hypothesis Context v2.0"
    )

    print(
        "-----------------------------"
    )

    print(
        f"Master ATT&CK techniques : "
        f"{len(attack_rows)}"
    )

    print(
        f"Master contexts          : "
        f"{len(contexts)}"
    )

    print()

    print(
        "Routes:"
    )

    for route, count in sorted(
        route_counter.items()
    ):

        print(
            f"  {route:<32} {count}"
        )

    print()

    print(
        f"Runtime hunt contexts    : "
        f"{len(runtime_rows)}"
    )

    print(
        f"Collection gap contexts  : "
        f"{len(collection_rows)}"
    )

    print(
        f"Environment resolution   : "
        f"{len(environment_rows)}"
    )

    print(
        f"PRE attack contexts      : "
        f"{len(pre_rows)}"
    )

    print()

    print(
        "Runtime rank contiguous  : "
        + (
            "YES"
            if actual_ranks
            == expected_ranks
            else "NO"
        )
    )

    print()

    if runtime_rows:

        first = runtime_rows[0]
        last = runtime_rows[-1]

        print(
            "First runtime hunt       : "
            f"#{first['prioritization']['runtime_hunt_rank']} "
            f"{first['technique_id']} "
            f"{first['technique']['technique_name']}"
        )

        print(
            "Last runtime hunt        : "
            f"#{last['prioritization']['runtime_hunt_rank']} "
            f"{last['technique_id']} "
            f"{last['technique']['technique_name']}"
        )

        print()

    print(
        "Occurrence claims         : "
        "DISALLOWED"
    )

    print(
        "Sigma proxy client cover  : "
        "FALSE"
    )

    print(
        "Detection eligibility     : "
        "SEPARATE GATE"
    )

    print(
        "Sigma generation here     : "
        "NO"
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
        f"Master JSONL : {MASTER_OUTPUT}"
    )

    print(
        f"Runtime      : {RUNTIME_OUTPUT}"
    )

    print(
        f"Collection   : {COLLECTION_GAP_OUTPUT}"
    )

    print(
        f"Environment  : {ENVIRONMENT_OUTPUT}"
    )

    print(
        f"PRE          : {PRE_OUTPUT}"
    )

    print(
        f"Top20 QA     : {TOP20_OUTPUT}"
    )

    print(
        f"Report       : {REPORT_OUTPUT}"
    )


if __name__ == "__main__":
    main()