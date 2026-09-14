from __future__ import annotations

import hashlib
import json
import re

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(r"D:\ThreatHunting\project")

PHASE3 = (
    ROOT
    / "data"
    / "processed"
    / "phase3"
)

INPUT_PATH = (
    PHASE3
    / "detection_plan"
    / "detection_plan_rag_contexts_v1.jsonl"
)

OUTPUT_DIR = (
    PHASE3
    / "detection_plan"
)

REPORT_DIR = (
    ROOT
    / "reports"
    / "phase3"
)

DISPATCH_PATH = (
    OUTPUT_DIR
    / "detection_plan_baseline_dispatch_v1.jsonl"
)

INDEX_PATH = (
    OUTPUT_DIR
    / "detection_plan_path_resolution_index_v1.jsonl"
)

ERROR_PATH = (
    OUTPUT_DIR
    / "detection_plan_baseline_dispatch_errors_v1.jsonl"
)

SUMMARY_PATH = (
    REPORT_DIR
    / "detection_plan_baseline_dispatch_v1_summary.json"
)

LLM_SCHEMA_PATH = (
    ROOT
    / "schemas"
    / "phase3"
    / "detection_plan"
    / "detection_plan_llm_semantic_output_v1.schema.json"
)


def read_jsonl(
    path: Path,
) -> list[dict[str, Any]]:

    rows = []

    with path.open(
        "r",
        encoding="utf-8-sig",
    ) as handle:

        for line_no, line in enumerate(
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
                    f"Invalid JSONL "
                    f"{path}:{line_no}: {exc}"
                ) from exc

            if not isinstance(row, dict):
                raise RuntimeError(
                    f"Non-object JSONL "
                    f"{path}:{line_no}"
                )

            rows.append(row)

    return rows


def write_jsonl(
    path: Path,
    rows: list[dict[str, Any]],
) -> None:

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temp = path.with_suffix(
        path.suffix + ".tmp"
    )

    with temp.open(
        "w",
        encoding="utf-8",
        newline="\n",
    ) as handle:

        for row in rows:

            handle.write(
                json.dumps(
                    row,
                    ensure_ascii=False,
                    sort_keys=True,
                )
            )

            handle.write("\n")

    temp.replace(path)


def write_json(
    path: Path,
    value: dict[str, Any],
) -> None:

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temp = path.with_suffix(
        path.suffix + ".tmp"
    )

    temp.write_text(
        json.dumps(
            value,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    temp.replace(path)


def stable_fingerprint(
    value: Any,
) -> str:

    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    return (
        "sha256:"
        + hashlib.sha256(
            encoded
        ).hexdigest()
    )


def stable_plan_id(
    environment_id: str,
    technique_id: str,
    fingerprint: str,
) -> str:

    seed = (
        environment_id
        + "|"
        + technique_id
        + "|"
        + fingerprint
    ).encode("utf-8")

    suffix = hashlib.sha256(
        seed
    ).hexdigest()[:24]

    return f"DP-{suffix}"


def unique_strings(
    values,
) -> list[str]:

    result = []
    seen = set()

    for value in values:

        if value is None:
            continue

        value = str(value).strip()

        if not value:
            continue

        if value in seen:
            continue

        seen.add(value)
        result.append(value)

    return result


def event_ids_from_channel(
    value: Any,
) -> list[str]:

    if not value:
        return []

    text = str(value)

    if (
        "eventcode" not in text.lower()
        and "event id" not in text.lower()
        and "event_id" not in text.lower()
    ):
        return []

    return unique_strings(
        re.findall(
            r"\b[0-9]{1,6}\b",
            text,
        )
    )


def normalize_required_components(
    values: list[dict[str, Any]],
) -> list[dict[str, Any]]:

    results = []

    for item in values:

        if not isinstance(
            item,
            dict,
        ):
            continue

        component_id = (
            item.get("component_id")
            or item.get(
                "data_component_id"
            )
        )

        component_name = (
            item.get("component_name")
            or item.get(
                "data_component_name"
            )
            or item.get("name")
        )

        if not component_id:
            continue

        environment_grounded = (
            item.get(
                "environment_grounded"
            )
        )

        if environment_grounded is None:
            environment_grounded = (
                item.get(
                    "current_environment_grounded"
                )
            )

        requirement_unspecified = (
            item.get(
                "requirement_unspecified"
            )
        )

        if requirement_unspecified is None:
            requirement_unspecified = False

        best_status = (
            item.get(
                "best_evidence_status"
            )
            or item.get(
                "evidence_status"
            )
            or item.get(
                "telemetry_evidence_status"
            )
            or "unknown"
        )

        results.append(
            {
                "component_id":
                    component_id,

                "component_name":
                    component_name
                    or component_id,

                "environment_grounded":
                    bool(
                        environment_grounded
                    ),

                "requirement_unspecified":
                    bool(
                        requirement_unspecified
                    ),

                "best_evidence_status":
                    str(best_status),
            }
        )

    return results


def build_grounded_path(
    technique_id: str,
    analytic: dict[str, Any],
    refs: list[dict[str, Any]],
    ordinal: int,
) -> dict[str, Any]:

    component_ids = unique_strings(
        ref.get("component_id")
        for ref in refs
    )

    requirement_ids = unique_strings(
        ref.get(
            "matched_requirement_id"
        )
        for ref in refs
    )

    log_sources = unique_strings(
        ref.get(
            "log_source_name"
        )
        for ref in refs
    )

    evidence_ids = unique_strings(
        evidence_id
        for ref in refs
        for evidence_id in ref.get(
            "evidence_ids",
            [],
        )
    )

    event_ids = unique_strings(
        event_id
        for ref in refs
        for event_id in (
            list(
                ref.get(
                    "exact_event_ids",
                    [],
                )
            )
            + event_ids_from_channel(
                ref.get("channel")
            )
        )
    )

    analytic_id = (
        analytic.get("analytic_id")
        or f"ANALYTIC-{ordinal}"
    )

    return {
        "path_id":
            (
                f"PATH-"
                f"{technique_id}-"
                f"{analytic_id}-"
                f"{ordinal:03d}"
            ),

        "analytic_id":
            analytic.get(
                "analytic_id"
            ),

        "analytic_name":
            analytic.get(
                "analytic_name"
            ),

        "analytic_description":
            analytic.get(
                "description"
            ),

        "component_ids":
            component_ids,

        "grounding_status":
            "TECHNIQUE_SPECIFIC_GROUNDED",

        "requirement_ids":
            requirement_ids,

        "log_sources":
            log_sources,

        "event_ids":
            event_ids,

        "canonical_category":
            None,

        "canonical_action":
            None,

        "field_bindings":
            [],

        "evidence_ids":
            evidence_ids,
    }


def build_unresolved_path(
    technique_id: str,
    analytic: dict[str, Any],
    ordinal: int,
) -> dict[str, Any]:

    refs = [
        ref
        for ref in analytic.get(
            "log_source_references",
            [],
        )
        if isinstance(ref, dict)
    ]

    required_refs = [
        ref
        for ref in refs
        if ref.get(
            "required_by_eligible_hypothesis"
        )
    ]

    selected_refs = (
        required_refs
        or refs
    )

    component_ids = unique_strings(
        ref.get("component_id")
        for ref in selected_refs
    )

    log_sources = unique_strings(
        ref.get("log_source_name")
        for ref in selected_refs
    )

    event_ids = unique_strings(
        event_id
        for ref in selected_refs
        for event_id in (
            list(
                ref.get(
                    "exact_event_ids",
                    [],
                )
            )
            + event_ids_from_channel(
                ref.get("channel")
            )
        )
    )

    analytic_id = (
        analytic.get("analytic_id")
        or f"ANALYTIC-{ordinal}"
    )

    return {
        "path_id":
            (
                f"PATH-"
                f"{technique_id}-"
                f"{analytic_id}-"
                f"{ordinal:03d}"
            ),

        "analytic_id":
            analytic.get(
                "analytic_id"
            ),

        "analytic_name":
            analytic.get(
                "analytic_name"
            ),

        "analytic_description":
            analytic.get(
                "description"
            ),

        "component_ids":
            component_ids,

        "grounding_status":
            (
                "COMPONENT_LEVEL_ONLY"
                if component_ids
                else "UNRESOLVED"
            ),

        "requirement_ids":
            [],

        "log_sources":
            log_sources,

        "event_ids":
            event_ids,

        "canonical_category":
            None,

        "canonical_action":
            None,

        "field_bindings":
            [],

        "evidence_ids":
            [],
    }


def resolve_paths(
    rag: dict[str, Any],
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
]:

    grounded_paths = []
    unresolved_paths = []

    tid = rag["technique_id"]

    ordinal = 0

    for analytic in rag.get(
        "retrieved_analytics",
        [],
    ):

        if not isinstance(
            analytic,
            dict,
        ):
            continue

        if not analytic.get(
            "platform_relevant"
        ):
            continue

        ordinal += 1

        refs = [
            ref
            for ref in analytic.get(
                "log_source_references",
                [],
            )
            if isinstance(ref, dict)
        ]

        usable = []

        for ref in refs:

            if (
                ref.get(
                    "environment_evidence_status"
                )
                != "GROUNDED"
            ):
                continue

            if not ref.get(
                "required_by_eligible_hypothesis"
            ):
                continue

            if not ref.get(
                "matched_requirement_id"
            ):
                continue

            if not ref.get(
                "log_source_name"
            ):
                continue

            if not ref.get(
                "evidence_ids"
            ):
                continue

            usable.append(ref)

        if usable:

            grounded_paths.append(
                build_grounded_path(
                    tid,
                    analytic,
                    usable,
                    ordinal,
                )
            )

        else:

            unresolved_paths.append(
                build_unresolved_path(
                    tid,
                    analytic,
                    ordinal,
                )
            )

    return (
        grounded_paths,
        unresolved_paths,
    )


def build_prompt(
    rag: dict[str, Any],
    deterministic: dict[str, Any],
) -> list[dict[str, str]]:

    analytic_knowledge = []

    for analytic in rag.get(
        "retrieved_analytics",
        [],
    ):

        if not analytic.get(
            "platform_relevant"
        ):
            continue

        analytic_knowledge.append(
            {
                "analytic_id":
                    analytic.get(
                        "analytic_id"
                    ),

                "description":
                    analytic.get(
                        "description"
                    ),

                "platforms":
                    analytic.get(
                        "platforms",
                        [],
                    ),
            }
        )

    semantic_context = {
        "technique": {
            "technique_id":
                rag["technique_id"],

            "technique_name":
                rag["technique_name"],

            "description":
                rag.get(
                    "attack_context",
                    {}
                ).get(
                    "technique_description"
                ),
        },

        "hypothesis":
            rag.get("hypothesis"),

        "current_environment_platforms":
            rag.get(
                "attack_context",
                {}
            ).get(
                "current_environment_platforms",
                [],
            ),

        "detection_strategies":
            rag.get(
                "retrieved_detection_strategies",
                [],
            ),

        "platform_relevant_analytics":
            analytic_knowledge,

        "deterministic_plan_status":
            deterministic[
                "plan_status"
            ],

        "grounded_detection_paths":
            deterministic[
                "grounded_paths"
            ],

        "unresolved_detection_paths":
            deterministic[
                "unresolved_paths"
            ],

        "mandatory_grounding_rules": [
            "Do not claim that the technique occurred.",
            "Do not invent fields.",
            "Do not invent event IDs.",
            "Do not invent log sources.",
            "Do not invent evidence.",
            "Do not change the deterministic plan status.",
            "Do not generate Sigma.",
            "Do not generate SIEM queries."
        ]
    }

    system = (
        "You are the semantic-writing component "
        "of a production threat-detection planning "
        "pipeline. The engineering path, evidence, "
        "status, log sources, event IDs, and fields "
        "are controlled deterministically outside "
        "the model. Your only task is to write the "
        "detection objective, observable behaviors, "
        "and known limitations using only the "
        "provided grounded context. "
        "Return JSON only. "
        "Do not add keys outside the required "
        "output schema."
    )

    user = (
        "Produce Detection Plan semantic content "
        "for the following grounded context.\n\n"
        + json.dumps(
            semantic_context,
            indent=2,
            ensure_ascii=False,
        )
        + "\n\nRequired JSON shape:\n"
        + json.dumps(
            {
                "technique_id":
                    rag["technique_id"],

                "detection_intent": {
                    "objective":
                        "<grounded objective>",

                    "observable_behaviors": [
                        "<grounded observable behavior>"
                    ]
                },

                "known_limitations": [
                    "<grounded limitation>"
                ]
            },
            indent=2,
            ensure_ascii=False,
        )
    )

    return [
        {
            "role": "system",
            "content": system,
        },
        {
            "role": "user",
            "content": user,
        },
    ]


def main() -> int:

    if not LLM_SCHEMA_PATH.exists():
        raise RuntimeError(
            "LLM semantic output schema missing: "
            + str(LLM_SCHEMA_PATH)
        )

    rows = read_jsonl(
        INPUT_PATH
    )

    dispatch = []
    index = []
    errors = []

    status_counts = Counter()

    grounded_path_count = 0
    unresolved_path_count = 0

    seen = set()


    for rag in rows:

        tid = rag.get(
            "technique_id"
        )

        try:

            if not tid:
                raise RuntimeError(
                    "Missing technique_id"
                )

            if tid in seen:
                raise RuntimeError(
                    "Duplicate technique_id"
                )

            seen.add(tid)


            if (
                rag.get(
                    "eligibility",
                    {}
                ).get("decision")
                != "ELIGIBLE_FOR_DETECTION"
            ):
                raise RuntimeError(
                    "Non-eligible input reached "
                    "Detection Plan Baseline"
                )


            grounded_paths, unresolved_paths = (
                resolve_paths(rag)
            )


            if grounded_paths:

                plan_status = (
                    "READY_FOR_BASELINE_SIGMA"
                )

                downstream_action = (
                    "BASELINE_SIGMA_GENERATION"
                )

                reason_codes = [
                    "TECHNIQUE_SPECIFIC_PATH_GROUNDED",
                    "FIELD_BINDING_NOT_RESOLVED",
                ]

            else:

                plan_status = (
                    "NEEDS_PATH_RESOLUTION"
                )

                downstream_action = (
                    "DETECTION_PATH_RESOLUTION"
                )

                reason_codes = [
                    "TECHNIQUE_SPECIFIC_PATH_NOT_RESOLVED",
                    "COMPONENT_EVIDENCE_ONLY",
                    "FIELD_BINDING_NOT_RESOLVED",
                ]


            normalized_components = (
                normalize_required_components(
                    rag.get(
                        "eligible_required_components",
                        [],
                    )
                )
            )


            deterministic_core = {
                "plan_status":
                    plan_status,

                "downstream_action":
                    downstream_action,

                "reason_codes":
                    reason_codes,

                "grounded_paths":
                    grounded_paths,

                "unresolved_paths":
                    unresolved_paths,

                "required_components":
                    normalized_components,
            }


            plan_input_fingerprint = (
                stable_fingerprint(
                    {
                        "rag_input_fingerprint":
                            rag[
                                "rag_input_fingerprint"
                            ],

                        "deterministic_core":
                            deterministic_core,
                    }
                )
            )


            plan_id = stable_plan_id(
                rag["environment_id"],
                tid,
                plan_input_fingerprint,
            )


            record = {
                "dispatch_version": "1.0",

                "generated_at_utc":
                    datetime.now(
                        timezone.utc
                    ).isoformat(),

                "technique_id":
                    tid,

                "technique_name":
                    rag["technique_name"],

                "environment_id":
                    rag["environment_id"],

                "runtime_hunt_rank":
                    rag.get(
                        "runtime_hunt_rank"
                    ),

                "plan_identity": {
                    "plan_id":
                        plan_id,

                    "artifact_revision":
                        1,

                    "plan_input_fingerprint":
                        plan_input_fingerprint,
                },

                "execution_context": {
                    "campaign_id": None,
                    "run_id": None,
                    "trace_id": None,
                },

                "eligibility":
                    rag["eligibility"],

                "attack_context":
                    rag[
                        "attack_context"
                    ],

                "hypothesis":
                    rag["hypothesis"],

                "deterministic_resolution":
                    deterministic_core,

                "llm_task": {
                    "task_name":
                        "generate_detection_plan_semantics",

                    "model_call_performed":
                        False,

                    "output_schema":
                        str(
                            LLM_SCHEMA_PATH
                        ),

                    "messages":
                        build_prompt(
                            rag,
                            deterministic_core,
                        ),
                },

                "grounding_policy":
                    rag[
                        "grounding_policy"
                    ],

                "source_rag_fingerprint":
                    rag[
                        "rag_input_fingerprint"
                    ],
            }


            dispatch.append(record)

            status_counts[
                plan_status
            ] += 1

            grounded_path_count += len(
                grounded_paths
            )

            unresolved_path_count += len(
                unresolved_paths
            )


            index.append(
                {
                    "technique_id":
                        tid,

                    "technique_name":
                        rag[
                            "technique_name"
                        ],

                    "environment_id":
                        rag[
                            "environment_id"
                        ],

                    "runtime_hunt_rank":
                        rag.get(
                            "runtime_hunt_rank"
                        ),

                    "plan_id":
                        plan_id,

                    "plan_status":
                        plan_status,

                    "downstream_action":
                        downstream_action,

                    "grounded_path_count":
                        len(
                            grounded_paths
                        ),

                    "unresolved_path_count":
                        len(
                            unresolved_paths
                        ),

                    "plan_input_fingerprint":
                        plan_input_fingerprint,

                    "model_call_performed":
                        False,
                }
            )


        except Exception as exc:

            errors.append(
                {
                    "technique_id":
                        tid,

                    "error_type":
                        type(exc).__name__,

                    "error":
                        str(exc),
                }
            )


    write_jsonl(
        DISPATCH_PATH,
        dispatch,
    )

    write_jsonl(
        INDEX_PATH,
        index,
    )

    write_jsonl(
        ERROR_PATH,
        errors,
    )


    summary = {
        "dispatch_version": "1.0",

        "input_contexts":
            len(rows),

        "successful_dispatch_records":
            len(dispatch),

        "processing_errors":
            len(errors),

        "plan_status_counts":
            dict(status_counts),

        "grounded_detection_paths":
            grounded_path_count,

        "unresolved_detection_paths":
            unresolved_path_count,

        "model_calls_performed":
            0,

        "outputs": {
            "dispatch":
                str(DISPATCH_PATH),

            "index":
                str(INDEX_PATH),

            "errors":
                str(ERROR_PATH),
        },
    }

    write_json(
        SUMMARY_PATH,
        summary,
    )


    print(
        "===== DETECTION PLAN BASELINE "
        "DISPATCH v1.0 ====="
    )

    print()

    print(
        "Input RAG contexts        :",
        len(rows),
    )

    print(
        "Successful dispatch       :",
        len(dispatch),
    )

    print(
        "Processing errors         :",
        len(errors),
    )

    print()

    print(
        "READY_FOR_BASELINE_SIGMA  :",
        status_counts[
            "READY_FOR_BASELINE_SIGMA"
        ],
    )

    print(
        "NEEDS_PATH_RESOLUTION     :",
        status_counts[
            "NEEDS_PATH_RESOLUTION"
        ],
    )

    print()

    print(
        "Grounded detection paths  :",
        grounded_path_count,
    )

    print(
        "Unresolved detection paths:",
        unresolved_path_count,
    )

    print()

    print(
        "Model calls performed     : 0"
    )

    print()

    print(
        "Dispatch:",
        DISPATCH_PATH,
    )

    print(
        "Index   :",
        INDEX_PATH,
    )

    print(
        "Errors  :",
        ERROR_PATH,
    )

    print(
        "Summary :",
        SUMMARY_PATH,
    )


    if errors:

        print()

        print(
            "Detection Plan Baseline "
            "Dispatch v1.0: FAIL"
        )

        return 2


    print()

    print(
        "Detection Plan Baseline "
        "Dispatch v1.0: PASS"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
