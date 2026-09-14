from __future__ import annotations

import hashlib
import json
import re

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(r"D:\ThreatHunting\project")

PHASE3 = ROOT / "data" / "processed" / "phase3"
KNOWLEDGE = ROOT / "data" / "processed" / "knowledge"
TELEMETRY = ROOT / "data" / "processed" / "telemetry"

ELIGIBILITY_PATH = (
    PHASE3
    / "detection_eligibility"
    / "detection_eligibility_outputs_v1.jsonl"
)

MASTER_PATH = (
    PHASE3
    / "master_hypothesis_context_v2.jsonl"
)

HYPOTHESIS_PATH = (
    PHASE3
    / "hypothesis_engine"
    / "runtime_hunt_outputs_v1.jsonl"
)

ANALYTICS_PATH = (
    KNOWLEDGE
    / "attack_analytics.jsonl"
)

STRATEGIES_PATH = (
    KNOWLEDGE
    / "attack_detection_strategies.jsonl"
)

COMPONENTS_PATH = (
    KNOWLEDGE
    / "attack_data_components.jsonl"
)

RESOLVED_PATH = (
    TELEMETRY
    / "resolved"
    / "attack_data_component_evidence_v2_1.jsonl"
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

RAG_OUTPUT = (
    OUTPUT_DIR
    / "detection_plan_rag_contexts_v1.jsonl"
)

INDEX_OUTPUT = (
    OUTPUT_DIR
    / "detection_plan_rag_index_v1.jsonl"
)

ERROR_OUTPUT = (
    OUTPUT_DIR
    / "detection_plan_rag_errors_v1.jsonl"
)

SUMMARY_OUTPUT = (
    REPORT_DIR
    / "detection_plan_rag_context_v1_summary.json"
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
                rows.append(
                    json.loads(line)
                )

            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    f"Invalid JSONL "
                    f"{path}:{line_no}: {exc}"
                ) from exc

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
            indent=2,
            ensure_ascii=False,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    temp.replace(path)


def index_unique(
    rows: list[dict[str, Any]],
    key: str,
    label: str,
) -> dict[str, dict[str, Any]]:

    result = {}

    for row in rows:

        value = row.get(key)

        if not value:
            raise RuntimeError(
                f"{label}: missing {key}"
            )

        if value in result:
            raise RuntimeError(
                f"{label}: duplicate {key}:{value}"
            )

        result[value] = row

    return result


def normalize_source(
    value: Any,
) -> str:

    if value is None:
        return ""

    return re.sub(
        r"[^a-z0-9]+",
        "",
        str(value).lower(),
    )


def extract_event_ids(
    value: Any,
) -> list[str]:

    if not value:
        return []

    text = str(value)

    found = re.findall(
        r"(?i)"
        r"(?:eventcode|event[\s_-]*id)"
        r"\s*[:=]?\s*"
        r"([0-9]+)",
        text,
    )

    return list(
        dict.fromkeys(found)
    )


def component_external_id(
    row: dict[str, Any],
) -> str | None:

    for key in [
        "component_id",
        "external_id",
        "data_component_id",
    ]:

        value = row.get(key)

        if (
            isinstance(value, str)
            and re.fullmatch(
                r"DC[0-9]{4}",
                value,
            )
        ):
            return value

    raw = row.get("raw")

    if isinstance(raw, dict):

        for ref in raw.get(
            "external_references",
            [],
        ):

            if not isinstance(ref, dict):
                continue

            value = ref.get(
                "external_id"
            )

            if (
                isinstance(value, str)
                and re.fullmatch(
                    r"DC[0-9]{4}",
                    value,
                )
            ):
                return value

    return None


def requirement_rank(
    row: dict[str, Any],
) -> int:

    status = row.get(
        "evidence_status"
    )

    return {
        "exact_event_observed": 4,
        "source_available_activity_unverified": 3,
        "source_available_event_requirement_unverified": 2,
        "required_source_not_observed": 0,
    }.get(
        status,
        1,
    )


def match_requirements(
    resolved_component: dict[str, Any],
    log_source: str,
    channel: str | None,
) -> list[dict[str, Any]]:

    wanted_source = normalize_source(
        log_source
    )

    wanted_event_ids = set(
        extract_event_ids(channel)
    )

    matches = []

    for req in resolved_component.get(
        "requirement_results",
        [],
    ):

        req_source = normalize_source(
            req.get("log_source_name")
        )

        if (
            not wanted_source
            or req_source != wanted_source
        ):
            continue

        if wanted_event_ids:

            req_event_ids = {
                str(value)
                for value in req.get(
                    "exact_event_ids",
                    [],
                )
            }

            req_event_ids.update(
                extract_event_ids(
                    req.get("channel")
                )
            )

            if not (
                wanted_event_ids
                & req_event_ids
            ):
                continue

        matches.append(req)

    matches.sort(
        key=lambda item: (
            -requirement_rank(item),
            str(
                item.get(
                    "requirement_id",
                    "",
                )
            ),
        )
    )

    return matches


def fingerprint(
    payload: dict[str, Any],
) -> str:

    raw = json.dumps(
        payload,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")

    return (
        "sha256:"
        + hashlib.sha256(raw).hexdigest()
    )


def main() -> int:

    eligibility_rows = read_jsonl(
        ELIGIBILITY_PATH
    )

    master_rows = read_jsonl(
        MASTER_PATH
    )

    hypothesis_rows = read_jsonl(
        HYPOTHESIS_PATH
    )

    analytic_rows = read_jsonl(
        ANALYTICS_PATH
    )

    strategy_rows = read_jsonl(
        STRATEGIES_PATH
    )

    component_rows = read_jsonl(
        COMPONENTS_PATH
    )

    resolved_rows = read_jsonl(
        RESOLVED_PATH
    )

    master = index_unique(
        master_rows,
        "technique_id",
        "master",
    )

    hypotheses = index_unique(
        hypothesis_rows,
        "technique_id",
        "hypotheses",
    )

    analytics = index_unique(
        analytic_rows,
        "external_id",
        "analytics",
    )

    strategies = index_unique(
        strategy_rows,
        "external_id",
        "strategies",
    )

    resolved = index_unique(
        resolved_rows,
        "component_id",
        "resolved",
    )


    stix_to_component = {}

    for row in component_rows:

        stix_id = row.get(
            "stix_id"
        )

        component_id = (
            component_external_id(row)
        )

        if (
            stix_id
            and component_id
        ):
            stix_to_component[
                stix_id
            ] = component_id


    eligible_rows = [
        row
        for row in eligibility_rows

        if (
            row.get(
                "processing_status"
            )
            == "SUCCESS"

            and row.get(
                "eligibility_decision"
            )
            == "ELIGIBLE_FOR_DETECTION"
        )
    ]


    outputs = []
    indexes = []
    errors = []

    platform_analytic_count = 0
    grounded_reference_count = 0
    techniques_with_strategy = 0
    techniques_with_analytic = 0
    techniques_with_grounded_reference = 0


    for eligibility in sorted(
        eligible_rows,
        key=lambda row: (
            row.get(
                "runtime_hunt_rank"
            )
            if row.get(
                "runtime_hunt_rank"
            )
            is not None
            else 10**9,
            row["technique_id"],
        ),
    ):

        tid = eligibility[
            "technique_id"
        ]

        try:

            context = master[tid]
            hypothesis = hypotheses[tid]

            technique = context[
                "technique"
            ]

            environment = context[
                "environment"
            ]

            observed_platforms = set(
                environment.get(
                    "observed_platforms",
                    [],
                )
            )

            technique_matches = set(
                environment.get(
                    "technique_observed_platform_matches",
                    [],
                )
            )

            active_platforms = (
                technique_matches
                or observed_platforms
            )

            strategy_ids = list(
                technique.get(
                    "detection_strategy_ids",
                    [],
                )
            )

            analytic_ids = list(
                technique.get(
                    "analytic_ids",
                    [],
                )
            )

            selected_strategies = []

            linked_analytic_stix = set()

            for strategy_id in strategy_ids:

                strategy = strategies.get(
                    strategy_id
                )

                if not strategy:
                    continue

                if (
                    strategy.get(
                        "revoked"
                    )
                    or strategy.get(
                        "deprecated"
                    )
                ):
                    continue

                selected_strategies.append(
                    strategy
                )

                raw = strategy.get(
                    "raw",
                    {},
                )

                if isinstance(raw, dict):
                    linked_analytic_stix.update(
                        raw.get(
                            "x_mitre_analytic_refs",
                            [],
                        )
                    )

            if selected_strategies:
                techniques_with_strategy += 1


            selected_analytics = []

            for analytic_id in analytic_ids:

                analytic = analytics.get(
                    analytic_id
                )

                if not analytic:
                    continue

                if (
                    analytic.get("revoked")
                    or analytic.get(
                        "deprecated"
                    )
                ):
                    continue

                if (
                    linked_analytic_stix
                    and analytic.get(
                        "stix_id"
                    )
                    not in linked_analytic_stix
                ):
                    continue

                platforms = set(
                    analytic.get(
                        "platforms",
                        [],
                    )
                )

                platform_relevant = bool(
                    not platforms
                    or (
                        platforms
                        & active_platforms
                    )
                )

                selected_analytics.append(
                    {
                        "analytic":
                            analytic,

                        "platform_relevant":
                            platform_relevant,
                    }
                )

            if selected_analytics:
                techniques_with_analytic += 1


            required_components = set(
                eligibility.get(
                    "required_data_components",
                    [],
                )
            )

            analytic_contexts = []

            technique_grounded = False


            for selected in selected_analytics:

                analytic = selected[
                    "analytic"
                ]

                platform_relevant = selected[
                    "platform_relevant"
                ]

                if platform_relevant:
                    platform_analytic_count += 1

                raw = analytic.get(
                    "raw",
                    {},
                )

                log_refs = []

                if isinstance(raw, dict):
                    log_refs = raw.get(
                        "x_mitre_log_source_references",
                        [],
                    ) or []

                resolved_refs = []


                for log_ref in log_refs:

                    if not isinstance(
                        log_ref,
                        dict,
                    ):
                        continue

                    component_stix = (
                        log_ref.get(
                            "x_mitre_data_component_ref"
                        )
                    )

                    component_id = (
                        stix_to_component.get(
                            component_stix
                        )
                    )

                    log_source = (
                        log_ref.get("name")
                    )

                    channel = (
                        log_ref.get(
                            "channel"
                        )
                    )

                    ref_record = {
                        "component_stix_id":
                            component_stix,

                        "component_id":
                            component_id,

                        "log_source_name":
                            log_source,

                        "channel":
                            channel,

                        "platform_relevant":
                            platform_relevant,

                        "required_by_eligible_hypothesis":
                            (
                                component_id
                                in required_components
                            )
                            if component_id
                            else False,

                        "environment_evidence_status":
                            "UNRESOLVED",

                        "matched_requirement_id":
                            None,

                        "matched_requirement_type":
                            None,

                        "matched_evidence_status":
                            None,

                        "exact_event_ids":
                            [],

                        "evidence_ids":
                            [],
                    }


                    if (
                        platform_relevant
                        and component_id
                        and component_id
                        in required_components
                        and component_id
                        in resolved
                    ):

                        matches = match_requirements(
                            resolved[
                                component_id
                            ],
                            log_source,
                            channel,
                        )

                        usable = [
                            row
                            for row in matches
                            if row.get(
                                "evidence_status"
                            )
                            in {
                                "exact_event_observed",
                                "source_available_activity_unverified",
                                "source_available_event_requirement_unverified",
                            }
                        ]

                        if usable:

                            best = usable[0]

                            evidence_ids = list(
                                best.get(
                                    "exact_event_evidence_ids",
                                    [],
                                )
                            )

                            source_match = (
                                best.get(
                                    "source_match"
                                )
                            )

                            if (
                                not evidence_ids
                                and isinstance(
                                    source_match,
                                    dict,
                                )
                                and source_match.get(
                                    "reference"
                                )
                            ):
                                evidence_ids = [
                                    source_match[
                                        "reference"
                                    ]
                                ]

                            ref_record[
                                "environment_evidence_status"
                            ] = "GROUNDED"

                            ref_record[
                                "matched_requirement_id"
                            ] = best.get(
                                "requirement_id"
                            )

                            ref_record[
                                "matched_requirement_type"
                            ] = best.get(
                                "requirement_type"
                            )

                            ref_record[
                                "matched_evidence_status"
                            ] = best.get(
                                "evidence_status"
                            )

                            ref_record[
                                "exact_event_ids"
                            ] = list(
                                best.get(
                                    "exact_event_ids",
                                    [],
                                )
                            )

                            ref_record[
                                "evidence_ids"
                            ] = evidence_ids

                            grounded_reference_count += 1
                            technique_grounded = True


                    resolved_refs.append(
                        ref_record
                    )


                analytic_contexts.append(
                    {
                        "analytic_id":
                            analytic.get(
                                "external_id"
                            ),

                        "analytic_name":
                            analytic.get(
                                "name"
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

                        "platform_relevant":
                            platform_relevant,

                        "log_source_references":
                            resolved_refs,
                    }
                )


            if technique_grounded:
                techniques_with_grounded_reference += 1


            hypothesis_output = hypothesis.get(
                "model_output",
                {},
            )


            rag = {
                "rag_version": "1.0",

                "generated_at_utc":
                    datetime.now(
                        timezone.utc
                    ).isoformat(),

                "technique_id":
                    tid,

                "technique_name":
                    eligibility[
                        "technique_name"
                    ],

                "environment_id":
                    environment[
                        "environment_id"
                    ],

                "runtime_hunt_rank":
                    eligibility.get(
                        "runtime_hunt_rank"
                    ),

                "eligibility": {
                    "decision":
                        eligibility[
                            "eligibility_decision"
                        ],

                    "gate_version":
                        eligibility[
                            "gate_version"
                        ],

                    "input_fingerprint":
                        eligibility[
                            "input_fingerprint"
                        ],
                },

                "hypothesis": {
                    "text":
                        hypothesis_output.get(
                            "hypothesis"
                        ),

                    "investigation_focus":
                        hypothesis_output.get(
                            "investigation_focus",
                            [],
                        ),

                    "known_collection_limitations":
                        hypothesis_output.get(
                            "known_collection_limitations",
                            [],
                        ),

                    "confidence":
                        hypothesis_output.get(
                            "confidence"
                        ),
                },

                "attack_context": {
                    "attack_version":
                        technique.get(
                            "attack_version"
                        ),

                    "technique_description":
                        technique.get(
                            "description"
                        ),

                    "platforms":
                        technique.get(
                            "platforms",
                            [],
                        ),

                    "current_environment_platforms":
                        sorted(
                            active_platforms
                        ),

                    "data_components":
                        technique.get(
                            "data_components",
                            [],
                        ),

                    "detection_strategy_ids":
                        strategy_ids,

                    "analytic_ids":
                        analytic_ids,
                },

                "retrieved_detection_strategies": [
                    {
                        "strategy_id":
                            row.get(
                                "external_id"
                            ),

                        "name":
                            row.get(
                                "name"
                            ),

                        "description":
                            row.get(
                                "description"
                            ),
                    }
                    for row
                    in selected_strategies
                ],

                "retrieved_analytics":
                    analytic_contexts,

                "eligible_required_components":
                    eligibility.get(
                        "component_assessments",
                        [],
                    ),

                "grounding_policy": {
                    "component_evidence_is_not_technique_specific_path":
                        True,

                    "telemetry_evidence_proves_occurrence":
                        False,

                    "source_availability_proves_activity":
                        False,

                    "unresolved_fields_must_not_be_invented":
                        True,

                    "sigma_generation_allowed":
                        False,
                },
            }


            rag[
                "rag_input_fingerprint"
            ] = fingerprint(
                {
                    "technique_id":
                        tid,

                    "eligibility_fingerprint":
                        eligibility[
                            "input_fingerprint"
                        ],

                    "strategies":
                        [
                            row.get(
                                "external_id"
                            )
                            for row
                            in selected_strategies
                        ],

                    "analytics":
                        [
                            row[
                                "analytic"
                            ].get(
                                "external_id"
                            )
                            for row
                            in selected_analytics
                        ],

                    "environment_id":
                        environment[
                            "environment_id"
                        ],
                }
            )


            outputs.append(rag)

            indexes.append(
                {
                    "rag_version":
                        "1.0",

                    "technique_id":
                        tid,

                    "technique_name":
                        eligibility[
                            "technique_name"
                        ],

                    "environment_id":
                        environment[
                            "environment_id"
                        ],

                    "runtime_hunt_rank":
                        eligibility.get(
                            "runtime_hunt_rank"
                        ),

                    "strategy_count":
                        len(
                            selected_strategies
                        ),

                    "analytic_count":
                        len(
                            selected_analytics
                        ),

                    "platform_relevant_analytic_count":
                        sum(
                            1
                            for row
                            in selected_analytics
                            if row[
                                "platform_relevant"
                            ]
                        ),

                    "has_grounded_analytic_reference":
                        technique_grounded,

                    "rag_input_fingerprint":
                        rag[
                            "rag_input_fingerprint"
                        ],
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
        RAG_OUTPUT,
        outputs,
    )

    write_jsonl(
        INDEX_OUTPUT,
        indexes,
    )

    write_jsonl(
        ERROR_OUTPUT,
        errors,
    )


    summary = {
        "rag_version": "1.0",

        "eligible_inputs":
            len(eligible_rows),

        "successful_contexts":
            len(outputs),

        "processing_errors":
            len(errors),

        "techniques_with_detection_strategy":
            techniques_with_strategy,

        "techniques_with_analytics":
            techniques_with_analytic,

        "platform_relevant_analytics":
            platform_analytic_count,

        "grounded_analytic_logsource_references":
            grounded_reference_count,

        "techniques_with_grounded_analytic_reference":
            techniques_with_grounded_reference,

        "outputs": {
            "rag_contexts":
                str(RAG_OUTPUT),

            "index":
                str(INDEX_OUTPUT),

            "errors":
                str(ERROR_OUTPUT),
        },
    }

    write_json(
        SUMMARY_OUTPUT,
        summary,
    )


    print(
        "===== DETECTION PLAN RAG CONTEXT v1.0 ====="
    )

    print()
    print(
        "Eligible inputs                  :",
        len(eligible_rows),
    )

    print(
        "Successful contexts             :",
        len(outputs),
    )

    print(
        "Processing errors               :",
        len(errors),
    )

    print()
    print(
        "Techniques with DET strategy    :",
        techniques_with_strategy,
    )

    print(
        "Techniques with analytics       :",
        techniques_with_analytic,
    )

    print(
        "Platform-relevant analytics     :",
        platform_analytic_count,
    )

    print(
        "Grounded analytic logsource refs:",
        grounded_reference_count,
    )

    print(
        "Techniques with grounded refs   :",
        techniques_with_grounded_reference,
    )

    print()
    print(
        "RAG contexts:",
        RAG_OUTPUT,
    )

    print(
        "RAG index   :",
        INDEX_OUTPUT,
    )

    print(
        "Error queue :",
        ERROR_OUTPUT,
    )

    print(
        "Summary     :",
        SUMMARY_OUTPUT,
    )

    if errors:

        print()
        print(
            "Detection Plan RAG Context v1.0: "
            "FAIL"
        )

        return 2

    print()
    print(
        "Detection Plan RAG Context v1.0: "
        "PASS"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
