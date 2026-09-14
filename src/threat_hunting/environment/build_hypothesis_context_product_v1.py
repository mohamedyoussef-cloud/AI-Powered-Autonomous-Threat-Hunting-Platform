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
    / "adaptive_product_prioritization_v1.jsonl"
)

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

ENVIRONMENT_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "environment"
    / "environment_profile_product_v1.json"
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

JSONL_OUTPUT = (
    OUTPUT_DIR
    / "hypothesis_context_product_v1.jsonl"
)

TOP20_OUTPUT = (
    OUTPUT_DIR
    / "hypothesis_context_product_v1_top20.jsonl"
)

REPORT_OUTPUT = (
    REPORT_DIR
    / "hypothesis_context_product_v1_summary.json"
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


def write_jsonl(path, rows):
    with path.open(
        "w",
        encoding="utf-8",
        newline="\n"
    ) as f:
        for row in rows:
            f.write(
                json.dumps(
                    row,
                    ensure_ascii=False
                )
                + "\n"
            )


def main():
    required = [
        ATTACK_FILE,
        PRIORITY_FILE,
        READINESS_FILE,
        SIGMA_FILE,
        ENVIRONMENT_FILE,
    ]

    for path in required:
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

    attack_rows = read_jsonl(
        ATTACK_FILE
    )

    priority_rows = read_jsonl(
        PRIORITY_FILE
    )

    readiness_rows = read_jsonl(
        READINESS_FILE
    )

    sigma_rows = read_jsonl(
        SIGMA_FILE
    )

    environment = json.loads(
        ENVIRONMENT_FILE.read_text(
            encoding="utf-8"
        )
    )

    attack_map = {
        row["technique_id"]: row
        for row in attack_rows
    }

    readiness_map = {
        row["technique_id"]: row
        for row in readiness_rows
    }

    sigma_map = {
        row["technique_id"]: row
        for row in sigma_rows
    }

    validation_errors = []

    if len(attack_rows) != 697:
        validation_errors.append(
            f"Expected 697 ATT&CK techniques, "
            f"found {len(attack_rows)}"
        )

    if len(priority_rows) != 697:
        validation_errors.append(
            f"Expected 697 priority rows, "
            f"found {len(priority_rows)}"
        )

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

    ranked = [
        row
        for row in priority_rows
        if (
            row.get("priority_rank")
            is not None
            and row.get(
                "applicability_status"
            )
            == "observed_environment_applicable"
        )
    ]

    ranked.sort(
        key=lambda row: int(
            row["priority_rank"]
        )
    )

    if len(ranked) != 571:
        validation_errors.append(
            f"Expected 571 ranked techniques, "
            f"found {len(ranked)}"
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

    for priority in ranked:
        technique_id = priority[
            "technique_id"
        ]

        attack = attack_map.get(
            technique_id
        )

        readiness = readiness_map.get(
            technique_id
        )

        sigma = sigma_map.get(
            technique_id
        )

        if (
            attack is None
            or readiness is None
            or sigma is None
        ):
            validation_errors.append(
                f"{technique_id}: missing "
                f"joined master record"
            )
            continue

        technique_platforms = sorted(
            attack.get(
                "platforms"
            )
            or []
        )

        matched_platforms = sorted(
            readiness.get(
                "observed_platform_matches"
            )
            or []
        )

        data_components = sorted(
            attack.get(
                "data_components"
            )
            or []
        )

        tactics = sorted(
            attack.get(
                "tactics"
            )
            or []
        )

        telemetry_status = (
            readiness.get(
                "telemetry_evidence_status"
            )
        )

        telemetry_score = (
            readiness.get(
                "telemetry_readiness_score"
            )
        )

        telemetry_band = (
            readiness.get(
                "telemetry_readiness_band"
            )
        )

        sigma_rule_count = int(
            sigma.get(
                "sigma_rule_count",
                0
            )
        )

        sigma_gap_score = float(
            sigma.get(
                "sigma_detection_knowledge_gap_score",
                0.0
            )
        )

        sigma_gap_class = sigma.get(
            "sigma_detection_knowledge_gap_class"
        )

        context = {
            "context_version": "1.0",

            "context_scope": (
                "product_hunt_hypothesis"
            ),

            "technique": {
                "technique_id": technique_id,

                "technique_name": (
                    attack.get("name")
                ),

                "description": (
                    attack.get(
                        "description"
                    )
                ),

                "is_subtechnique": bool(
                    attack.get(
                        "is_subtechnique",
                        False
                    )
                ),

                "parent_technique_id": (
                    attack.get(
                        "parent_technique_id"
                    )
                ),

                "tactics": tactics,

                "platforms": (
                    technique_platforms
                ),

                "data_components": (
                    data_components
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
            },

            "environment": {
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
                    matched_platforms
                ),

                "asset_inventory_available": False,

                "asset_criticality_available": False,

                "incident_history_available": False,

                "client_detection_coverage_available": False,
            },

            "telemetry": {
                "evidence_status": (
                    telemetry_status
                ),

                "readiness_score": (
                    telemetry_score
                ),

                "readiness_band": (
                    telemetry_band
                ),

                "component_evidence_coverage_pct": (
                    readiness.get(
                        "component_evidence_coverage_pct"
                    )
                ),

                "exact_event_component_coverage_pct": (
                    readiness.get(
                        "exact_event_component_coverage_pct"
                    )
                ),

                "data_components_referenced": (
                    readiness.get(
                        "data_components_referenced"
                    )
                ),

                "data_components_with_any_evidence": (
                    readiness.get(
                        "data_components_with_any_evidence"
                    )
                ),

                "data_components_with_exact_event_evidence": (
                    readiness.get(
                        "data_components_with_exact_event_evidence"
                    )
                ),

                "data_components_source_only": (
                    readiness.get(
                        "data_components_source_only"
                    )
                ),

                "evidence_sources": (
                    readiness.get(
                        "evidence_sources"
                    )
                ),

                "interpretation": (
                    "Telemetry evidence indicates "
                    "observability/support only. "
                    "It does not prove technique "
                    "occurrence."
                ),
            },

            "sigma_knowledge": {
                "mapped_rule_count": (
                    sigma_rule_count
                ),

                "knowledge_coverage_score": (
                    sigma.get(
                        "sigma_knowledge_coverage_score"
                    )
                ),

                "knowledge_gap_score": (
                    sigma_gap_score
                ),

                "knowledge_gap_class": (
                    sigma_gap_class
                ),

                "gap_source": (
                    "prepared_sigma_corpus_proxy"
                ),

                "is_client_detection_coverage": (
                    False
                ),

                "interpretation": (
                    "Mapped Sigma rule count and "
                    "knowledge gap describe only the "
                    "current prepared Sigma corpus. "
                    "They do not represent deployed "
                    "client detection coverage."
                ),
            },

            "priority": {
                "rank": int(
                    priority[
                        "priority_rank"
                    ]
                ),

                "score": float(
                    priority[
                        "priority_score"
                    ]
                ),

                "available_factor_count": (
                    priority[
                        "available_factor_count"
                    ]
                ),

                "effective_weights": (
                    priority[
                        "effective_weights"
                    ]
                ),

                "detection_gap_source": (
                    priority[
                        "detection_gap_source"
                    ]
                ),
            },

            "grounding_constraints": {
                "technique_occurrence_observed": (
                    False
                ),

                "must_not_claim_occurrence": True,

                "must_not_invent_missing_telemetry": (
                    True
                ),

                "required_telemetry_must_be_grounded_in_attack_data_components": (
                    True
                ),

                "must_preserve_unknown_asset_context": (
                    True
                ),

                "must_preserve_unknown_incident_history": (
                    True
                ),

                "must_preserve_unknown_client_detection_coverage": (
                    True
                ),

                "sigma_zero_rule_semantics": (
                    "No mapped Sigma rules in the "
                    "current prepared Sigma corpus; "
                    "do not claim that no Sigma rules "
                    "exist globally."
                ),

                "detection_generation": (
                    "Do not assume every hunt "
                    "hypothesis is suitable for Sigma. "
                    "A separate Detection Eligibility "
                    "Gate decides whether Sigma "
                    "generation is appropriate."
                ),
            },

            "llm_task": {
                "task": (
                    "generate_grounded_hunt_hypothesis"
                ),

                "objective": (
                    "Generate an explainable threat "
                    "hunting hypothesis grounded only "
                    "in the supplied ATT&CK, environment, "
                    "telemetry, priority, and Sigma "
                    "knowledge context."
                ),

                "required_behavior": [
                    (
                        "Explain why the technique is "
                        "worth hunting in the current "
                        "environment."
                    ),
                    (
                        "Use only supported telemetry "
                        "and ATT&CK data-component "
                        "information."
                    ),
                    (
                        "Do not claim that the technique "
                        "has occurred."
                    ),
                    (
                        "Do not fabricate asset "
                        "criticality, incident history, "
                        "or deployed detection coverage."
                    ),
                    (
                        "State important limitations "
                        "and unavailable context."
                    ),
                    (
                        "Separate hunt reasoning from "
                        "detection-rule generation."
                    ),
                ],
            },
        }

        contexts.append(
            context
        )

    if len(contexts) != 571:
        validation_errors.append(
            f"Expected 571 contexts, "
            f"found {len(contexts)}"
        )

    ids = [
        row["technique"][
            "technique_id"
        ]
        for row in contexts
    ]

    if len(set(ids)) != len(ids):
        validation_errors.append(
            "Duplicate technique contexts detected"
        )

    ranks = [
        row["priority"]["rank"]
        for row in contexts
    ]

    if ranks != list(
        range(
            1,
            len(contexts) + 1
        )
    ):
        validation_errors.append(
            "Priority ranks are not contiguous "
            "from 1 through 571"
        )

    occurrence_violations = [
        row["technique"][
            "technique_id"
        ]
        for row in contexts
        if row[
            "grounding_constraints"
        ][
            "technique_occurrence_observed"
        ]
        is not False
    ]

    if occurrence_violations:
        validation_errors.append(
            "Technique occurrence was "
            "incorrectly asserted"
        )

    sigma_semantic_violations = [
        row["technique"][
            "technique_id"
        ]
        for row in contexts
        if row[
            "sigma_knowledge"
        ][
            "is_client_detection_coverage"
        ]
        is not False
    ]

    if sigma_semantic_violations:
        validation_errors.append(
            "Sigma knowledge proxy was "
            "incorrectly treated as client "
            "detection coverage"
        )

    invalid_platform_matches = []

    observed_set = set(
        observed_platforms
    )

    for row in contexts:
        matches = set(
            row["environment"][
                "technique_observed_platform_matches"
            ]
        )

        technique_platform_set = set(
            row["technique"][
                "platforms"
            ]
        )

        if not matches:
            invalid_platform_matches.append(
                row["technique"][
                    "technique_id"
                ]
            )
            continue

        if not matches.issubset(
            observed_set
        ):
            invalid_platform_matches.append(
                row["technique"][
                    "technique_id"
                ]
            )
            continue

        if not matches.issubset(
            technique_platform_set
        ):
            invalid_platform_matches.append(
                row["technique"][
                    "technique_id"
                ]
            )

    if invalid_platform_matches:
        validation_errors.append(
            "One or more ranked techniques "
            "lack valid observed platform matches"
        )

    band_counter = Counter(
        row["telemetry"][
            "readiness_band"
        ]
        for row in contexts
    )

    platform_counter = Counter()

    for row in contexts:
        for platform in row[
            "environment"
        ][
            "technique_observed_platform_matches"
        ]:
            platform_counter[
                platform
            ] += 1

    validation_status = (
        "PASS"
        if not validation_errors
        else "FAIL"
    )

    write_jsonl(
        JSONL_OUTPUT,
        contexts
    )

    write_jsonl(
        TOP20_OUTPUT,
        contexts[:20]
    )

    report = {
        "component": (
            "hypothesis_context_product"
        ),

        "version": "1.0",

        "generated_at_utc": (
            datetime.now(
                timezone.utc
            ).isoformat()
        ),

        "master_attack_techniques": (
            len(attack_rows)
        ),

        "ranked_input_techniques": (
            len(ranked)
        ),

        "contexts_generated": (
            len(contexts)
        ),

        "full_product_context_count": (
            len(contexts)
        ),

        "top20_preview_count": min(
            20,
            len(contexts)
        ),

        "observed_environment_platforms": (
            observed_platforms
        ),

        "unknown_environment_platforms": (
            unknown_platforms
        ),

        "techniques_by_observed_platform_match": (
            dict(
                sorted(
                    platform_counter.items()
                )
            )
        ),

        "telemetry_readiness_bands": dict(
            sorted(
                band_counter.items()
            )
        ),

        "first_ranked_technique": (
            contexts[0]["technique"][
                "technique_id"
            ]
            if contexts
            else None
        ),

        "last_ranked_technique": (
            contexts[-1]["technique"][
                "technique_id"
            ]
            if contexts
            else None
        ),

        "grounding_policy": {
            "occurrence_claim_allowed": False,
            "invent_missing_telemetry_allowed": False,
            "invent_asset_context_allowed": False,
            "invent_incident_history_allowed": False,
            "sigma_proxy_is_client_coverage": False,
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
            ensure_ascii=False
        ),
        encoding="utf-8"
    )

    print(
        "Hypothesis Context Product v1.0"
    )

    print(
        "-------------------------------"
    )

    print(
        f"Master ATT&CK techniques : "
        f"{len(attack_rows)}"
    )

    print(
        f"Ranked input techniques  : "
        f"{len(ranked)}"
    )

    print(
        f"Contexts generated       : "
        f"{len(contexts)}"
    )

    print()

    print(
        "Observed environment platforms:"
    )

    for platform in observed_platforms:
        print(
            f"  {platform}"
        )

    print()

    print(
        "Context telemetry bands:"
    )

    for key, value in sorted(
        band_counter.items()
    ):
        print(
            f"  {str(key):<15} {value}"
        )

    print()

    print(
        "Technique platform matches:"
    )

    for key, value in sorted(
        platform_counter.items()
    ):
        print(
            f"  {key:<18} {value}"
        )

    print()

    if contexts:
        print(
            f"Rank 1 technique         : "
            f"{contexts[0]['technique']['technique_id']} "
            f"{contexts[0]['technique']['technique_name']}"
        )

        print(
            f"Rank 571 technique       : "
            f"{contexts[-1]['technique']['technique_id']} "
            f"{contexts[-1]['technique']['technique_name']}"
        )

    print()

    print(
        "Occurrence claims        : DISALLOWED"
    )

    print(
        "Sigma proxy client cover : FALSE"
    )

    print(
        "Detection eligibility    : SEPARATE GATE"
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
        f"Full JSONL : {JSONL_OUTPUT}"
    )

    print(
        f"Top20 QA   : {TOP20_OUTPUT}"
    )

    print(
        f"Report     : {REPORT_OUTPUT}"
    )


if __name__ == "__main__":
    main()