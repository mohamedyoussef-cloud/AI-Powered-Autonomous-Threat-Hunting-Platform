from __future__ import annotations

import hashlib
import json
from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[4]

SCHEMA_PATH = (
    ROOT
    / "schemas"
    / "phase3"
    / "detection_plan"
    / "detection_plan_v1_1.schema.json"
)

BUNDLE = (
    ROOT
    / "gpu"
    / "detection_plan_v1"
    / "return"
    / "extracted_v1_3"
    / "detection_plan_v1"
    / "export_v1_3"
)

DISPATCH_PATH = (
    BUNDLE
    / "detection_plan_baseline_dispatch_v1.jsonl"
)

SEMANTIC_PATH = (
    BUNDLE
    / "detection_plan_semantic_outputs_v1_3.jsonl"
)

SEMANTIC_ERRORS_PATH = (
    BUNDLE
    / "detection_plan_semantic_errors_v1_3.jsonl"
)

SEMANTIC_SUMMARY_PATH = (
    BUNDLE
    / "detection_plan_semantic_summary_v1_3.json"
)

SEMANTIC_AUDIT_PATH = (
    BUNDLE
    / "detection_plan_semantic_full_audit_v1_3.json"
)

ELIGIBILITY_PATH = (
    ROOT
    / "data"
    / "processed"
    / "phase3"
    / "detection_eligibility"
    / "detection_eligibility_outputs_v1.jsonl"
)

OUTPUT_DIR = (
    ROOT
    / "data"
    / "processed"
    / "phase3"
    / "detection_plan"
)

PLANS_PATH = (
    OUTPUT_DIR
    / "detection_plans_v1_1.jsonl"
)

INDEX_PATH = (
    OUTPUT_DIR
    / "detection_plan_results_index_v1_1.jsonl"
)

ERRORS_PATH = (
    OUTPUT_DIR
    / "detection_plan_errors_v1_1.jsonl"
)

SUMMARY_PATH = (
    OUTPUT_DIR
    / "detection_plan_summary_v1_1.json"
)

AUDIT_PATH = (
    OUTPUT_DIR
    / "detection_plan_final_audit_v1_1.json"
)


# ============================================================
# IO helpers
# ============================================================

def read_jsonl(path: Path) -> list[dict]:
    rows = []

    for line_no, line in enumerate(
        path.read_text(
            encoding="utf-8-sig"
        ).splitlines(),
        start=1,
    ):
        line = line.strip()

        if not line:
            continue

        value = json.loads(line)

        if not isinstance(value, dict):
            raise RuntimeError(
                f"Non-object JSONL record: "
                f"{path}:{line_no}"
            )

        rows.append(value)

    return rows


def atomic_text(
    path: Path,
    text: str,
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temp = path.with_name(
        path.name + ".tmp"
    )

    temp.write_text(
        text,
        encoding="utf-8",
    )

    temp.replace(path)


def write_jsonl(
    path: Path,
    rows: list[dict],
) -> None:
    text = "".join(
        json.dumps(
            row,
            ensure_ascii=False,
            sort_keys=True,
        )
        + "\n"
        for row in rows
    )

    atomic_text(
        path,
        text,
    )


def write_json(
    path: Path,
    value: dict,
) -> None:
    atomic_text(
        path,
        json.dumps(
            value,
            indent=2,
            ensure_ascii=False,
            sort_keys=True,
        )
        + "\n",
    )


def sha256_file(
    path: Path,
) -> str:
    h = hashlib.sha256()

    with path.open("rb") as handle:

        for chunk in iter(
            lambda: handle.read(
                1024 * 1024
            ),
            b"",
        ):
            h.update(chunk)

    return (
        "sha256:"
        + h.hexdigest()
    )


def unique_map(
    rows: list[dict],
    label: str,
) -> tuple[dict[str, dict], list[str]]:
    result = {}
    duplicates = []

    for row in rows:

        tid = row.get(
            "technique_id"
        )

        if not tid:
            raise RuntimeError(
                f"{label}: missing technique_id"
            )

        if tid in result:
            duplicates.append(tid)
        else:
            result[tid] = row

    return (
        result,
        duplicates,
    )


# ============================================================
# Canonical transformations
# ============================================================

COMPONENT_KEYS = [
    "component_id",
    "component_name",
    "environment_grounded",
    "requirement_unspecified",
    "best_evidence_status",
]

PATH_KEYS = [
    "path_id",
    "component_ids",
    "grounding_status",
    "requirement_ids",
    "log_sources",
    "event_ids",
    "canonical_category",
    "canonical_action",
    "field_bindings",
    "evidence_ids",
]


def confidence_level(
    hypothesis: dict,
):
    value = hypothesis.get(
        "confidence"
    )

    if isinstance(value, dict):
        return value.get(
            "level"
        )

    if value is None:
        return None

    return str(value)


def canonical_components(
    resolution: dict,
) -> list[dict]:
    result = []

    for component in resolution.get(
        "required_components",
        [],
    ):
        result.append(
            {
                key:
                    deepcopy(
                        component[key]
                    )
                for key in COMPONENT_KEYS
            }
        )

    return result


def canonical_paths(
    resolution: dict,
) -> list[dict]:
    result = []

    all_paths = (
        resolution.get(
            "grounded_paths",
            [],
        )
        +
        resolution.get(
            "unresolved_paths",
            [],
        )
    )

    for path in all_paths:

        result.append(
            {
                key:
                    deepcopy(
                        path[key]
                    )
                for key in PATH_KEYS
            }
        )

    return result


def authoritative_lineage(
    eligibility_record: dict,
) -> dict:
    versions = eligibility_record.get(
        "source_versions",
        {}
    )

    required = [
        "master_context_version",
        "hypothesis_engine_version",
        "environment_profile_version",
        "telemetry_resolver_version",
    ]

    missing = [
        key
        for key in required
        if not versions.get(key)
    ]

    if missing:
        raise RuntimeError(
            "Missing authoritative lineage "
            f"versions: {missing}"
        )

    gate_version = (
        eligibility_record.get(
            "gate_version"
        )
    )

    if not gate_version:
        raise RuntimeError(
            "Missing eligibility gate_version"
        )

    return {
        "master_context_version":
            versions[
                "master_context_version"
            ],

        "hypothesis_engine_version":
            versions[
                "hypothesis_engine_version"
            ],

        "eligibility_gate_version":
            gate_version,

        "environment_profile_version":
            versions[
                "environment_profile_version"
            ],

        "telemetry_resolver_version":
            versions[
                "telemetry_resolver_version"
            ],
    }


def build_plan(
    dispatch: dict,
    semantic_row: dict,
    eligibility_source: dict,
    generated_at_utc: str,
) -> dict:

    tid = dispatch[
        "technique_id"
    ]

    resolution = dispatch[
        "deterministic_resolution"
    ]

    semantic = semantic_row[
        "model_output"
    ]

    dispatch_eligibility = dispatch[
        "eligibility"
    ]


    # --------------------------------------------------------
    # Authoritative cross-source consistency
    # --------------------------------------------------------

    if (
        eligibility_source.get(
            "eligibility_decision"
        )
        != "ELIGIBLE_FOR_DETECTION"
    ):
        raise RuntimeError(
            "Authoritative eligibility decision "
            "is not ELIGIBLE_FOR_DETECTION"
        )


    if (
        dispatch_eligibility.get(
            "decision"
        )
        != "ELIGIBLE_FOR_DETECTION"
    ):
        raise RuntimeError(
            "Dispatch eligibility decision drift"
        )


    if (
        dispatch_eligibility.get(
            "gate_version"
        )
        != eligibility_source.get(
            "gate_version"
        )
    ):
        raise RuntimeError(
            "Eligibility gate version mismatch"
        )


    if (
        dispatch_eligibility.get(
            "input_fingerprint"
        )
        != eligibility_source.get(
            "input_fingerprint"
        )
    ):
        raise RuntimeError(
            "Eligibility input fingerprint mismatch"
        )


    if (
        semantic.get(
            "technique_id"
        )
        != tid
    ):
        raise RuntimeError(
            "Semantic technique ID mismatch"
        )


    if (
        semantic_row.get(
            "plan_id"
        )
        != dispatch[
            "plan_identity"
        ][
            "plan_id"
        ]
    ):
        raise RuntimeError(
            "Semantic plan ID mismatch"
        )


    if (
        semantic_row.get(
            "plan_input_fingerprint"
        )
        != dispatch[
            "plan_identity"
        ][
            "plan_input_fingerprint"
        ]
    ):
        raise RuntimeError(
            "Semantic plan fingerprint mismatch"
        )


    source_attack_version = (
        eligibility_source.get(
            "source_versions",
            {}
        ).get(
            "attack_version"
        )
    )

    dispatch_attack_version = (
        dispatch[
            "attack_context"
        ].get(
            "attack_version"
        )
    )

    if (
        source_attack_version
        and dispatch_attack_version
        and source_attack_version
        != dispatch_attack_version
    ):
        raise RuntimeError(
            "ATT&CK version mismatch"
        )


    # --------------------------------------------------------
    # Final Contract v1.1 object
    # --------------------------------------------------------

    return {
        "contract_version":
            "1.1",

        "generated_at_utc":
            generated_at_utc,

        "plan_id":
            dispatch[
                "plan_identity"
            ][
                "plan_id"
            ],

        "environment_id":
            dispatch[
                "environment_id"
            ],

        "artifact_revision":
            dispatch[
                "plan_identity"
            ][
                "artifact_revision"
            ],

        "plan_input_fingerprint":
            dispatch[
                "plan_identity"
            ][
                "plan_input_fingerprint"
            ],

        "execution_context":
            deepcopy(
                dispatch[
                    "execution_context"
                ]
            ),

        "technique": {
            "technique_id":
                tid,

            "technique_name":
                dispatch[
                    "technique_name"
                ],
        },

        "eligibility":
            deepcopy(
                dispatch_eligibility
            ),

        "attack_provenance": {
            "attack_version":
                dispatch[
                    "attack_context"
                ][
                    "attack_version"
                ],

            "detection_strategy_ids":
                deepcopy(
                    dispatch[
                        "attack_context"
                    ].get(
                        "detection_strategy_ids",
                        [],
                    )
                ),

            "analytic_ids":
                deepcopy(
                    dispatch[
                        "attack_context"
                    ].get(
                        "analytic_ids",
                        [],
                    )
                ),
        },

        "hypothesis": {
            "text":
                dispatch[
                    "hypothesis"
                ][
                    "text"
                ],

            "investigation_focus":
                deepcopy(
                    dispatch[
                        "hypothesis"
                    ].get(
                        "investigation_focus",
                        [],
                    )
                ),

            "confidence_level":
                confidence_level(
                    dispatch[
                        "hypothesis"
                    ]
                ),
        },

        "processing_status":
            "SUCCESS",

        "plan_status":
            resolution[
                "plan_status"
            ],

        "reason_codes":
            deepcopy(
                resolution[
                    "reason_codes"
                ]
            ),

        "error_codes":
            [],

        "detection_intent":
            deepcopy(
                semantic[
                    "detection_intent"
                ]
            ),

        "required_components":
            canonical_components(
                resolution
            ),

        "detection_paths":
            canonical_paths(
                resolution
            ),

        "known_limitations":
            deepcopy(
                semantic[
                    "known_limitations"
                ]
            ),

        "downstream_action":
            resolution[
                "downstream_action"
            ],

        "grounding_assertions": {
            "component_evidence_is_not_technique_specific_path":
                True,

            "telemetry_evidence_proves_occurrence":
                False,

            "unresolved_fields_must_not_be_invented":
                True,

            "sigma_generation_performed_here":
                False,
        },

        "lineage":
            authoritative_lineage(
                eligibility_source
            ),
    }


# ============================================================
# Load authoritative inputs
# ============================================================

schema = json.loads(
    SCHEMA_PATH.read_text(
        encoding="utf-8-sig"
    )
)

validator = Draft202012Validator(
    schema,
    format_checker=FormatChecker(),
)

dispatch_rows = read_jsonl(
    DISPATCH_PATH
)

semantic_rows = read_jsonl(
    SEMANTIC_PATH
)

semantic_error_rows = read_jsonl(
    SEMANTIC_ERRORS_PATH
)

eligibility_rows = read_jsonl(
    ELIGIBILITY_PATH
)

semantic_summary = json.loads(
    SEMANTIC_SUMMARY_PATH.read_text(
        encoding="utf-8-sig"
    )
)

semantic_audit = json.loads(
    SEMANTIC_AUDIT_PATH.read_text(
        encoding="utf-8-sig"
    )
)


dispatch_map, dispatch_dupes = (
    unique_map(
        dispatch_rows,
        "dispatch",
    )
)

semantic_map, semantic_dupes = (
    unique_map(
        semantic_rows,
        "semantic",
    )
)

eligibility_map, eligibility_dupes = (
    unique_map(
        eligibility_rows,
        "eligibility",
    )
)


# ============================================================
# Preflight
# ============================================================

preflight_failures = []


def preflight_fail(
    category,
    detail,
):
    preflight_failures.append(
        {
            "stage":
                "PREFLIGHT",

            "category":
                category,

            "detail":
                detail,
        }
    )


if dispatch_dupes:
    preflight_fail(
        "DUPLICATE_DISPATCH",
        dispatch_dupes,
    )

if semantic_dupes:
    preflight_fail(
        "DUPLICATE_SEMANTIC",
        semantic_dupes,
    )

if eligibility_dupes:
    preflight_fail(
        "DUPLICATE_ELIGIBILITY",
        eligibility_dupes,
    )

if len(dispatch_rows) != 505:
    preflight_fail(
        "DISPATCH_COUNT",
        len(dispatch_rows),
    )

if len(semantic_rows) != 505:
    preflight_fail(
        "SEMANTIC_COUNT",
        len(semantic_rows),
    )

if semantic_error_rows:
    preflight_fail(
        "SEMANTIC_ERROR_RECORDS",
        len(
            semantic_error_rows
        ),
    )

if set(dispatch_map) != set(semantic_map):
    preflight_fail(
        "DISPATCH_SEMANTIC_UNIVERSE_MISMATCH",
        {
            "missing_semantic":
                sorted(
                    set(dispatch_map)
                    - set(semantic_map)
                ),

            "unexpected_semantic":
                sorted(
                    set(semantic_map)
                    - set(dispatch_map)
                ),
        },
    )

if (
    semantic_audit.get(
        "status"
    )
    != "PASS"
    or semantic_audit.get(
        "failure_count"
    )
    != 0
    or semantic_audit.get(
        "warning_count"
    )
    != 0
):
    preflight_fail(
        "SEMANTIC_V1_3_AUDIT",
        {
            "status":
                semantic_audit.get(
                    "status"
                ),

            "failures":
                semantic_audit.get(
                    "failure_count"
                ),

            "warnings":
                semantic_audit.get(
                    "warning_count"
                ),
        },
    )

if (
    semantic_summary.get(
        "semantic_outputs"
    )
    != 505
):
    preflight_fail(
        "SEMANTIC_SUMMARY_COUNT",
        semantic_summary.get(
            "semantic_outputs"
        ),
    )


for tid in dispatch_map:

    if tid not in eligibility_map:
        preflight_fail(
            "MISSING_ELIGIBILITY_SOURCE",
            tid,
        )


if preflight_failures:

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    write_jsonl(
        ERRORS_PATH,
        preflight_failures,
    )

    print(
        "FINAL DETECTION PLAN PREFLIGHT: FAIL"
    )

    print(
        json.dumps(
            preflight_failures[:20],
            indent=2,
            ensure_ascii=False,
        )
    )

    raise SystemExit(1)


# ============================================================
# Assemble all 505 plans
# ============================================================

generated_at_utc = (
    datetime.now(
        timezone.utc
    ).isoformat()
)

plans = []
index_rows = []
assembly_errors = []


for dispatch in dispatch_rows:

    tid = dispatch[
        "technique_id"
    ]

    try:

        semantic_row = semantic_map[
            tid
        ]

        eligibility_source = (
            eligibility_map[
                tid
            ]
        )

        plan = build_plan(
            dispatch,
            semantic_row,
            eligibility_source,
            generated_at_utc,
        )


        schema_errors = sorted(
            validator.iter_errors(
                plan
            ),
            key=lambda e: list(
                e.absolute_path
            ),
        )


        if schema_errors:

            assembly_errors.append(
                {
                    "stage":
                        "SCHEMA_VALIDATION",

                    "technique_id":
                        tid,

                    "errors": [
                        {
                            "path":
                                ".".join(
                                    str(part)
                                    for part
                                    in error.absolute_path
                                ),

                            "message":
                                error.message,
                        }

                        for error
                        in schema_errors[:10]
                    ],
                }
            )

            continue


        plans.append(
            plan
        )


        index_rows.append(
            {
                "technique_id":
                    tid,

                "runtime_hunt_rank":
                    dispatch.get(
                        "runtime_hunt_rank"
                    ),

                "plan_id":
                    plan[
                        "plan_id"
                    ],

                "plan_input_fingerprint":
                    plan[
                        "plan_input_fingerprint"
                    ],

                "processing_status":
                    plan[
                        "processing_status"
                    ],

                "plan_status":
                    plan[
                        "plan_status"
                    ],

                "downstream_action":
                    plan[
                        "downstream_action"
                    ],

                "contract_version":
                    "1.1",

                "semantic_artifact_version":
                    "1.3",

                "schema_valid":
                    True,
            }
        )


    except Exception as exc:

        assembly_errors.append(
            {
                "stage":
                    "ASSEMBLY",

                "technique_id":
                    tid,

                "error_type":
                    type(exc).__name__,

                "error":
                    str(exc),
            }
        )


# ============================================================
# Full 505/505 final audit
# ============================================================

audit_failures = []


def audit_fail(
    tid,
    category,
    detail,
):
    audit_failures.append(
        {
            "technique_id":
                tid,

            "category":
                category,

            "detail":
                detail,
        }
    )


plan_map = {
    plan[
        "technique"
    ][
        "technique_id"
    ]:
        plan
    for plan in plans
}


if len(plan_map) != len(plans):
    audit_fail(
        "*",
        "DUPLICATE_FINAL_TECHNIQUE",
        (
            len(plans),
            len(plan_map),
        ),
    )


if len(plans) != 505:
    audit_fail(
        "*",
        "FINAL_PLAN_COUNT",
        len(plans),
    )


if len(index_rows) != 505:
    audit_fail(
        "*",
        "FINAL_INDEX_COUNT",
        len(index_rows),
    )


if assembly_errors:
    audit_fail(
        "*",
        "ASSEMBLY_ERRORS",
        len(
            assembly_errors
        ),
    )


missing_final = sorted(
    set(dispatch_map)
    - set(plan_map)
)

unexpected_final = sorted(
    set(plan_map)
    - set(dispatch_map)
)


if missing_final:
    audit_fail(
        "*",
        "MISSING_FINAL_PLANS",
        missing_final,
    )


if unexpected_final:
    audit_fail(
        "*",
        "UNEXPECTED_FINAL_PLANS",
        unexpected_final,
    )


plan_ids = [
    plan[
        "plan_id"
    ]
    for plan in plans
]

if (
    len(plan_ids)
    != len(set(plan_ids))
):
    audit_fail(
        "*",
        "DUPLICATE_PLAN_ID",
        "Final plan_id values are not unique",
    )


status_counts = Counter(
    plan[
        "plan_status"
    ]
    for plan in plans
)


if (
    status_counts[
        "READY_FOR_BASELINE_SIGMA"
    ]
    != 492
):
    audit_fail(
        "*",
        "READY_COUNT",
        status_counts[
            "READY_FOR_BASELINE_SIGMA"
        ],
    )


if (
    status_counts[
        "NEEDS_PATH_RESOLUTION"
    ]
    != 13
):
    audit_fail(
        "*",
        "NEEDS_PATH_COUNT",
        status_counts[
            "NEEDS_PATH_RESOLUTION"
        ],
    )


lineage_sets = set()
attack_versions = set()


for tid in sorted(
    set(dispatch_map)
    & set(plan_map)
):

    dispatch = dispatch_map[
        tid
    ]

    semantic = semantic_map[
        tid
    ][
        "model_output"
    ]

    eligibility_source = (
        eligibility_map[
            tid
        ]
    )

    plan = plan_map[
        tid
    ]

    resolution = dispatch[
        "deterministic_resolution"
    ]


    # --------------------------------------------------------
    # Schema re-validation
    # --------------------------------------------------------

    schema_errors = list(
        validator.iter_errors(
            plan
        )
    )

    if schema_errors:
        audit_fail(
            tid,
            "CONTRACT_SCHEMA",
            [
                error.message
                for error
                in schema_errors[:5]
            ],
        )


    # --------------------------------------------------------
    # Identity invariants
    # --------------------------------------------------------

    if (
        plan[
            "plan_id"
        ]
        != dispatch[
            "plan_identity"
        ][
            "plan_id"
        ]
    ):
        audit_fail(
            tid,
            "PLAN_ID_DRIFT",
            plan[
                "plan_id"
            ],
        )


    if (
        plan[
            "plan_input_fingerprint"
        ]
        != dispatch[
            "plan_identity"
        ][
            "plan_input_fingerprint"
        ]
    ):
        audit_fail(
            tid,
            "PLAN_FINGERPRINT_DRIFT",
            plan[
                "plan_input_fingerprint"
            ],
        )


    if (
        plan[
            "environment_id"
        ]
        != dispatch[
            "environment_id"
        ]
    ):
        audit_fail(
            tid,
            "ENVIRONMENT_ID_DRIFT",
            plan[
                "environment_id"
            ],
        )


    if (
        plan[
            "artifact_revision"
        ]
        != dispatch[
            "plan_identity"
        ][
            "artifact_revision"
        ]
    ):
        audit_fail(
            tid,
            "ARTIFACT_REVISION_DRIFT",
            plan[
                "artifact_revision"
            ],
        )


    if (
        plan[
            "execution_context"
        ]
        != dispatch[
            "execution_context"
        ]
    ):
        audit_fail(
            tid,
            "EXECUTION_CONTEXT_DRIFT",
            "Mismatch",
        )


    # --------------------------------------------------------
    # Deterministic decision invariants
    # --------------------------------------------------------

    if (
        plan[
            "plan_status"
        ]
        != resolution[
            "plan_status"
        ]
    ):
        audit_fail(
            tid,
            "PLAN_STATUS_DRIFT",
            plan[
                "plan_status"
            ],
        )


    if (
        plan[
            "downstream_action"
        ]
        != resolution[
            "downstream_action"
        ]
    ):
        audit_fail(
            tid,
            "DOWNSTREAM_ACTION_DRIFT",
            plan[
                "downstream_action"
            ],
        )


    if (
        plan[
            "reason_codes"
        ]
        != resolution[
            "reason_codes"
        ]
    ):
        audit_fail(
            tid,
            "REASON_CODE_DRIFT",
            "Mismatch",
        )


    if (
        plan[
            "required_components"
        ]
        != canonical_components(
            resolution
        )
    ):
        audit_fail(
            tid,
            "COMPONENT_DRIFT",
            "Mismatch",
        )


    if (
        plan[
            "detection_paths"
        ]
        != canonical_paths(
            resolution
        )
    ):
        audit_fail(
            tid,
            "DETECTION_PATH_DRIFT",
            "Mismatch",
        )


    # --------------------------------------------------------
    # Semantic provenance invariants
    # --------------------------------------------------------

    if (
        plan[
            "detection_intent"
        ]
        != semantic[
            "detection_intent"
        ]
    ):
        audit_fail(
            tid,
            "SEMANTIC_INTENT_DRIFT",
            "Mismatch",
        )


    if (
        plan[
            "known_limitations"
        ]
        != semantic[
            "known_limitations"
        ]
    ):
        audit_fail(
            tid,
            "LIMITATION_DRIFT",
            "Mismatch",
        )


    # --------------------------------------------------------
    # Eligibility invariants
    # --------------------------------------------------------

    if (
        plan[
            "eligibility"
        ]
        != dispatch[
            "eligibility"
        ]
    ):
        audit_fail(
            tid,
            "ELIGIBILITY_DRIFT",
            "Mismatch",
        )


    if (
        plan[
            "eligibility"
        ][
            "input_fingerprint"
        ]
        != eligibility_source[
            "input_fingerprint"
        ]
    ):
        audit_fail(
            tid,
            "ELIGIBILITY_FINGERPRINT_DRIFT",
            "Mismatch",
        )


    # --------------------------------------------------------
    # Lineage invariants
    # --------------------------------------------------------

    expected_lineage = (
        authoritative_lineage(
            eligibility_source
        )
    )


    if (
        plan[
            "lineage"
        ]
        != expected_lineage
    ):
        audit_fail(
            tid,
            "LINEAGE_DRIFT",
            "Mismatch",
        )


    lineage_sets.add(
        tuple(
            sorted(
                expected_lineage.items()
            )
        )
    )


    attack_versions.add(
        plan[
            "attack_provenance"
        ][
            "attack_version"
        ]
    )


    # --------------------------------------------------------
    # Grounding / status invariants
    # --------------------------------------------------------

    grounded_paths = [
        path
        for path
        in plan[
            "detection_paths"
        ]
        if path[
            "grounding_status"
        ]
        == "TECHNIQUE_SPECIFIC_GROUNDED"
    ]


    if (
        plan[
            "plan_status"
        ]
        == "READY_FOR_BASELINE_SIGMA"
    ):

        if not grounded_paths:
            audit_fail(
                tid,
                "READY_WITHOUT_GROUNDED_PATH",
                "No grounded detection path",
            )


        if (
            plan[
                "downstream_action"
            ]
            != "BASELINE_SIGMA_GENERATION"
        ):
            audit_fail(
                tid,
                "READY_ACTION",
                plan[
                    "downstream_action"
                ],
            )


    elif (
        plan[
            "plan_status"
        ]
        == "NEEDS_PATH_RESOLUTION"
    ):

        if grounded_paths:
            audit_fail(
                tid,
                "NEEDS_PATH_HAS_GROUNDED_PATH",
                len(
                    grounded_paths
                ),
            )


        if (
            plan[
                "downstream_action"
            ]
            != "DETECTION_PATH_RESOLUTION"
        ):
            audit_fail(
                tid,
                "NEEDS_PATH_ACTION",
                plan[
                    "downstream_action"
                ],
            )


    # --------------------------------------------------------
    # Product safety assertions
    # --------------------------------------------------------

    expected_assertions = {
        "component_evidence_is_not_technique_specific_path":
            True,

        "telemetry_evidence_proves_occurrence":
            False,

        "unresolved_fields_must_not_be_invented":
            True,

        "sigma_generation_performed_here":
            False,
    }


    if (
        plan[
            "grounding_assertions"
        ]
        != expected_assertions
    ):
        audit_fail(
            tid,
            "GROUNDING_ASSERTION_DRIFT",
            "Mismatch",
        )


# ============================================================
# Batch lineage consistency
# ============================================================

if len(lineage_sets) != 1:
    audit_fail(
        "*",
        "LINEAGE_VERSION_SET_COUNT",
        len(lineage_sets),
    )


# ============================================================
# Final outputs
# ============================================================

all_errors = (
    assembly_errors
    +
    [
        {
            "stage":
                "FINAL_AUDIT",

            **failure,
        }
        for failure
        in audit_failures
    ]
)


failure_counts = Counter(
    failure[
        "category"
    ]
    for failure
    in audit_failures
)


audit_status = (
    "PASS"
    if not all_errors
    else "FAIL"
)


audit_report = {
    "audit_version":
        "1.1",

    "contract_version":
        "1.1",

    "input_dispatch_records":
        len(dispatch_rows),

    "semantic_records":
        len(semantic_rows),

    "final_detection_plans":
        len(plans),

    "results_index_records":
        len(index_rows),

    "ready_for_baseline_sigma":
        status_counts[
            "READY_FOR_BASELINE_SIGMA"
        ],

    "needs_path_resolution":
        status_counts[
            "NEEDS_PATH_RESOLUTION"
        ],

    "schema_valid_records":
        len(plans)
        - sum(
            1
            for row in assembly_errors
            if row.get(
                "stage"
            )
            == "SCHEMA_VALIDATION"
        ),

    "assembly_errors":
        len(
            assembly_errors
        ),

    "audit_failures":
        len(
            audit_failures
        ),

    "failure_categories":
        dict(
            failure_counts
        ),

    "lineage_version_sets":
        [
            dict(items)
            for items
            in sorted(
                lineage_sets
            )
        ],

    "attack_versions":
        sorted(
            attack_versions
        ),

    "source_semantic_audit_status":
        semantic_audit.get(
            "status"
        ),

    "source_semantic_corrected_records":
        semantic_summary.get(
            "corrected_records"
        ),

    "failures":
        audit_failures,

    "status":
        audit_status,
}


summary = {
    "assembler_version":
        "1.0",

    "contract_version":
        "1.1",

    "semantic_artifact_version":
        "1.3",

    "generated_at_utc":
        generated_at_utc,

    "input_dispatch_records":
        len(dispatch_rows),

    "semantic_input_records":
        len(semantic_rows),

    "final_detection_plans":
        len(plans),

    "schema_valid":
        len(plans)
        if not assembly_errors
        else (
            len(plans)
        ),

    "processing_errors":
        len(
            all_errors
        ),

    "ready_for_baseline_sigma":
        status_counts[
            "READY_FOR_BASELINE_SIGMA"
        ],

    "needs_path_resolution":
        status_counts[
            "NEEDS_PATH_RESOLUTION"
        ],

    "lineage_version_set_count":
        len(lineage_sets),

    "source_hashes": {
        "dispatch":
            sha256_file(
                DISPATCH_PATH
            ),

        "semantic_v1_3":
            sha256_file(
                SEMANTIC_PATH
            ),

        "eligibility":
            sha256_file(
                ELIGIBILITY_PATH
            ),

        "contract_schema_v1_1":
            sha256_file(
                SCHEMA_PATH
            ),
    },

    "final_audit_status":
        audit_status,
}


write_jsonl(
    PLANS_PATH,
    plans,
)

write_jsonl(
    INDEX_PATH,
    index_rows,
)

write_jsonl(
    ERRORS_PATH,
    all_errors,
)

write_json(
    SUMMARY_PATH,
    summary,
)

write_json(
    AUDIT_PATH,
    audit_report,
)


# ============================================================
# Console report
# ============================================================

print(
    "===== TASK 42 FINAL DETECTION PLAN ASSEMBLY ====="
)

print()

print(
    "Dispatch inputs              :",
    len(dispatch_rows),
)

print(
    "Semantic v1.3 inputs         :",
    len(semantic_rows),
)

print(
    "Final Detection Plans        :",
    len(plans),
)

print(
    "Results index                :",
    len(index_rows),
)

print()

print(
    "READY_FOR_BASELINE_SIGMA     :",
    status_counts[
        "READY_FOR_BASELINE_SIGMA"
    ],
)

print(
    "NEEDS_PATH_RESOLUTION        :",
    status_counts[
        "NEEDS_PATH_RESOLUTION"
    ],
)

print()

print(
    "Assembly/schema errors       :",
    len(assembly_errors),
)

print(
    "Final audit failures         :",
    len(audit_failures),
)

print(
    "Total error records          :",
    len(all_errors),
)

print()

print(
    "Lineage version sets         :",
    len(lineage_sets),
)


for items in sorted(
    lineage_sets
):
    print(
        "Lineage:",
        dict(items),
    )


print(
    "ATT&CK versions              :",
    sorted(
        attack_versions
    ),
)

print()

print(
    "Plans   :",
    PLANS_PATH,
)

print(
    "Index   :",
    INDEX_PATH,
)

print(
    "Errors  :",
    ERRORS_PATH,
)

print(
    "Summary :",
    SUMMARY_PATH,
)

print(
    "Audit   :",
    AUDIT_PATH,
)

print()


if audit_status != "PASS":

    print(
        "===== FAILURE CATEGORIES ====="
    )

    for key, value in sorted(
        failure_counts.items()
    ):
        print(
            key,
            ":",
            value,
        )

    print()

    if all_errors:

        print(
            "===== FIRST ERRORS ====="
        )

        for error in all_errors[:20]:
            print(
                json.dumps(
                    error,
                    ensure_ascii=False,
                )
            )

        print()

    print(
        "TASK 42 FINAL AUDIT: FAIL"
    )

    raise SystemExit(1)


print(
    "TASK 42 FINAL AUDIT: PASS"
)
