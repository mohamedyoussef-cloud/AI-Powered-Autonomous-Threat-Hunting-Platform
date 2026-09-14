from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]

PLANS_PATH = (
    ROOT
    / "data"
    / "processed"
    / "phase3"
    / "detection_plan"
    / "detection_plans_v1_1.jsonl"
)

PLAN_AUDIT_PATH = (
    ROOT
    / "data"
    / "processed"
    / "phase3"
    / "detection_plan"
    / "detection_plan_final_audit_v1_1.json"
)

DISPATCH_PATH = (
    ROOT
    / "gpu"
    / "detection_plan_v1"
    / "return"
    / "extracted_v1_3"
    / "detection_plan_v1"
    / "export_v1_3"
    / "detection_plan_baseline_dispatch_v1.jsonl"
)

OUTPUT_DIR = (
    ROOT
    / "data"
    / "processed"
    / "phase3"
    / "sigma_generation"
)

UNITS_PATH = (
    OUTPUT_DIR
    / "sigma_generation_units_v1.jsonl"
)

BLOCKED_PATH = (
    OUTPUT_DIR
    / "sigma_generation_blocked_v1.jsonl"
)

DESIGN_PATH = (
    OUTPUT_DIR
    / "sigma_generation_design_v1.json"
)

AUDIT_PATH = (
    OUTPUT_DIR
    / "sigma_generation_design_audit_v1.json"
)


def read_jsonl(path):
    return [
        json.loads(line)
        for line in path.read_text(
            encoding="utf-8-sig"
        ).splitlines()
        if line.strip()
    ]


def write_jsonl(path, rows):
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_text(
        "".join(
            json.dumps(
                row,
                ensure_ascii=False,
                sort_keys=True,
            ) + "\n"
            for row in rows
        ),
        encoding="utf-8",
    )


def write_json(path, value):
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_text(
        json.dumps(
            value,
            indent=2,
            ensure_ascii=False,
            sort_keys=True,
        ) + "\n",
        encoding="utf-8",
    )


def stable_unit_id(plan_id, path_id):
    raw = (
        plan_id
        + "|"
        + path_id
    ).encode("utf-8")

    return (
        "SGU-"
        + hashlib.sha256(
            raw
        ).hexdigest()[:24]
    )


plans = read_jsonl(
    PLANS_PATH
)

dispatch_rows = read_jsonl(
    DISPATCH_PATH
)

plan_audit = json.loads(
    PLAN_AUDIT_PATH.read_text(
        encoding="utf-8-sig"
    )
)


if (
    plan_audit.get("status")
    != "PASS"
):
    raise SystemExit(
        "Task 42 final audit is not PASS"
    )


dispatch = {
    row["technique_id"]:
        row
    for row in dispatch_rows
}


units = []
blocked = []
failures = []

ready_count = 0
needs_count = 0
grounded_path_count = 0


for plan in plans:

    tid = plan[
        "technique"
    ][
        "technique_id"
    ]

    status = plan[
        "plan_status"
    ]

    source = dispatch.get(
        tid
    )

    if source is None:
        failures.append(
            {
                "technique_id":
                    tid,

                "error":
                    "MISSING_DISPATCH_SOURCE",
            }
        )
        continue


    if (
        source[
            "plan_identity"
        ][
            "plan_id"
        ]
        != plan[
            "plan_id"
        ]
    ):
        failures.append(
            {
                "technique_id":
                    tid,

                "error":
                    "PLAN_ID_MISMATCH",
            }
        )
        continue


    if (
        source[
            "plan_identity"
        ][
            "plan_input_fingerprint"
        ]
        != plan[
            "plan_input_fingerprint"
        ]
    ):
        failures.append(
            {
                "technique_id":
                    tid,

                "error":
                    "PLAN_FINGERPRINT_MISMATCH",
            }
        )
        continue


    grounded_final = {
        path["path_id"]:
            path

        for path in plan[
            "detection_paths"
        ]

        if (
            path[
                "grounding_status"
            ]
            == "TECHNIQUE_SPECIFIC_GROUNDED"
        )
    }


    grounded_source = {
        path["path_id"]:
            path

        for path in source[
            "deterministic_resolution"
        ].get(
            "grounded_paths",
            [],
        )
    }


    if (
        set(grounded_final)
        != set(grounded_source)
    ):
        failures.append(
            {
                "technique_id":
                    tid,

                "error":
                    "GROUNDED_PATH_UNIVERSE_MISMATCH",
            }
        )
        continue


    if (
        status
        == "READY_FOR_BASELINE_SIGMA"
    ):

        ready_count += 1

        if not grounded_final:
            failures.append(
                {
                    "technique_id":
                        tid,

                    "error":
                        "READY_WITHOUT_GROUNDED_PATH",
                }
            )
            continue


        for path_id in sorted(
            grounded_final
        ):

            final_path = (
                grounded_final[
                    path_id
                ]
            )

            source_path = (
                grounded_source[
                    path_id
                ]
            )


            # Exact structured provenance check.
            structured_keys = [
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


            drift = [
                key
                for key in structured_keys
                if (
                    final_path.get(key)
                    != source_path.get(key)
                )
            ]


            if drift:
                failures.append(
                    {
                        "technique_id":
                            tid,

                        "path_id":
                            path_id,

                        "error":
                            "PATH_PROVENANCE_DRIFT",

                        "fields":
                            drift,
                    }
                )

                continue


            analytic_id = (
                source_path.get(
                    "analytic_id"
                )
            )

            analytic_name = (
                source_path.get(
                    "analytic_name"
                )
            )

            analytic_description = (
                source_path.get(
                    "analytic_description"
                )
            )


            if (
                not analytic_id
                or not analytic_description
            ):
                failures.append(
                    {
                        "technique_id":
                            tid,

                        "path_id":
                            path_id,

                        "error":
                            "MISSING_PATH_SEMANTICS",
                    }
                )

                continue


            unit = {
                "generation_unit_version":
                    "1.0",

                "generation_unit_id":
                    stable_unit_id(
                        plan[
                            "plan_id"
                        ],
                        path_id,
                    ),

                "plan_id":
                    plan[
                        "plan_id"
                    ],

                "plan_input_fingerprint":
                    plan[
                        "plan_input_fingerprint"
                    ],

                "environment_id":
                    plan[
                        "environment_id"
                    ],

                "technique":
                    plan[
                        "technique"
                    ],

                "attack_provenance":
                    plan[
                        "attack_provenance"
                    ],

                "detection_intent":
                    plan[
                        "detection_intent"
                    ],

                "path_semantics": {
                    "path_id":
                        path_id,

                    "analytic_id":
                        analytic_id,

                    "analytic_name":
                        analytic_name,

                    "analytic_description":
                        analytic_description,
                },

                "grounded_detection_path":
                    final_path,

                "sigma_generation_policy": {
                    "baseline_only":
                        True,

                    "production_ready":
                        False,

                    "sigma_status":
                        "experimental",

                    "use_only_grounded_path":
                        True,

                    "unresolved_paths_exposed":
                        False,

                    "field_invention_allowed":
                        False,

                    "event_id_invention_allowed":
                        False,

                    "logsource_invention_allowed":
                        False,

                    "occurrence_claims_allowed":
                        False,

                    "siem_query_generation_allowed":
                        False,
                },
            }


            units.append(
                unit
            )

            grounded_path_count += 1


    elif (
        status
        == "NEEDS_PATH_RESOLUTION"
    ):

        needs_count += 1

        if grounded_final:
            failures.append(
                {
                    "technique_id":
                        tid,

                    "error":
                        "NEEDS_PATH_HAS_GROUNDED_PATH",
                }
            )

            continue


        blocked.append(
            {
                "technique_id":
                    tid,

                "technique_name":
                    plan[
                        "technique"
                    ][
                        "technique_name"
                    ],

                "plan_id":
                    plan[
                        "plan_id"
                    ],

                "plan_status":
                    status,

                "downstream_action":
                    plan[
                        "downstream_action"
                    ],

                "reason_codes":
                    plan[
                        "reason_codes"
                    ],

                "sigma_generation_allowed":
                    False,

                "block_reason":
                    "TECHNIQUE_SPECIFIC_PATH_NOT_RESOLVED",
            }
        )


    else:

        failures.append(
            {
                "technique_id":
                    tid,

                "error":
                    f"UNEXPECTED_PLAN_STATUS:{status}",
            }
        )


unit_ids = [
    row[
        "generation_unit_id"
    ]
    for row in units
]

path_keys = [
    (
        row[
            "technique"
        ][
            "technique_id"
        ],
        row[
            "path_semantics"
        ][
            "path_id"
        ],
    )
    for row in units
]


if (
    len(unit_ids)
    != len(set(unit_ids))
):
    failures.append(
        {
            "error":
                "DUPLICATE_GENERATION_UNIT_ID",
        }
    )


if (
    len(path_keys)
    != len(set(path_keys))
):
    failures.append(
        {
            "error":
                "DUPLICATE_TECHNIQUE_PATH_UNIT",
        }
    )


if len(plans) != 505:
    failures.append(
        {
            "error":
                "FINAL_PLAN_COUNT",

            "actual":
                len(plans),
        }
    )


if ready_count != 492:
    failures.append(
        {
            "error":
                "READY_COUNT",

            "actual":
                ready_count,
        }
    )


if needs_count != 13:
    failures.append(
        {
            "error":
                "NEEDS_PATH_COUNT",

            "actual":
                needs_count,
        }
    )


if len(blocked) != 13:
    failures.append(
        {
            "error":
                "BLOCKED_COUNT",

            "actual":
                len(blocked),
        }
    )


design = {
    "design_version":
        "1.0",

    "task":
        "Task 43 - Sigma Generation Design",

    "source_detection_plan_contract":
        "1.1",

    "input_population": {
        "final_detection_plans":
            505,

        "ready_for_baseline_sigma":
            ready_count,

        "needs_path_resolution":
            needs_count,
    },

    "generation_granularity":
        "ONE_SIGMA_RULE_PER_GROUNDED_DETECTION_PATH",

    "generation_unit_count":
        len(units),

    "blocked_plan_count":
        len(blocked),

    "baseline_rule_policy": {
        "sigma_status":
            "experimental",

        "baseline_not_production":
            True,

        "grounded_paths_only":
            True,

        "unresolved_paths_forbidden":
            True,

        "invented_fields_forbidden":
            True,

        "invented_event_ids_forbidden":
            True,

        "invented_log_sources_forbidden":
            True,

        "attack_occurrence_claims_forbidden":
            True,

        "siem_specific_queries_forbidden":
            True,
    },

    "task_44_contract": {
        "input":
            "sigma_generation_units_v1.jsonl",

        "output":
            "baseline Sigma YAML rules",

        "validation_next":
            "pySigma",

        "blocked_inputs":
            "sigma_generation_blocked_v1.jsonl",
    },

    "generated_at_utc":
        datetime.now(
            timezone.utc
        ).isoformat(),
}


audit = {
    "audit_version":
        "1.0",

    "final_detection_plans":
        len(plans),

    "ready_detection_plans":
        ready_count,

    "needs_path_resolution_plans":
        needs_count,

    "grounded_detection_paths":
        grounded_path_count,

    "sigma_generation_units":
        len(units),

    "blocked_sigma_plans":
        len(blocked),

    "duplicate_unit_ids":
        len(unit_ids)
        - len(set(unit_ids)),

    "duplicate_path_units":
        len(path_keys)
        - len(set(path_keys)),

    "unresolved_paths_exposed":
        0,

    "design_failures":
        len(failures),

    "failure_categories":
        dict(
            Counter(
                row.get(
                    "error",
                    "UNKNOWN"
                )
                for row in failures
            )
        ),

    "failures":
        failures,

    "status":
        (
            "PASS"
            if not failures
            else "FAIL"
        ),
}


write_jsonl(
    UNITS_PATH,
    units,
)

write_jsonl(
    BLOCKED_PATH,
    blocked,
)

write_json(
    DESIGN_PATH,
    design,
)

write_json(
    AUDIT_PATH,
    audit,
)


print(
    "===== TASK 43 SIGMA GENERATION DESIGN ====="
)

print()

print(
    "Final Detection Plans       :",
    len(plans),
)

print(
    "READY plans                 :",
    ready_count,
)

print(
    "NEEDS_PATH plans            :",
    needs_count,
)

print()

print(
    "Grounded detection paths    :",
    grounded_path_count,
)

print(
    "Sigma generation units      :",
    len(units),
)

print(
    "Blocked from Sigma          :",
    len(blocked),
)

print()

print(
    "Unresolved paths exposed    :",
    0,
)

print(
    "Design failures             :",
    len(failures),
)

print()

print(
    "Units  :",
    UNITS_PATH,
)

print(
    "Blocked:",
    BLOCKED_PATH,
)

print(
    "Design :",
    DESIGN_PATH,
)

print(
    "Audit  :",
    AUDIT_PATH,
)

print()


if failures:

    print(
        "===== FIRST FAILURES ====="
    )

    for failure in failures[:20]:

        print(
            json.dumps(
                failure,
                ensure_ascii=False,
            )
        )

    print()

    print(
        "TASK 43 SIGMA GENERATION DESIGN: FAIL"
    )

    raise SystemExit(1)


print(
    "TASK 43 SIGMA GENERATION DESIGN: PASS"
)
