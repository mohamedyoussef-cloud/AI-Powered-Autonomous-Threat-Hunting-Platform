from __future__ import annotations

import importlib.metadata
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

try:
    from sigma.collection import SigmaCollection
    from sigma.validation import SigmaValidator
    from sigma.validators.core import validators
except Exception as exc:
    raise SystemExit(
        f"pySigma import failed: {type(exc).__name__}: {exc}"
    )


ROOT = Path(__file__).resolve().parents[4]

BASELINE_DIR = (
    ROOT
    / "data"
    / "processed"
    / "phase3"
    / "sigma_baseline"
)

RULES_DIR = (
    BASELINE_DIR
    / "rules"
)

BASELINE_INDEX = (
    BASELINE_DIR
    / "baseline_sigma_results_index_v1.jsonl"
)

BASELINE_AUDIT = (
    BASELINE_DIR
    / "baseline_sigma_generation_audit_v1.json"
)

OUTPUT_DIR = (
    ROOT
    / "data"
    / "processed"
    / "phase3"
    / "pysigma_validation"
)

RESULTS_PATH = (
    OUTPUT_DIR
    / "pysigma_validation_results_index_v1.jsonl"
)

ISSUES_PATH = (
    OUTPUT_DIR
    / "pysigma_validation_issues_v1.jsonl"
)

ERRORS_PATH = (
    OUTPUT_DIR
    / "pysigma_validation_errors_v1.jsonl"
)

SUMMARY_PATH = (
    OUTPUT_DIR
    / "pysigma_validation_summary_v1.json"
)

AUDIT_PATH = (
    OUTPUT_DIR
    / "pysigma_validation_audit_v1.json"
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


def severity_name(issue):
    severity = getattr(
        issue,
        "severity",
        None,
    )

    name = getattr(
        severity,
        "name",
        None,
    )

    text = (
        str(name)
        if name
        else str(severity)
    ).lower()

    if "high" in text:
        return "HIGH"

    if "medium" in text:
        return "MEDIUM"

    if "low" in text:
        return "LOW"

    return "UNKNOWN"


def issue_rule_ids(issue):
    result = []

    for rule in (
        getattr(
            issue,
            "rules",
            [],
        )
        or []
    ):
        rid = getattr(
            rule,
            "id",
            None,
        )

        if rid is not None:
            result.append(
                str(rid)
            )

    return sorted(
        set(result)
    )


# ============================================================
# Authoritative Task 44 state
# ============================================================

baseline_index = read_jsonl(
    BASELINE_INDEX
)

baseline_audit = json.loads(
    BASELINE_AUDIT.read_text(
        encoding="utf-8-sig"
    )
)

rule_files = sorted(
    RULES_DIR.glob(
        "*.yml"
    )
)

expected_ids = {
    row[
        "rule_id"
    ]
    for row in baseline_index
}

expected_by_id = {
    row[
        "rule_id"
    ]:
        row
    for row in baseline_index
}


# ============================================================
# pySigma version
# ============================================================

try:
    pysigma_version = (
        importlib.metadata.version(
            "pySigma"
        )
    )
except Exception:
    pysigma_version = "UNKNOWN"


# ============================================================
# Parse all 540 rules
# ============================================================

fatal_runtime_errors = []

try:

    collection = (
        SigmaCollection.load_ruleset(
            [RULES_DIR],
            collect_errors=True,
        )
    )

except Exception as exc:

    fatal_runtime_errors.append(
        {
            "stage":
                "RULESET_LOAD",

            "error_type":
                type(exc).__name__,

            "error":
                str(exc),
        }
    )

    collection = None


parse_errors = []
loaded_rules = []


if collection is not None:

    loaded_rules = list(
        collection.rules
    )

    for error in (
        collection.errors
        or []
    ):

        parse_errors.append(
            {
                "stage":
                    "PYSIGMA_PARSE",

                "error_type":
                    type(error).__name__,

                "error":
                    str(error),
            }
        )


loaded_ids = []

for rule in loaded_rules:

    rid = getattr(
        rule,
        "id",
        None,
    )

    loaded_ids.append(
        str(rid)
        if rid is not None
        else None
    )


loaded_id_set = {
    rid
    for rid in loaded_ids
    if rid
}


# ============================================================
# pySigma semantic validation — all built-in validators
# ============================================================

validation_issues = []

if (
    collection is not None
    and not parse_errors
):

    try:

        validator = SigmaValidator(
            validators.values()
        )

        validation_issues = (
            validator.validate_rules(
                loaded_rules
            )
        )

    except Exception as exc:

        fatal_runtime_errors.append(
            {
                "stage":
                    "PYSIGMA_VALIDATION",

                "error_type":
                    type(exc).__name__,

                "error":
                    str(exc),
            }
        )


issue_rows = []
severity_counts = Counter()
per_rule_severity = defaultdict(
    Counter
)


for issue in validation_issues:

    severity = severity_name(
        issue
    )

    rule_ids = issue_rule_ids(
        issue
    )

    severity_counts[
        severity
    ] += 1


    row = {
        "issue_class":
            type(issue).__name__,

        "severity":
            severity,

        "description":
            getattr(
                issue,
                "description",
                None,
            ),

        "rule_ids":
            rule_ids,

        "rendered":
            str(issue),
    }


    issue_rows.append(
        row
    )


    for rid in rule_ids:

        per_rule_severity[
            rid
        ][
            severity
        ] += 1


# ============================================================
# Build 540-record validation index
# ============================================================

results = []


for row in baseline_index:

    rid = row[
        "rule_id"
    ]

    counts = (
        per_rule_severity[
            rid
        ]
    )


    results.append(
        {
            "rule_id":
                rid,

            "rule_file":
                row[
                    "rule_file"
                ],

            "generation_unit_id":
                row[
                    "generation_unit_id"
                ],

            "technique_id":
                row[
                    "technique_id"
                ],

            "path_id":
                row[
                    "path_id"
                ],

            "analytic_id":
                row[
                    "analytic_id"
                ],

            "pysigma_parsed":
                rid
                in loaded_id_set,

            "high_issues":
                counts[
                    "HIGH"
                ],

            "medium_issues":
                counts[
                    "MEDIUM"
                ],

            "low_issues":
                counts[
                    "LOW"
                ],

            "blocking_validation_issues":
                (
                    counts[
                        "HIGH"
                    ]
                    +
                    counts[
                        "MEDIUM"
                    ]
                ),

            "validation_status":
                (
                    "PASS"
                    if (
                        rid
                        in loaded_id_set
                        and counts[
                            "HIGH"
                        ] == 0
                        and counts[
                            "MEDIUM"
                        ] == 0
                    )
                    else "FAIL"
                ),
        }
    )


# ============================================================
# Full-universe invariants
# ============================================================

failures = []


def fail(
    category,
    detail,
):
    failures.append(
        {
            "category":
                category,

            "detail":
                detail,
        }
    )


if (
    baseline_audit.get(
        "status"
    )
    != "PASS"
):
    fail(
        "TASK44_AUDIT_NOT_PASS",
        baseline_audit.get(
            "status"
        ),
    )


if len(rule_files) != 540:
    fail(
        "RULE_FILE_COUNT",
        len(rule_files),
    )


if len(baseline_index) != 540:
    fail(
        "BASELINE_INDEX_COUNT",
        len(
            baseline_index
        ),
    )


if len(expected_ids) != 540:
    fail(
        "EXPECTED_RULE_ID_UNIQUENESS",
        len(expected_ids),
    )


if len(loaded_rules) != 540:
    fail(
        "PYSIGMA_LOADED_RULE_COUNT",
        len(loaded_rules),
    )


if len(loaded_id_set) != 540:
    fail(
        "PYSIGMA_LOADED_ID_COUNT",
        len(
            loaded_id_set
        ),
    )


missing_ids = sorted(
    expected_ids
    - loaded_id_set
)

unexpected_ids = sorted(
    loaded_id_set
    - expected_ids
)


if missing_ids:
    fail(
        "MISSING_RULE_IDS",
        missing_ids,
    )


if unexpected_ids:
    fail(
        "UNEXPECTED_RULE_IDS",
        unexpected_ids,
    )


if parse_errors:
    fail(
        "PYSIGMA_PARSE_ERRORS",
        len(parse_errors),
    )


if fatal_runtime_errors:
    fail(
        "PYSIGMA_RUNTIME_ERRORS",
        len(
            fatal_runtime_errors
        ),
    )


if (
    severity_counts[
        "HIGH"
    ]
    > 0
):
    fail(
        "HIGH_VALIDATION_ISSUES",
        severity_counts[
            "HIGH"
        ],
    )


if (
    severity_counts[
        "MEDIUM"
    ]
    > 0
):
    fail(
        "MEDIUM_VALIDATION_ISSUES",
        severity_counts[
            "MEDIUM"
        ],
    )


failed_results = [
    row
    for row in results
    if (
        row[
            "validation_status"
        ]
        != "PASS"
    )
]


if failed_results:
    fail(
        "FAILED_RULE_VALIDATIONS",
        len(
            failed_results
        ),
    )


# ============================================================
# Output
# ============================================================

all_errors = (
    fatal_runtime_errors
    + parse_errors
)


summary = {
    "validator_version":
        "1.0",

    "pysigma_version":
        pysigma_version,

    "input_rule_files":
        len(rule_files),

    "baseline_index_records":
        len(baseline_index),

    "pysigma_loaded_rules":
        len(loaded_rules),

    "pysigma_parse_errors":
        len(parse_errors),

    "validation_issues_total":
        len(validation_issues),

    "high_issues":
        severity_counts[
            "HIGH"
        ],

    "medium_issues":
        severity_counts[
            "MEDIUM"
        ],

    "low_issues":
        severity_counts[
            "LOW"
        ],

    "unknown_severity_issues":
        severity_counts[
            "UNKNOWN"
        ],

    "rules_passed":
        sum(
            1
            for row in results
            if row[
                "validation_status"
            ]
            == "PASS"
        ),

    "rules_failed":
        len(
            failed_results
        ),

    "generated_at_utc":
        datetime.now(
            timezone.utc
        ).isoformat(),
}


audit = {
    "audit_version":
        "1.0",

    "validation_scope":
        "FULL_540_RULE_UNIVERSE",

    "rule_files":
        len(rule_files),

    "expected_rule_ids":
        len(expected_ids),

    "loaded_rules":
        len(loaded_rules),

    "loaded_unique_rule_ids":
        len(
            loaded_id_set
        ),

    "missing_rule_ids":
        len(missing_ids),

    "unexpected_rule_ids":
        len(unexpected_ids),

    "parse_errors":
        len(parse_errors),

    "high_validation_issues":
        severity_counts[
            "HIGH"
        ],

    "medium_validation_issues":
        severity_counts[
            "MEDIUM"
        ],

    "low_validation_warnings":
        severity_counts[
            "LOW"
        ],

    "blocking_failures":
        len(failures),

    "failure_categories":
        dict(
            Counter(
                row[
                    "category"
                ]
                for row
                in failures
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
    RESULTS_PATH,
    results,
)

write_jsonl(
    ISSUES_PATH,
    issue_rows,
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
    audit,
)


# ============================================================
# Console
# ============================================================

print(
    "===== TASK 45 PYSIGMA VALIDATION ====="
)

print()

print(
    "pySigma version             :",
    pysigma_version,
)

print()

print(
    "Input rule files            :",
    len(rule_files),
)

print(
    "Expected rule IDs           :",
    len(expected_ids),
)

print(
    "pySigma loaded rules        :",
    len(loaded_rules),
)

print(
    "Unique loaded rule IDs      :",
    len(loaded_id_set),
)

print()

print(
    "Parse errors                :",
    len(parse_errors),
)

print(
    "Missing rule IDs            :",
    len(missing_ids),
)

print(
    "Unexpected rule IDs         :",
    len(unexpected_ids),
)

print()

print(
    "Validation issues:"
)

print(
    "  HIGH                      :",
    severity_counts[
        "HIGH"
    ],
)

print(
    "  MEDIUM                    :",
    severity_counts[
        "MEDIUM"
    ],
)

print(
    "  LOW                       :",
    severity_counts[
        "LOW"
    ],
)

print(
    "  UNKNOWN                   :",
    severity_counts[
        "UNKNOWN"
    ],
)

print()

print(
    "Rules PASS                  :",
    sum(
        1
        for row in results
        if row[
            "validation_status"
        ]
        == "PASS"
    ),
)

print(
    "Rules FAIL                  :",
    len(failed_results),
)

print(
    "Blocking audit failures     :",
    len(failures),
)

print()


if validation_issues:

    print(
        "===== ISSUE CATEGORY COUNTS ====="
    )

    classes = Counter(
        type(issue).__name__
        for issue
        in validation_issues
    )

    for key, value in sorted(
        classes.items()
    ):
        print(
            f"{key}: {value}"
        )

    print()


if failures:

    print(
        "===== FIRST BLOCKING FAILURES ====="
    )

    for row in failures[:20]:
        print(
            json.dumps(
                row,
                ensure_ascii=False,
            )
        )

    print()


if (
    severity_counts[
        "LOW"
    ]
    > 0
):

    print(
        "LOW-severity issues are recorded "
        "as non-blocking baseline warnings."
    )

    print()


print(
    "Results:",
    RESULTS_PATH,
)

print(
    "Issues :",
    ISSUES_PATH,
)

print(
    "Errors :",
    ERRORS_PATH,
)

print(
    "Summary:",
    SUMMARY_PATH,
)

print(
    "Audit  :",
    AUDIT_PATH,
)

print()


if failures:

    print(
        "TASK 45 PYSIGMA VALIDATION: FAIL"
    )

    raise SystemExit(1)


print(
    "TASK 45 PYSIGMA VALIDATION: PASS"
)
