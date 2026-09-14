from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from importlib.metadata import version
from pathlib import Path

from sigma.rule import SigmaRule
from sigma.validation import SigmaValidator
from sigma.validators.core import validators


ROOT = Path(__file__).resolve().parents[1]

INPUT = (
    ROOT
    / "data"
    / "processed"
    / "detections"
    / "sigma_rules_valid.jsonl"
)

COMPAT_OUTPUT = (
    ROOT
    / "data"
    / "processed"
    / "detections"
    / "sigma_pysigma_compatibility.csv"
)

ISSUES_OUTPUT = (
    ROOT
    / "reports"
    / "sigma_pysigma_validation_issues.csv"
)

SUMMARY_OUTPUT = (
    ROOT
    / "reports"
    / "sigma_pysigma_validation_summary.json"
)

SUMMARY_OUTPUT.parent.mkdir(
    parents=True,
    exist_ok=True,
)


def read_jsonl(path: Path):
    records = []

    with path.open(
        "r",
        encoding="utf-8",
    ) as f:

        for line_number, line in enumerate(
            f,
            start=1,
        ):

            if not line.strip():
                continue

            record = json.loads(line)

            record["_input_line_number"] = line_number
            records.append(record)

    return records


def reconstruct_sigma_rule(record: dict) -> dict:
    """
    Reconstruct only fields that have direct Sigma semantics.

    Important:
    required_fields from our prepared record are NOT mapped
    to Sigma's optional top-level `fields` attribute because
    those two concepts are not equivalent.
    """

    detection = dict(
        record.get("detection")
        or {}
    )

    detection["condition"] = record.get(
        "condition"
    )

    rule = {
        "title": record.get("title"),
        "id": record.get("rule_id"),
        "logsource": record.get("logsource") or {},
        "detection": detection,
    }

    optional_fields = {
        "status": record.get("status"),
        "description": record.get("description"),
        "author": record.get("author"),
        "falsepositives": record.get("falsepositives"),
        "level": record.get("level"),
        "tags": record.get("tags"),
    }

    for key, value in optional_fields.items():
        if value not in (
            None,
            "",
            [],
            {},
        ):
            rule[key] = value

    return rule


def stringify_error(error) -> str:
    try:
        return str(error)
    except Exception:
        return repr(error)


def get_issue_severity(issue) -> str:
    severity = getattr(
        issue,
        "severity",
        None,
    )

    if severity is None:
        return ""

    name = getattr(
        severity,
        "name",
        None,
    )

    if name:
        return str(name).lower()

    return str(severity)


records = read_jsonl(INPUT)

if len(records) != 3780:
    raise RuntimeError(
        f"Expected 3780 accepted Sigma records, found {len(records)}"
    )


# ---------------------------------------------------------
# Phase A: pySigma parse compatibility
# ---------------------------------------------------------

compat_rows = []

parsed_rules = []
rule_id_to_record = {}

parse_failures = []


for record in records:

    rule_id = str(
        record.get("rule_id")
        or ""
    )

    lineage = (
        record.get("lineage")
        or {}
    )

    source_file = str(
        lineage.get("source_file")
        or ""
    )

    reconstructed = reconstruct_sigma_rule(
        record
    )

    parse_status = ""
    parse_error_count = 0
    parse_errors = []
    exception_type = ""
    exception_message = ""

    parsed_rule = None

    try:
        # pySigma may represent recognized parsing problems
        # on the rule object itself depending on the error.
        parsed_rule = SigmaRule.from_dict(
            reconstructed
        )

        object_errors = list(
            getattr(
                parsed_rule,
                "errors",
                [],
            )
            or []
        )

        parse_errors = [
            stringify_error(error)
            for error in object_errors
        ]

        parse_error_count = len(
            parse_errors
        )

        if parse_error_count:
            parse_status = (
                "parsed_with_parse_errors"
            )
        else:
            parse_status = (
                "parsed_clean"
            )

    except Exception as exc:

        parse_status = "parse_failed"
        exception_type = type(exc).__name__
        exception_message = str(exc)

        parse_failures.append(
            {
                "rule_id": rule_id,
                "title": record.get(
                    "title",
                    "",
                ),
                "source_file": source_file,
                "exception_type":
                    exception_type,
                "exception_message":
                    exception_message,
            }
        )

    if parsed_rule is not None:

        parsed_rules.append(
            parsed_rule
        )

        rule_id_to_record[
            str(parsed_rule.id)
        ] = record

    compat_rows.append(
        {
            "rule_id":
                rule_id,

            "title":
                record.get(
                    "title",
                    "",
                ),

            "source_file":
                source_file,

            "original_validation_status":
                (
                    record
                    .get(
                        "validation",
                        {}
                    )
                    .get(
                        "status",
                        ""
                    )
                ),

            "pysigma_version":
                version("pysigma"),

            "parse_status":
                parse_status,

            "parse_error_count":
                parse_error_count,

            "parse_errors":
                " | ".join(
                    parse_errors
                ),

            "exception_type":
                exception_type,

            "exception_message":
                exception_message,

            "core_validation_issue_count":
                0,

            "core_validation_error_count":
                0,

            "core_validation_warning_count":
                0,

            "core_validation_low_count":
                0,

            "compatibility_status":
                "",
        }
    )


# ---------------------------------------------------------
# Phase B: pySigma core validation
# ---------------------------------------------------------

validator = SigmaValidator(
    validators.values()
)

issues_by_rule_id = defaultdict(
    list
)

issue_rows = []


for parsed_rule in parsed_rules:

    try:
        issues = (
            validator.validate_rule(
                parsed_rule
            )
            or []
        )

    except Exception as exc:

        issues = []

        issue_rows.append(
            {
                "rule_id":
                    str(
                        parsed_rule.id
                    ),

                "title":
                    parsed_rule.title,

                "issue_type":
                    "ValidatorRuntimeException",

                "severity":
                    "runtime_error",

                "description":
                    str(exc),

                "phase":
                    "validate_rule",
            }
        )

        issues_by_rule_id[
            str(parsed_rule.id)
        ].append(
            {
                "type":
                    "ValidatorRuntimeException",

                "severity":
                    "runtime_error",

                "description":
                    str(exc),
            }
        )

        continue


    for issue in issues:

        issue_type = type(
            issue
        ).__name__

        severity = (
            get_issue_severity(
                issue
            )
        )

        description = (
            stringify_error(
                issue
            )
        )

        item = {
            "type":
                issue_type,

            "severity":
                severity,

            "description":
                description,
        }

        issues_by_rule_id[
            str(parsed_rule.id)
        ].append(item)

        issue_rows.append(
            {
                "rule_id":
                    str(
                        parsed_rule.id
                    ),

                "title":
                    parsed_rule.title,

                "issue_type":
                    issue_type,

                "severity":
                    severity,

                "description":
                    description,

                "phase":
                    "validate_rule",
            }
        )


# Stateful validators can emit additional issues
# during finalization, e.g. cross-rule checks.
try:

    final_issues = (
        validator.finalize()
        or []
    )

except Exception as exc:

    final_issues = []

    issue_rows.append(
        {
            "rule_id": "",
            "title": "",
            "issue_type":
                "ValidatorFinalizeException",
            "severity":
                "runtime_error",
            "description":
                str(exc),
            "phase":
                "finalize",
        }
    )


for issue in final_issues:

    issue_type = type(
        issue
    ).__name__

    severity = (
        get_issue_severity(
            issue
        )
    )

    description = (
        stringify_error(
            issue
        )
    )

    associated_rules = list(
        getattr(
            issue,
            "rules",
            [],
        )
        or []
    )

    if associated_rules:

        for sigma_rule in associated_rules:

            rid = str(
                sigma_rule.id
                or ""
            )

            issues_by_rule_id[
                rid
            ].append(
                {
                    "type":
                        issue_type,

                    "severity":
                        severity,

                    "description":
                        description,
                }
            )

            issue_rows.append(
                {
                    "rule_id":
                        rid,

                    "title":
                        sigma_rule.title,

                    "issue_type":
                        issue_type,

                    "severity":
                        severity,

                    "description":
                        description,

                    "phase":
                        "finalize",
                }
            )

    else:

        issue_rows.append(
            {
                "rule_id": "",
                "title": "",
                "issue_type":
                    issue_type,
                "severity":
                    severity,
                "description":
                    description,
                "phase":
                    "finalize",
            }
        )


# ---------------------------------------------------------
# Merge validation results into compatibility table
# ---------------------------------------------------------

for row in compat_rows:

    rid = row["rule_id"]

    if row["parse_status"] == "parse_failed":

        row["compatibility_status"] = (
            "parse_failed"
        )

        continue

    issues = (
        issues_by_rule_id.get(
            rid,
            []
        )
    )

    severity_counts = Counter(
        item["severity"]
        for item in issues
    )

    row[
        "core_validation_issue_count"
    ] = len(issues)

    # Different pySigma releases can render severity
    # names slightly differently; retain raw issue CSV
    # and count common names here.
    row[
        "core_validation_error_count"
    ] = (
        severity_counts.get(
            "error",
            0,
        )
        +
        severity_counts.get(
            "high",
            0,
        )
        +
        severity_counts.get(
            "critical",
            0,
        )
        +
        severity_counts.get(
            "runtime_error",
            0,
        )
    )

    row[
        "core_validation_warning_count"
    ] = (
        severity_counts.get(
            "warning",
            0,
        )
        +
        severity_counts.get(
            "medium",
            0,
        )
    )

    row[
        "core_validation_low_count"
    ] = (
        severity_counts.get(
            "low",
            0,
        )
        +
        severity_counts.get(
            "info",
            0,
        )
        +
        severity_counts.get(
            "informational",
            0,
        )
    )

    if (
        row["parse_status"]
        == "parsed_with_parse_errors"
    ):

        row[
            "compatibility_status"
        ] = "parsed_with_parse_errors"

    elif issues:

        row[
            "compatibility_status"
        ] = "parsed_with_validation_issues"

    else:

        row[
            "compatibility_status"
        ] = "compatible_clean"


# ---------------------------------------------------------
# Write outputs
# ---------------------------------------------------------

compat_fields = [
    "rule_id",
    "title",
    "source_file",
    "original_validation_status",
    "pysigma_version",
    "parse_status",
    "parse_error_count",
    "parse_errors",
    "exception_type",
    "exception_message",
    "core_validation_issue_count",
    "core_validation_error_count",
    "core_validation_warning_count",
    "core_validation_low_count",
    "compatibility_status",
]


with COMPAT_OUTPUT.open(
    "w",
    encoding="utf-8",
    newline="",
) as f:

    writer = csv.DictWriter(
        f,
        fieldnames=compat_fields,
    )

    writer.writeheader()
    writer.writerows(
        compat_rows
    )


issue_fields = [
    "rule_id",
    "title",
    "issue_type",
    "severity",
    "description",
    "phase",
]


with ISSUES_OUTPUT.open(
    "w",
    encoding="utf-8",
    newline="",
) as f:

    writer = csv.DictWriter(
        f,
        fieldnames=issue_fields,
    )

    writer.writeheader()
    writer.writerows(
        issue_rows
    )


# ---------------------------------------------------------
# Quality summary
# ---------------------------------------------------------

parse_status_counts = Counter(
    row["parse_status"]
    for row in compat_rows
)

compatibility_counts = Counter(
    row["compatibility_status"]
    for row in compat_rows
)

issue_type_counts = Counter(
    row["issue_type"]
    for row in issue_rows
)

severity_counts = Counter(
    row["severity"]
    for row in issue_rows
)


duplicate_rule_ids = [
    rid
    for rid, count in Counter(
        row["rule_id"]
        for row in compat_rows
    ).items()
    if rid and count > 1
]


parsed_count = sum(
    1
    for row in compat_rows
    if row["parse_status"]
    != "parse_failed"
)


summary = {
    "artifact":
        "Sigma pySigma Compatibility Gate",

    "artifact_version":
        "1.0.0",

    "pysigma_version":
        version("pysigma"),

    "input_prepared_rules":
        len(records),

    "parsed_rule_objects":
        parsed_count,

    "parse_failed_rules":
        parse_status_counts.get(
            "parse_failed",
            0,
        ),

    "parsed_with_parse_errors":
        parse_status_counts.get(
            "parsed_with_parse_errors",
            0,
        ),

    "parsed_clean":
        parse_status_counts.get(
            "parsed_clean",
            0,
        ),

    "compatible_clean_rules":
        compatibility_counts.get(
            "compatible_clean",
            0,
        ),

    "rules_with_validation_issues":
        compatibility_counts.get(
            "parsed_with_validation_issues",
            0,
        ),

    "validation_issue_rows":
        len(issue_rows),

    "issue_severity_counts":
        dict(
            sorted(
                severity_counts.items()
            )
        ),

    "top_issue_types":
        dict(
            issue_type_counts.most_common(
                20
            )
        ),

    "duplicate_rule_ids":
        len(
            duplicate_rule_ids
        ),

    "source_yaml_validation_scope":
        (
            "prepared-record reconstruction; "
            "original Sigma source repository was "
            "not present at the inspected raw paths"
        ),

    "important_note":
        (
            "pySigma validation issues are review signals. "
            "They do not automatically imply quarantine. "
            "Parse failures are treated separately."
        ),

    "status":
        (
            "PASS"
            if (
                len(records) == 3780
                and
                parsed_count
                + parse_status_counts.get(
                    "parse_failed",
                    0,
                )
                == 3780
                and
                len(
                    duplicate_rule_ids
                )
                == 0
            )
            else "FAIL"
        ),
}


with SUMMARY_OUTPUT.open(
    "w",
    encoding="utf-8",
) as f:

    json.dump(
        summary,
        f,
        indent=2,
    )


print(
    json.dumps(
        summary,
        indent=2,
    )
)

print()
print(
    f"Compatibility: {COMPAT_OUTPUT}"
)
print(
    f"Issues:        {ISSUES_OUTPUT}"
)
print(
    f"Summary:       {SUMMARY_OUTPUT}"
)
