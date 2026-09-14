from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

DETECTIONS = (
    ROOT
    / "data"
    / "processed"
    / "detections"
)

KNOWLEDGE = (
    ROOT
    / "data"
    / "processed"
    / "knowledge"
)

REPORTS = ROOT / "reports"


RULES_PATH = (
    DETECTIONS
    / "sigma_rules_valid.jsonl"
)

COMPAT_PATH = (
    DETECTIONS
    / "sigma_pysigma_compatibility.csv"
)

ISSUES_PATH = (
    REPORTS
    / "sigma_pysigma_validation_issues.csv"
)

ACTIVE_ATTACK = (
    KNOWLEDGE
    / "attack_techniques_active.jsonl"
)

INACTIVE_ATTACK = (
    KNOWLEDGE
    / "attack_techniques_inactive.jsonl"
)

OUTPUT = (
    REPORTS
    / "sigma_pysigma_triage.csv"
)

SUMMARY = (
    REPORTS
    / "sigma_pysigma_triage_summary.json"
)


def read_jsonl(path: Path):
    rows = []

    with path.open(
        "r",
        encoding="utf-8",
    ) as f:

        for line in f:
            if line.strip():
                rows.append(
                    json.loads(line)
                )

    return rows


rules = read_jsonl(RULES_PATH)
active = read_jsonl(ACTIVE_ATTACK)
inactive = read_jsonl(INACTIVE_ATTACK)

if len(rules) != 3780:
    raise RuntimeError(
        f"Expected 3780 Sigma rules, found {len(rules)}"
    )


valid_attack_ids = {
    row["technique_id"]
    for row in active + inactive
}


rules_by_id = {
    str(row["rule_id"]): row
    for row in rules
}


with COMPAT_PATH.open(
    "r",
    encoding="utf-8-sig",
    newline="",
) as f:
    compatibility = list(
        csv.DictReader(f)
    )


with ISSUES_PATH.open(
    "r",
    encoding="utf-8-sig",
    newline="",
) as f:
    issues = list(
        csv.DictReader(f)
    )


issues_by_rule = defaultdict(list)

for issue in issues:

    rid = issue["rule_id"]

    if rid:
        issues_by_rule[rid].append(
            issue
        )


KNOWN_RETAINABLE = {
    "EscapedWildcardIssue",
    "NumberAsStringIssue",
    "SpecificInsteadOfGenericLogsourceIssue",
    "InvalidATTACKTagIssue",
}


triage_rows = []


for compat in compatibility:

    rid = compat["rule_id"]

    rule = rules_by_id.get(rid)

    if rule is None:
        raise RuntimeError(
            f"Compatibility record references unknown rule: {rid}"
        )

    rule_issues = issues_by_rule.get(
        rid,
        []
    )

    issue_types = sorted({
        item["issue_type"]
        for item in rule_issues
    })

    severities = sorted({
        item["severity"]
        for item in rule_issues
    })

    attack_techniques = (
        rule.get(
            "attack_techniques"
        )
        or []
    )

    invalid_extracted_attack_ids = [
        tid
        for tid in attack_techniques
        if tid not in valid_attack_ids
    ]

    raw_tags = (
        rule.get("tags")
        or []
    )

    invalid_attack_tag_issue = (
        "InvalidATTACKTagIssue"
        in issue_types
    )

    unknown_issue_types = [
        issue_type
        for issue_type in issue_types
        if issue_type
        not in KNOWN_RETAINABLE
    ]

    parse_failed = (
        compat["parse_status"]
        == "parse_failed"
    )

    parse_errors = (
        compat["parse_status"]
        == "parsed_with_parse_errors"
    )

    # -------------------------------------
    # Decision
    # -------------------------------------

    if parse_failed or parse_errors:

        decision = "quarantine_candidate"

        rationale = (
            "pySigma parsing failed or returned "
            "parse-level errors."
        )

    elif invalid_extracted_attack_ids:

        decision = "manual_review_required"

        rationale = (
            "Prepared ATT&CK technique mapping "
            "contains an identifier not present "
            "in the prepared ATT&CK knowledge base."
        )

    elif unknown_issue_types:

        decision = "manual_review_required"

        rationale = (
            "pySigma emitted an issue type not "
            "covered by the approved triage policy."
        )

    elif not rule_issues:

        decision = "retain_clean"

        rationale = (
            "pySigma parsed the rule cleanly and "
            "reported no core validation issues."
        )

    elif invalid_attack_tag_issue:

        decision = "retain_with_metadata_warning"

        rationale = (
            "Raw Sigma ATT&CK tag warning is preserved, "
            "while extracted ATT&CK technique IDs remain "
            "valid against the prepared ATT&CK knowledge base."
        )

    elif (
        "SpecificInsteadOfGenericLogsourceIssue"
        in issue_types
    ):

        decision = "retain_with_logsource_warning"

        rationale = (
            "Rule is pySigma-compatible; issue concerns "
            "specific-versus-generic logsource modeling, "
            "not parsing failure."
        )

    else:

        decision = "retain_with_style_warning"

        rationale = (
            "Rule is pySigma-compatible; validation "
            "issues are retained as non-fatal review metadata."
        )


    triage_rows.append(
        {
            "rule_id":
                rid,

            "title":
                rule.get(
                    "title",
                    "",
                ),

            "source_file":
                (
                    rule
                    .get(
                        "lineage",
                        {}
                    )
                    .get(
                        "source_file",
                        ""
                    )
                ),

            "parse_status":
                compat[
                    "parse_status"
                ],

            "compatibility_status":
                compat[
                    "compatibility_status"
                ],

            "issue_count":
                len(
                    rule_issues
                ),

            "issue_types":
                " | ".join(
                    issue_types
                ),

            "issue_severities":
                " | ".join(
                    severities
                ),

            "raw_tags":
                " | ".join(
                    raw_tags
                ),

            "extracted_attack_techniques":
                " | ".join(
                    attack_techniques
                ),

            "invalid_extracted_attack_ids":
                " | ".join(
                    invalid_extracted_attack_ids
                ),

            "triage_decision":
                decision,

            "rationale":
                rationale,
        }
    )


fieldnames = [
    "rule_id",
    "title",
    "source_file",
    "parse_status",
    "compatibility_status",
    "issue_count",
    "issue_types",
    "issue_severities",
    "raw_tags",
    "extracted_attack_techniques",
    "invalid_extracted_attack_ids",
    "triage_decision",
    "rationale",
]


with OUTPUT.open(
    "w",
    encoding="utf-8",
    newline="",
) as f:

    writer = csv.DictWriter(
        f,
        fieldnames=fieldnames,
    )

    writer.writeheader()
    writer.writerows(
        triage_rows
    )


decision_counts = Counter(
    row["triage_decision"]
    for row in triage_rows
)


quarantine_candidates = (
    decision_counts.get(
        "quarantine_candidate",
        0,
    )
)

manual_review = (
    decision_counts.get(
        "manual_review_required",
        0,
    )
)

invalid_attack_mappings = sum(
    1
    for row in triage_rows
    if row[
        "invalid_extracted_attack_ids"
    ]
)


summary = {
    "artifact":
        "Sigma pySigma Issue Triage",

    "artifact_version":
        "1.0.0",

    "input_rules":
        len(rules),

    "rules_with_pysigma_issues":
        len(
            issues_by_rule
        ),

    "issue_rows":
        len(issues),

    "decision_counts":
        dict(
            sorted(
                decision_counts.items()
            )
        ),

    "invalid_extracted_attack_mapping_rules":
        invalid_attack_mappings,

    "quarantine_candidates":
        quarantine_candidates,

    "manual_review_required":
        manual_review,

    "policy": {
        "parse_failure":
            "quarantine_candidate",

        "invalid_prepared_attack_mapping":
            "manual_review_required",

        "known_pysigma_non_parse_issue":
            "retain_with_warning",

        "clean_parse_and_validation":
            "retain_clean",
    },

    "status": (
        "PASS"
        if (
            len(rules) == 3780
            and
            len(triage_rows) == 3780
            and
            quarantine_candidates == 0
            and
            manual_review == 0
            and
            invalid_attack_mappings == 0
        )
        else "FAIL"
    ),
}


with SUMMARY.open(
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
print(f"Triage:  {OUTPUT}")
print(f"Summary: {SUMMARY}")
