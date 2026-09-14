import csv
import json
from collections import Counter, defaultdict
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]

PLATFORM_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "phase3"
    / "attack_platform_eligibility.csv"
)

SIGMA_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "detections"
    / "sigma_rules_valid.jsonl"
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

CSV_OUTPUT = OUTPUT_DIR / "sigma_detection_coverage_profile.csv"
JSONL_OUTPUT = OUTPUT_DIR / "sigma_detection_coverage_profile.jsonl"
SUMMARY_OUTPUT = REPORT_DIR / "sigma_detection_coverage_profile_summary.json"


def load_jsonl(path):
    rows = []

    with path.open("r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, start=1):
            line = line.strip()

            if not line:
                continue

            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    f"Invalid JSON at line {line_number}: {exc}"
                ) from exc

    return rows


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    with PLATFORM_FILE.open(
        "r",
        encoding="utf-8-sig",
        newline=""
    ) as f:
        platform_rows = list(csv.DictReader(f))

    eligible_rows = [
        row
        for row in platform_rows
        if row.get("platform_eligible", "").strip().lower() == "true"
    ]

    eligible_by_id = {
        row["technique_id"]: row
        for row in eligible_rows
    }

    sigma_rules = load_jsonl(SIGMA_FILE)

    rule_ids_by_technique = defaultdict(set)
    levels_by_technique = defaultdict(Counter)
    statuses_by_technique = defaultdict(Counter)

    mapped_sigma_rules = 0
    mapped_relationships = 0

    for rule in sigma_rules:
        techniques = rule.get("attack_techniques") or []

        if techniques:
            mapped_sigma_rules += 1

        rule_id = rule.get("rule_id")
        level = rule.get("level") or "unknown"
        status = rule.get("status") or "unknown"

        for technique_id in set(techniques):
            if technique_id not in eligible_by_id:
                continue

            rule_ids_by_technique[technique_id].add(rule_id)
            levels_by_technique[technique_id][level] += 1
            statuses_by_technique[technique_id][status] += 1
            mapped_relationships += 1

    output_rows = []

    zero_rules = 0
    one_rule = 0
    two_to_four = 0
    five_to_nine = 0
    ten_plus = 0

    for technique_id, platform_row in eligible_by_id.items():
        rule_count = len(rule_ids_by_technique[technique_id])

        if rule_count == 0:
            coverage_band = "0_rules"
            zero_rules += 1

        elif rule_count == 1:
            coverage_band = "1_rule"
            one_rule += 1

        elif rule_count <= 4:
            coverage_band = "2_4_rules"
            two_to_four += 1

        elif rule_count <= 9:
            coverage_band = "5_9_rules"
            five_to_nine += 1

        else:
            coverage_band = "10_plus_rules"
            ten_plus += 1

        output_rows.append(
            {
                "technique_id": technique_id,
                "technique_name": platform_row.get("name"),
                "sigma_rule_count": rule_count,
                "coverage_band": coverage_band,
                "sigma_levels": dict(
                    levels_by_technique[technique_id]
                ),
                "sigma_statuses": dict(
                    statuses_by_technique[technique_id]
                ),
                "has_sigma_detection_knowledge": rule_count > 0,
            }
        )

    validation = "PASS"

    if len(output_rows) != len(eligible_rows):
        validation = "FAIL"

    fields = [
        "technique_id",
        "technique_name",
        "sigma_rule_count",
        "coverage_band",
        "sigma_levels",
        "sigma_statuses",
        "has_sigma_detection_knowledge",
    ]

    with CSV_OUTPUT.open(
        "w",
        encoding="utf-8",
        newline=""
    ) as f:
        writer = csv.DictWriter(
            f,
            fieldnames=fields
        )
        writer.writeheader()

        for row in output_rows:
            csv_row = row.copy()
            csv_row["sigma_levels"] = json.dumps(
                csv_row["sigma_levels"],
                ensure_ascii=False,
                sort_keys=True
            )
            csv_row["sigma_statuses"] = json.dumps(
                csv_row["sigma_statuses"],
                ensure_ascii=False,
                sort_keys=True
            )

            writer.writerow(csv_row)

    with JSONL_OUTPUT.open(
        "w",
        encoding="utf-8",
        newline="\n"
    ) as f:
        for row in output_rows:
            f.write(
                json.dumps(
                    row,
                    ensure_ascii=False
                )
                + "\n"
            )

    counts = [
        row["sigma_rule_count"]
        for row in output_rows
    ]

    summary = {
        "phase": 3,
        "component": "sigma_detection_coverage_proxy",
        "platform_compatible_techniques": len(eligible_rows),
        "valid_sigma_rules": len(sigma_rules),
        "sigma_rules_with_attack_mapping": mapped_sigma_rules,
        "eligible_technique_rule_relationships": mapped_relationships,
        "techniques_with_zero_rules": zero_rules,
        "techniques_with_one_rule": one_rule,
        "techniques_with_2_4_rules": two_to_four,
        "techniques_with_5_9_rules": five_to_nine,
        "techniques_with_10_plus_rules": ten_plus,
        "minimum_rule_count": min(counts) if counts else None,
        "maximum_rule_count": max(counts) if counts else None,
        "status": validation,
    }

    with SUMMARY_OUTPUT.open(
        "w",
        encoding="utf-8"
    ) as f:
        json.dump(
            summary,
            f,
            indent=2,
            ensure_ascii=False
        )

    print(f"Platform-compatible techniques : {len(eligible_rows)}")
    print(f"Valid Sigma rules              : {len(sigma_rules)}")
    print(f"Sigma rules with ATT&CK map    : {mapped_sigma_rules}")
    print()
    print(f"0 Sigma rules                  : {zero_rules}")
    print(f"1 Sigma rule                   : {one_rule}")
    print(f"2-4 Sigma rules                : {two_to_four}")
    print(f"5-9 Sigma rules                : {five_to_nine}")
    print(f"10+ Sigma rules                : {ten_plus}")
    print()
    print(f"Minimum rule count             : {min(counts)}")
    print(f"Maximum rule count             : {max(counts)}")
    print(f"Validation                     : {validation}")
    print()
    print(f"CSV    : {CSV_OUTPUT}")
    print(f"JSONL  : {JSONL_OUTPUT}")
    print(f"Report : {SUMMARY_OUTPUT}")


if __name__ == "__main__":
    main()