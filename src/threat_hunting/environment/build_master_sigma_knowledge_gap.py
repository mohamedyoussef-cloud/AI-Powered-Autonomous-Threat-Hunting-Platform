import csv
import json
import math
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]

MASTER_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "environment"
    / "master_telemetry_eligibility_v0_1.csv"
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
    / "environment"
)

REPORT_DIR = (
    PROJECT_ROOT
    / "reports"
    / "environment"
)

CSV_OUTPUT = (
    OUTPUT_DIR
    / "master_sigma_knowledge_gap_v0_1.csv"
)

JSONL_OUTPUT = (
    OUTPUT_DIR
    / "master_sigma_knowledge_gap_v0_1.jsonl"
)

REPORT_OUTPUT = (
    REPORT_DIR
    / "master_sigma_knowledge_gap_v0_1_summary.json"
)


def read_csv(path):
    with path.open(
        "r",
        encoding="utf-8-sig",
        newline=""
    ) as f:
        return list(csv.DictReader(f))


def read_jsonl(path):
    rows = []

    with path.open(
        "r",
        encoding="utf-8"
    ) as f:
        for line_number, line in enumerate(f, start=1):
            line = line.strip()

            if not line:
                continue

            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    f"Invalid JSON line {line_number}: {exc}"
                ) from exc

    return rows


def classify_gap(score):
    if score >= 80:
        return "critical"

    if score >= 60:
        return "high"

    if score >= 40:
        return "medium"

    if score >= 20:
        return "low"

    return "minimal"


def main():
    if not MASTER_FILE.exists():
        raise FileNotFoundError(
            f"Missing master file: {MASTER_FILE}"
        )

    if not SIGMA_FILE.exists():
        raise FileNotFoundError(
            f"Missing Sigma file: {SIGMA_FILE}"
        )

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    master_rows = read_csv(
        MASTER_FILE
    )

    sigma_rules = read_jsonl(
        SIGMA_FILE
    )

    master_ids = {
        row["technique_id"]
        for row in master_rows
    }

    sigma_counts = Counter()

    sigma_rules_with_attack = 0

    for rule in sigma_rules:
        techniques = rule.get(
            "attack_techniques",
            []
        ) or []

        if techniques:
            sigma_rules_with_attack += 1

        seen_in_rule = set()

        for technique_id in techniques:
            technique_id = str(
                technique_id
            ).strip()

            if (
                technique_id in master_ids
                and technique_id not in seen_in_rule
            ):
                sigma_counts[
                    technique_id
                ] += 1

                seen_in_rule.add(
                    technique_id
                )

    max_rule_count = max(
        sigma_counts.values(),
        default=0
    )

    output_rows = []

    gap_class_counts = Counter()

    zero_rule_count = 0

    for master in master_rows:
        technique_id = master[
            "technique_id"
        ]

        rule_count = sigma_counts.get(
            technique_id,
            0
        )

        if rule_count == 0:
            zero_rule_count += 1

        if max_rule_count > 0:
            coverage_score = (
                100
                * math.log1p(rule_count)
                / math.log1p(max_rule_count)
            )
        else:
            coverage_score = 0.0

        gap_score = (
            100.0 - coverage_score
        )

        gap_score = round(
            gap_score,
            2
        )

        coverage_score = round(
            coverage_score,
            2
        )

        gap_class = classify_gap(
            gap_score
        )

        gap_class_counts[
            gap_class
        ] += 1

        output_rows.append({
            "technique_id": technique_id,
            "technique_name": master[
                "technique_name"
            ],
            "platform_eligible": master[
                "platform_eligible"
            ],
            "current_hunt_eligible": master[
                "current_hunt_eligible"
            ],
            "sigma_rule_count": rule_count,
            "sigma_knowledge_coverage_score": (
                coverage_score
            ),
            "sigma_detection_knowledge_gap_score": (
                gap_score
            ),
            "sigma_detection_knowledge_gap_class": (
                gap_class
            ),
            "gap_source": (
                "prepared_sigma_corpus_proxy"
            ),
            "is_client_detection_coverage": False,
            "product_scope": "master_catalog"
        })

    output_rows.sort(
        key=lambda row: row["technique_id"]
    )

    validation_errors = []

    if len(master_rows) != 697:
        validation_errors.append(
            "Master catalog does not contain 697 techniques"
        )

    if len(output_rows) != 697:
        validation_errors.append(
            "Output does not contain 697 techniques"
        )

    if not sigma_rules:
        validation_errors.append(
            "Sigma corpus is empty"
        )

    validation = (
        "PASS"
        if not validation_errors
        else "FAIL"
    )

    fields = [
        "technique_id",
        "technique_name",
        "platform_eligible",
        "current_hunt_eligible",
        "sigma_rule_count",
        "sigma_knowledge_coverage_score",
        "sigma_detection_knowledge_gap_score",
        "sigma_detection_knowledge_gap_class",
        "gap_source",
        "is_client_detection_coverage",
        "product_scope"
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
        writer.writerows(
            output_rows
        )

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

    report = {
        "component": (
            "master_sigma_detection_knowledge_gap"
        ),
        "version": "0.1",
        "product_mode": True,
        "master_catalog_techniques": len(
            master_rows
        ),
        "sigma_rules_valid": len(
            sigma_rules
        ),
        "sigma_rules_with_attack_mapping": (
            sigma_rules_with_attack
        ),
        "techniques_with_zero_sigma_rules": (
            zero_rule_count
        ),
        "max_sigma_rule_count": (
            max_rule_count
        ),
        "gap_class_counts": dict(
            gap_class_counts
        ),
        "gap_interpretation": (
            "Sigma detection-knowledge gap proxy. "
            "This is not deployed client detection coverage."
        ),
        "validation_errors": (
            validation_errors
        ),
        "status": validation
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
        "Master Sigma Knowledge Gap v0.1"
    )
    print(
        "-------------------------------"
    )

    print(
        f"Master techniques       : "
        f"{len(master_rows)}"
    )

    print(
        f"Valid Sigma rules       : "
        f"{len(sigma_rules)}"
    )

    print(
        f"ATT&CK-mapped rules     : "
        f"{sigma_rules_with_attack}"
    )

    print(
        f"Zero-rule techniques    : "
        f"{zero_rule_count}"
    )

    print(
        f"Max Sigma rule count    : "
        f"{max_rule_count}"
    )

    print()

    print("Gap classes:")

    for key in [
        "critical",
        "high",
        "medium",
        "low",
        "minimal"
    ]:
        print(
            f"  {key:<10}: "
            f"{gap_class_counts.get(key, 0)}"
        )

    print()

    print(
        f"Validation              : "
        f"{validation}"
    )

    print()
    print(f"CSV    : {CSV_OUTPUT}")
    print(f"JSONL  : {JSONL_OUTPUT}")
    print(f"Report : {REPORT_OUTPUT}")


if __name__ == "__main__":
    main()