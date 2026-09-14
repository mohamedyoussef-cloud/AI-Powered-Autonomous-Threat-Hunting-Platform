import csv
import json
import math
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]

INPUT_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "phase3"
    / "sigma_detection_coverage_profile.csv"
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

CSV_OUTPUT = OUTPUT_DIR / "sigma_detection_gap_proxy.csv"
JSONL_OUTPUT = OUTPUT_DIR / "sigma_detection_gap_proxy.jsonl"
SUMMARY_OUTPUT = REPORT_DIR / "sigma_detection_gap_proxy_summary.json"


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
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    with INPUT_FILE.open(
        "r",
        encoding="utf-8-sig",
        newline=""
    ) as f:
        rows = list(csv.DictReader(f))

    counts = [
        int(row["sigma_rule_count"])
        for row in rows
    ]

    max_count = max(counts) if counts else 0

    output_rows = []
    class_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "minimal": 0,
    }

    for row in rows:
        count = int(row["sigma_rule_count"])

        if max_count == 0:
            coverage_score = 0.0
        else:
            coverage_score = (
                math.log1p(count)
                / math.log1p(max_count)
            ) * 100.0

        coverage_score = round(coverage_score, 4)
        gap_score = round(100.0 - coverage_score, 4)

        gap_class = classify_gap(gap_score)
        class_counts[gap_class] += 1

        output_rows.append({
            "technique_id": row["technique_id"],
            "technique_name": row["technique_name"],
            "sigma_rule_count": count,
            "coverage_basis": "sigma_corpus_proxy",
            "sigma_knowledge_coverage_score": coverage_score,
            "detection_gap_proxy_score": gap_score,
            "detection_gap_proxy_class": gap_class,
            "has_sigma_detection_knowledge": (
                str(
                    row["has_sigma_detection_knowledge"]
                ).strip().lower() == "true"
            ),
        })

    validation = "PASS"

    if len(output_rows) != len(rows):
        validation = "FAIL"

    for row in output_rows:
        score = row["detection_gap_proxy_score"]

        if not 0 <= score <= 100:
            validation = "FAIL"

    fields = [
        "technique_id",
        "technique_name",
        "sigma_rule_count",
        "coverage_basis",
        "sigma_knowledge_coverage_score",
        "detection_gap_proxy_score",
        "detection_gap_proxy_class",
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
        writer.writerows(output_rows)

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

    summary = {
        "phase": 3,
        "component": "sigma_detection_knowledge_gap_proxy",
        "basis": (
            "Valid Sigma corpus mapped to ATT&CK. "
            "This is not client deployed detection coverage."
        ),
        "formula": (
            "coverage = "
            "100 * log1p(rule_count) / log1p(max_rule_count); "
            "gap = 100 - coverage"
        ),
        "input_records": len(rows),
        "maximum_sigma_rule_count": max_count,
        "critical_gap": class_counts["critical"],
        "high_gap": class_counts["high"],
        "medium_gap": class_counts["medium"],
        "low_gap": class_counts["low"],
        "minimal_gap": class_counts["minimal"],
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

    print(f"Input techniques          : {len(rows)}")
    print(f"Max Sigma rule count      : {max_count}")
    print()
    print(f"Critical gap              : {class_counts['critical']}")
    print(f"High gap                  : {class_counts['high']}")
    print(f"Medium gap                : {class_counts['medium']}")
    print(f"Low gap                   : {class_counts['low']}")
    print(f"Minimal gap               : {class_counts['minimal']}")
    print()
    print(f"Validation                : {validation}")
    print()
    print(f"CSV    : {CSV_OUTPUT}")
    print(f"JSONL  : {JSONL_OUTPUT}")
    print(f"Report : {SUMMARY_OUTPUT}")


if __name__ == "__main__":
    main()