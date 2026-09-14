import csv
import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]

PRIORITY_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "phase3"
    / "technique_prioritization_v0_1.csv"
)

TELEMETRY_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "phase3"
    / "attack_telemetry_eligibility.csv"
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

CSV_OUTPUT = OUTPUT_DIR / "technique_prioritization_v0_2.csv"
JSONL_OUTPUT = OUTPUT_DIR / "technique_prioritization_v0_2.jsonl"
SUMMARY_OUTPUT = REPORT_DIR / "technique_prioritization_v0_2_summary.json"


def read_csv(path):
    with path.open(
        "r",
        encoding="utf-8-sig",
        newline=""
    ) as f:
        return list(csv.DictReader(f))


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    priority_rows = read_csv(PRIORITY_FILE)
    telemetry_rows = read_csv(TELEMETRY_FILE)

    telemetry_by_id = {
        row["technique_id"]: row
        for row in telemetry_rows
    }

    output_rows = []
    missing = []

    for row in priority_rows:
        technique_id = row["technique_id"]
        telemetry = telemetry_by_id.get(technique_id)

        if telemetry is None:
            missing.append(technique_id)
            continue

        evidence_sources = [
            value.strip()
            for value in (
                telemetry.get("evidence_sources") or ""
            ).split("|")
            if value.strip()
        ]

        output = dict(row)

        output["exact_evidence_components"] = int(
            float(
                telemetry[
                    "data_components_with_exact_event_evidence"
                ]
                or 0
            )
        )

        output["data_components_referenced"] = int(
            float(
                telemetry[
                    "data_components_referenced"
                ]
                or 0
            )
        )

        output["evidence_source_count"] = len(
            set(evidence_sources)
        )

        output["evidence_sources"] = "|".join(
            sorted(set(evidence_sources))
        )

        output_rows.append(output)

    output_rows.sort(
        key=lambda row: (
            -float(row["priority_score"]),
            -int(row["exact_evidence_components"]),
            -int(row["evidence_source_count"]),
            row["technique_id"],
        )
    )

    for rank, row in enumerate(
        output_rows,
        start=1
    ):
        row["rank"] = rank

    validation = "PASS"

    if missing:
        validation = "FAIL"

    if len(output_rows) != 474:
        validation = "FAIL"

    fields = [
        "rank",
        "technique_id",
        "technique_name",
        "platform_eligible",
        "telemetry_readiness_score",
        "telemetry_readiness_class",
        "sigma_rule_count",
        "detection_gap_proxy_score",
        "detection_gap_proxy_class",
        "asset_criticality_score",
        "incident_history_relevance_score",
        "priority_score",
        "exact_evidence_components",
        "data_components_referenced",
        "evidence_source_count",
        "evidence_sources",
        "primary_driver",
        "explanation",
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
        "component": "technique_prioritization_v0_2",
        "ranking_logic": [
            "priority_score descending",
            "exact_evidence_components descending",
            "evidence_source_count descending",
            "technique_id deterministic fallback"
        ],
        "tie_breaker_changes_score": False,
        "ranked_techniques": len(output_rows),
        "missing_records": missing,
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

    print(
        f"Ranked techniques        : "
        f"{len(output_rows)}"
    )
    print(
        f"Missing records          : "
        f"{len(missing)}"
    )
    print(
        f"Validation               : "
        f"{validation}"
    )

    print()
    print("Top 15 Techniques - v0.2")
    print("------------------------")

    for row in output_rows[:15]:
        print(
            f"#{row['rank']:>3} "
            f"{row['technique_id']:<10} "
            f"Score={float(row['priority_score']):>6.2f} "
            f"Exact={row['exact_evidence_components']:>2} "
            f"Sources={row['evidence_source_count']} "
            f"{row['technique_name']}"
        )

    print()
    print(f"CSV    : {CSV_OUTPUT}")
    print(f"JSONL  : {JSONL_OUTPUT}")
    print(f"Report : {SUMMARY_OUTPUT}")


if __name__ == "__main__":
    main()