import csv
import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]

TELEMETRY_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "phase3"
    / "telemetry_readiness_scores.csv"
)

GAP_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "phase3"
    / "sigma_detection_gap_proxy.csv"
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

CSV_OUTPUT = OUTPUT_DIR / "technique_prioritization_v0_1.csv"
JSONL_OUTPUT = OUTPUT_DIR / "technique_prioritization_v0_1.jsonl"
SUMMARY_OUTPUT = REPORT_DIR / "technique_prioritization_v0_1_summary.json"


TELEMETRY_WEIGHT = 0.50
DETECTION_GAP_WEIGHT = 0.50


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

    telemetry_rows = read_csv(TELEMETRY_FILE)
    gap_rows = read_csv(GAP_FILE)

    telemetry_by_id = {
        row["technique_id"]: row
        for row in telemetry_rows
    }

    gap_by_id = {
        row["technique_id"]: row
        for row in gap_rows
    }

    telemetry_ids = set(telemetry_by_id)
    gap_ids = set(gap_by_id)

    missing_in_telemetry = sorted(gap_ids - telemetry_ids)
    missing_in_gap = sorted(telemetry_ids - gap_ids)

    common_ids = sorted(
        telemetry_ids.intersection(gap_ids)
    )

    rows = []

    for technique_id in common_ids:
        telemetry = telemetry_by_id[technique_id]
        gap = gap_by_id[technique_id]

        telemetry_score = float(
            telemetry["telemetry_readiness_score"]
        )

        gap_score = float(
            gap["detection_gap_proxy_score"]
        )

        priority_score = (
            TELEMETRY_WEIGHT * telemetry_score
            + DETECTION_GAP_WEIGHT * gap_score
        )

        priority_score = round(priority_score, 4)

        if telemetry_score >= gap_score:
            primary_driver = "telemetry_readiness"
        else:
            primary_driver = "detection_gap"

        explanation = (
            f"Telemetry readiness={telemetry_score:.2f}; "
            f"Sigma detection-knowledge gap={gap_score:.2f}; "
            f"lab baseline weights="
            f"{TELEMETRY_WEIGHT:.2f}/{DETECTION_GAP_WEIGHT:.2f}."
        )

        rows.append({
            "technique_id": technique_id,
            "technique_name": telemetry["technique_name"],
            "platform_eligible": True,

            "telemetry_readiness_score": telemetry_score,
            "telemetry_readiness_class": (
                telemetry["telemetry_readiness_class"]
            ),

            "sigma_rule_count": int(
                gap["sigma_rule_count"]
            ),

            "detection_gap_proxy_score": gap_score,
            "detection_gap_proxy_class": (
                gap["detection_gap_proxy_class"]
            ),

            "asset_criticality_score": None,
            "incident_history_relevance_score": None,

            "priority_score": priority_score,
            "primary_driver": primary_driver,
            "explanation": explanation,
        })

    rows.sort(
        key=lambda row: (
            -row["priority_score"],
            -row["detection_gap_proxy_score"],
            -row["telemetry_readiness_score"],
            row["technique_id"],
        )
    )

    for rank, row in enumerate(rows, start=1):
        row["rank"] = rank

    validation = "PASS"

    if missing_in_telemetry:
        validation = "FAIL"

    if missing_in_gap:
        validation = "FAIL"

    if len(rows) != 474:
        validation = "FAIL"

    for row in rows:
        score = row["priority_score"]

        if not 0 <= score <= 100:
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
        writer.writerows(rows)

    with JSONL_OUTPUT.open(
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

    summary = {
        "phase": 3,
        "component": "technique_prioritization_v0_1",
        "mode": "lab_baseline",
        "platform_compatibility": "hard_gate",
        "weights": {
            "telemetry_readiness": TELEMETRY_WEIGHT,
            "detection_knowledge_gap_proxy": (
                DETECTION_GAP_WEIGHT
            ),
        },
        "unavailable_parameters": [
            "asset_criticality",
            "incident_history_relevance",
        ],
        "input_telemetry_records": len(
            telemetry_rows
        ),
        "input_gap_records": len(gap_rows),
        "ranked_techniques": len(rows),
        "missing_in_telemetry": missing_in_telemetry,
        "missing_in_gap": missing_in_gap,
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
        f"Telemetry records          : "
        f"{len(telemetry_rows)}"
    )
    print(
        f"Detection-gap records      : "
        f"{len(gap_rows)}"
    )
    print(
        f"Ranked techniques          : "
        f"{len(rows)}"
    )
    print(
        f"Missing telemetry records  : "
        f"{len(missing_in_telemetry)}"
    )
    print(
        f"Missing gap records        : "
        f"{len(missing_in_gap)}"
    )
    print(
        f"Validation                 : "
        f"{validation}"
    )

    print()
    print("Top 10 Techniques")
    print("-----------------")

    for row in rows[:10]:
        print(
            f"#{row['rank']:>3} "
            f"{row['technique_id']:<10} "
            f"{row['priority_score']:>6.2f} "
            f"{row['technique_name']}"
        )

    print()
    print(f"CSV    : {CSV_OUTPUT}")
    print(f"JSONL  : {JSONL_OUTPUT}")
    print(f"Report : {SUMMARY_OUTPUT}")


if __name__ == "__main__":
    main()