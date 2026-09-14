import csv
import json
from pathlib import Path
from statistics import mean


PROJECT_ROOT = Path(__file__).resolve().parents[3]

INPUT_FILE = (
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

CSV_OUTPUT = OUTPUT_DIR / "telemetry_readiness_scores.csv"
JSONL_OUTPUT = OUTPUT_DIR / "telemetry_readiness_scores.jsonl"
SUMMARY_OUTPUT = REPORT_DIR / "telemetry_readiness_summary.json"


COMPONENT_WEIGHT = 0.30
EXACT_EVENT_WEIGHT = 0.70


def to_float(value):
    if value in (None, ""):
        return None
    return float(value)


def classify_score(score):
    if score is None:
        return "unknown"
    if score >= 80:
        return "high"
    if score >= 50:
        return "medium"
    return "low"


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"Telemetry eligibility file not found: {INPUT_FILE}"
        )

    with INPUT_FILE.open(
        "r",
        encoding="utf-8-sig",
        newline=""
    ) as f:
        rows = list(csv.DictReader(f))

    output_rows = []
    numeric_scores = []

    high = 0
    medium = 0
    low = 0
    unknown = 0

    for row in rows:
        status = row["telemetry_evidence_status"]

        component_pct = to_float(
            row["component_evidence_coverage_pct"]
        )

        exact_pct = to_float(
            row["exact_event_component_coverage_pct"]
        )

        if status == "requirement_unspecified":
            score = None

        elif status == "not_observed":
            score = 0.0

        else:
            component_pct = component_pct or 0.0
            exact_pct = exact_pct or 0.0

            score = (
                COMPONENT_WEIGHT * component_pct
                + EXACT_EVENT_WEIGHT * exact_pct
            )

            score = round(score, 4)

        readiness_class = classify_score(score)

        if readiness_class == "high":
            high += 1
        elif readiness_class == "medium":
            medium += 1
        elif readiness_class == "low":
            low += 1
        else:
            unknown += 1

        if score is not None:
            numeric_scores.append(score)

        output = {
            "technique_id": row["technique_id"],
            "technique_name": row["technique_name"],
            "telemetry_evidence_status": status,
            "telemetry_class": row["telemetry_class"],
            "component_evidence_coverage_pct": component_pct,
            "exact_event_component_coverage_pct": exact_pct,
            "evidence_sources": row["evidence_sources"],
            "telemetry_readiness_score": score,
            "telemetry_readiness_class": readiness_class,
        }

        output_rows.append(output)

    validation = "PASS"

    if len(output_rows) != len(rows):
        validation = "FAIL"

    for row in output_rows:
        score = row["telemetry_readiness_score"]

        if score is not None and not (0 <= score <= 100):
            validation = "FAIL"

    fields = [
        "technique_id",
        "technique_name",
        "telemetry_evidence_status",
        "telemetry_class",
        "component_evidence_coverage_pct",
        "exact_event_component_coverage_pct",
        "evidence_sources",
        "telemetry_readiness_score",
        "telemetry_readiness_class",
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
        "component": "telemetry_readiness",
        "formula": (
            "0.30 * component_evidence_coverage_pct "
            "+ 0.70 * exact_event_component_coverage_pct"
        ),
        "input_records": len(rows),
        "output_records": len(output_rows),
        "high": high,
        "medium": medium,
        "low": low,
        "unknown": unknown,
        "minimum_score": (
            min(numeric_scores)
            if numeric_scores else None
        ),
        "maximum_score": (
            max(numeric_scores)
            if numeric_scores else None
        ),
        "mean_score": (
            round(mean(numeric_scores), 4)
            if numeric_scores else None
        ),
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

    print(f"Input techniques             : {len(rows)}")
    print(f"High readiness               : {high}")
    print(f"Medium readiness             : {medium}")
    print(f"Low readiness                : {low}")
    print(f"Unknown readiness            : {unknown}")

    if numeric_scores:
        print(f"Minimum score                : {min(numeric_scores):.2f}")
        print(f"Maximum score                : {max(numeric_scores):.2f}")
        print(f"Mean score                   : {mean(numeric_scores):.2f}")

    print(f"Validation                   : {validation}")
    print()
    print(f"CSV    : {CSV_OUTPUT}")
    print(f"JSONL  : {JSONL_OUTPUT}")
    print(f"Report : {SUMMARY_OUTPUT}")


if __name__ == "__main__":
    main()