import csv
import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]

RANKING_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "phase3"
    / "technique_prioritization_v0_3.csv"
)

ATTACK_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "knowledge"
    / "attack_techniques_active.jsonl"
)

TELEMETRY_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "phase3"
    / "attack_telemetry_eligibility.csv"
)

PROFILE_FILE = (
    PROJECT_ROOT
    / "config"
    / "phase3"
    / "environment_profile.lab.json"
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

OUTPUT_FILE = OUTPUT_DIR / "hypothesis_context_all_474.jsonl"
SUMMARY_FILE = REPORT_DIR / "hypothesis_context_all_474_summary.json"

TOP_N = 474


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


def to_float(value):
    if value in (None, ""):
        return None
    return float(value)


def to_int(value):
    if value in (None, ""):
        return 0
    return int(float(value))


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    ranking = read_csv(RANKING_FILE)
    attack = read_jsonl(ATTACK_FILE)
    telemetry = read_csv(TELEMETRY_FILE)

    with PROFILE_FILE.open(
        "r",
        encoding="utf-8"
    ) as f:
        profile = json.load(f)

    attack_by_id = {
        row["technique_id"]: row
        for row in attack
    }

    telemetry_by_id = {
        row["technique_id"]: row
        for row in telemetry
    }

    top_rows = sorted(
        ranking,
        key=lambda row: int(row["rank"])
    )[:TOP_N]

    contexts = []
    missing_attack = []
    missing_telemetry = []

    for ranked in top_rows:
        technique_id = ranked["technique_id"]

        technique = attack_by_id.get(technique_id)
        tel = telemetry_by_id.get(technique_id)

        if technique is None:
            missing_attack.append(technique_id)
            continue

        if tel is None:
            missing_telemetry.append(technique_id)
            continue

        context = {
            "context_version": "0.1",

            "environment": {
                "environment_id": profile.get(
                    "environment_id"
                ),
                "environment_name": profile.get(
                    "environment_name"
                ),
                "platforms": profile.get(
                    "platforms",
                    []
                ),
                "asset_criticality_available": bool(
                    profile.get("assets")
                ),
                "incident_history_available": bool(
                    profile.get("incident_history")
                ),
                "detection_coverage_available": bool(
                    profile.get("detection_coverage")
                ),
            },

            "technique": {
                "technique_id": technique_id,
                "name": technique.get("name"),
                "description": technique.get(
                    "description"
                ),
                "tactics": technique.get(
                    "tactics",
                    []
                ),
                "platforms": technique.get(
                    "platforms",
                    []
                ),
                "is_subtechnique": technique.get(
                    "is_subtechnique",
                    False
                ),
                "parent_technique_id": technique.get(
                    "parent_technique_id"
                ),
                "data_components": technique.get(
                    "data_components",
                    []
                ),
            },

            "prioritization": {
                "rank": int(ranked["rank"]),
                "priority_score": to_float(
                    ranked["priority_score"]
                ),
                "telemetry_readiness_score": to_float(
                    ranked[
                        "telemetry_readiness_score"
                    ]
                ),
                "telemetry_readiness_class": ranked[
                    "telemetry_readiness_class"
                ],
                "detection_gap_proxy_score": to_float(
                    ranked[
                        "detection_gap_proxy_score"
                    ]
                ),
                "detection_gap_proxy_class": ranked[
                    "detection_gap_proxy_class"
                ],
                "sigma_rule_count": to_int(
                    ranked["sigma_rule_count"]
                ),
                "asset_criticality_score": None,
                "incident_history_relevance_score": None,
                "ranking_mode": (
                    "lab_evidence_baseline"
                ),
            },

            "telemetry_evidence": {
                "status": tel.get(
                    "telemetry_evidence_status"
                ),
                "component_coverage_pct": to_float(
                    tel.get(
                        "component_evidence_coverage_pct"
                    )
                ),
                "exact_event_component_coverage_pct": (
                    to_float(
                        tel.get(
                            "exact_event_component_coverage_pct"
                        )
                    )
                ),
                "data_components_referenced": to_int(
                    tel.get(
                        "data_components_referenced"
                    )
                ),
                "data_components_with_any_evidence": (
                    to_int(
                        tel.get(
                            "data_components_with_any_evidence"
                        )
                    )
                ),
                "data_components_with_exact_event_evidence": (
                    to_int(
                        tel.get(
                            "data_components_with_exact_event_evidence"
                        )
                    )
                ),
                "evidence_sources": [
                    value.strip()
                    for value in (
                        tel.get("evidence_sources")
                        or ""
                    ).split("|")
                    if value.strip()
                ],
            },

            "generation_constraints": {
                "objective": (
                    "Generate an explainable threat-hunting "
                    "hypothesis for the ranked ATT&CK technique."
                ),
                "do_not_claim_attack_occurred": True,
                "do_not_invent_indicators": True,
                "use_only_supported_telemetry": True,
                "distinguish_evidence_from_occurrence": True,
                "expected_output_fields": [
                    "hypothesis",
                    "rationale",
                    "investigation_focus",
                    "required_telemetry",
                    "collection_gaps",
                    "confidence"
                ],
            },

            "evidence_interpretation": (
                "Telemetry evidence indicates observability "
                "or collection support. It does not prove that "
                "the ATT&CK technique occurred in the environment."
            ),
        }

        contexts.append(context)

    validation = "PASS"

    if len(contexts) != TOP_N:
        validation = "FAIL"

    if missing_attack:
        validation = "FAIL"

    if missing_telemetry:
        validation = "FAIL"

    with OUTPUT_FILE.open(
        "w",
        encoding="utf-8",
        newline="\n"
    ) as f:
        for context in contexts:
            f.write(
                json.dumps(
                    context,
                    ensure_ascii=False
                )
                + "\n"
            )

    summary = {
        "phase": 3,
        "component": "hypothesis_context_builder",
        "context_version": "0.1",
        "requested_top_n": TOP_N,
        "generated_contexts": len(contexts),
        "missing_attack_records": missing_attack,
        "missing_telemetry_records": missing_telemetry,
        "status": validation,
    }

    with SUMMARY_FILE.open(
        "w",
        encoding="utf-8"
    ) as f:
        json.dump(
            summary,
            f,
            indent=2,
            ensure_ascii=False
        )

    print(f"Requested contexts       : {TOP_N}")
    print(f"Generated contexts       : {len(contexts)}")
    print(f"Missing ATT&CK records   : {len(missing_attack)}")
    print(f"Missing telemetry records: {len(missing_telemetry)}")
    print(f"Validation               : {validation}")

    print()
    print("Top Hypothesis Contexts")
    print("-----------------------")

    for context in contexts[:10]:
        technique = context["technique"]
        priority = context["prioritization"]

        print(
            f"#{priority['rank']:>3} "
            f"{technique['technique_id']:<10} "
            f"Score={priority['priority_score']:>6.2f} "
            f"{technique['name']}"
        )

    print()
    print(f"JSONL  : {OUTPUT_FILE}")
    print(f"Report : {SUMMARY_FILE}")


if __name__ == "__main__":
    main()