import csv
import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]

TELEMETRY_FILE = (
    PROJECT_ROOT / "data" / "processed" / "environment"
    / "master_telemetry_readiness_v0_1.csv"
)

ELIGIBILITY_FILE = (
    PROJECT_ROOT / "data" / "processed" / "environment"
    / "master_telemetry_eligibility_v0_1.csv"
)

SIGMA_FILE = (
    PROJECT_ROOT / "data" / "processed" / "environment"
    / "master_sigma_knowledge_gap_v0_1.csv"
)

ENVIRONMENT_FILE = (
    PROJECT_ROOT / "data" / "processed" / "environment"
    / "dynamic_environment_profile_v0_1.json"
)

POLICY_FILE = (
    PROJECT_ROOT / "config" / "phase3"
    / "adaptive_prioritization_policy_v1.json"
)

OUTPUT_DIR = (
    PROJECT_ROOT / "data" / "processed" / "environment"
)

REPORT_DIR = (
    PROJECT_ROOT / "reports" / "environment"
)

CSV_OUTPUT = OUTPUT_DIR / "adaptive_product_prioritization_v0_1.csv"
JSONL_OUTPUT = OUTPUT_DIR / "adaptive_product_prioritization_v0_1.jsonl"
REPORT_OUTPUT = REPORT_DIR / "adaptive_product_prioritization_v0_1_summary.json"


def read_csv(path):
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def to_bool(value):
    return str(value).strip().lower() == "true"


def to_float(value):
    if value in (None, ""):
        return None
    return float(value)


def to_int(value):
    if value in (None, ""):
        return 0
    return int(float(value))


def main():
    telemetry_rows = read_csv(TELEMETRY_FILE)
    eligibility_rows = read_csv(ELIGIBILITY_FILE)
    sigma_rows = read_csv(SIGMA_FILE)

    environment = json.loads(
        ENVIRONMENT_FILE.read_text(encoding="utf-8")
    )

    policy = json.loads(
        POLICY_FILE.read_text(encoding="utf-8")
    )

    telemetry_by_id = {
        row["technique_id"]: row
        for row in telemetry_rows
    }

    eligibility_by_id = {
        row["technique_id"]: row
        for row in eligibility_rows
    }

    sigma_by_id = {
        row["technique_id"]: row
        for row in sigma_rows
    }

    weights = policy["nominal_weights"]

    assets_available = bool(
        environment.get("assets")
    )

    incident_available = bool(
        environment.get("incident_history")
    )

    client_detection_available = bool(
        environment.get("detection_coverage")
    )

    output_rows = []
    missing_records = []

    for technique_id, eligibility in eligibility_by_id.items():
        telemetry = telemetry_by_id.get(technique_id)
        sigma = sigma_by_id.get(technique_id)

        if telemetry is None or sigma is None:
            missing_records.append(technique_id)
            continue

        hunt_eligible = to_bool(
            eligibility["current_hunt_eligible"]
        )

        telemetry_score = to_float(
            telemetry["telemetry_readiness_score"]
        )

        sigma_gap_score = to_float(
            sigma["sigma_detection_knowledge_gap_score"]
        )

        asset_score = None
        incident_score = None
        client_detection_gap_score = None

        available_factors = {}

        if hunt_eligible and telemetry_score is not None:
            available_factors["telemetry_readiness"] = (
                telemetry_score
            )

        if hunt_eligible and assets_available:
            # No technique-specific client asset score is
            # currently available in the discovered profile.
            asset_score = None

        if hunt_eligible and incident_available:
            # No technique-specific incident score is
            # currently available in the discovered profile.
            incident_score = None

        detection_gap_source = None
        detection_gap_score = None

        if hunt_eligible:
            if (
                client_detection_available
                and client_detection_gap_score is not None
            ):
                detection_gap_score = (
                    client_detection_gap_score
                )
                detection_gap_source = (
                    "client_detection_coverage"
                )

            elif sigma_gap_score is not None:
                detection_gap_score = sigma_gap_score
                detection_gap_source = (
                    "sigma_detection_knowledge_gap_proxy"
                )

                available_factors[
                    "detection_coverage_gap"
                ] = detection_gap_score

        available_weight_sum = sum(
            weights[name]
            for name in available_factors
        )

        effective_weights = {}

        if available_weight_sum > 0:
            for name in available_factors:
                effective_weights[name] = round(
                    weights[name] / available_weight_sum,
                    4
                )

        if (
            hunt_eligible
            and len(available_factors)
            >= policy["minimum_available_factors"]
        ):
            priority_score = round(
                sum(
                    available_factors[name]
                    * effective_weights[name]
                    for name in available_factors
                ),
                2
            )

            prioritization_status = "scored"

        elif hunt_eligible:
            priority_score = None
            prioritization_status = (
                "insufficient_scoring_context"
            )

        else:
            priority_score = None
            prioritization_status = (
                eligibility["current_hunt_status"]
            )

        output_rows.append({
            "rank": None,

            "technique_id": technique_id,
            "technique_name": eligibility[
                "technique_name"
            ],

            "is_subtechnique": to_bool(
                eligibility["is_subtechnique"]
            ),

            "platform_eligible": to_bool(
                eligibility["platform_eligible"]
            ),

            "current_hunt_eligible": hunt_eligible,

            "telemetry_readiness_score": (
                telemetry_score
            ),

            "asset_criticality_score": (
                asset_score
            ),

            "incident_history_relevance_score": (
                incident_score
            ),

            "client_detection_gap_score": (
                client_detection_gap_score
            ),

            "sigma_detection_knowledge_gap_score": (
                sigma_gap_score
            ),

            "detection_gap_score_used": (
                detection_gap_score
            ),

            "detection_gap_source": (
                detection_gap_source
            ),

            "available_factor_count": len(
                available_factors
            ),

            "available_factors": "|".join(
                available_factors.keys()
            ),

            "effective_telemetry_weight": (
                effective_weights.get(
                    "telemetry_readiness"
                )
            ),

            "effective_asset_weight": (
                effective_weights.get(
                    "asset_criticality"
                )
            ),

            "effective_incident_weight": (
                effective_weights.get(
                    "incident_history_relevance"
                )
            ),

            "effective_detection_gap_weight": (
                effective_weights.get(
                    "detection_coverage_gap"
                )
            ),

            "priority_score": priority_score,

            "prioritization_status": (
                prioritization_status
            ),

            "exact_evidence_components": to_int(
                eligibility[
                    "data_components_with_exact_event_evidence"
                ]
            ),

            "evidence_source_count": len([
                value
                for value in (
                    eligibility.get(
                        "evidence_sources"
                    ) or ""
                ).split("|")
                if value.strip()
            ]),

            "evidence_sources": eligibility.get(
                "evidence_sources",
                ""
            ),

            "missing_factors": "|".join([
                name
                for name, value in [
                    (
                        "asset_criticality",
                        asset_score
                    ),
                    (
                        "incident_history_relevance",
                        incident_score
                    ),
                    (
                        "client_detection_coverage",
                        client_detection_gap_score
                    ),
                ]
                if value is None
            ]),

            "product_scope": "master_catalog"
        })

    scored_rows = [
        row
        for row in output_rows
        if row["priority_score"] is not None
    ]

    scored_rows.sort(
        key=lambda row: (
            -row["priority_score"],
            -int(row["is_subtechnique"]),
            -row["exact_evidence_components"],
            -row["evidence_source_count"],
            row["technique_id"]
        )
    )

    for rank, row in enumerate(
        scored_rows,
        start=1
    ):
        row["rank"] = rank

    unscored_rows = [
        row
        for row in output_rows
        if row["priority_score"] is None
    ]

    unscored_rows.sort(
        key=lambda row: row["technique_id"]
    )

    final_rows = scored_rows + unscored_rows

    validation_errors = []

    if len(final_rows) != 697:
        validation_errors.append(
            "Output does not contain 697 techniques"
        )

    if missing_records:
        validation_errors.append(
            f"{len(missing_records)} joined records missing"
        )

    validation = (
        "PASS"
        if not validation_errors
        else "FAIL"
    )

    fields = list(final_rows[0].keys())

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
        writer.writerows(final_rows)

    with JSONL_OUTPUT.open(
        "w",
        encoding="utf-8",
        newline="\n"
    ) as f:
        for row in final_rows:
            f.write(
                json.dumps(
                    row,
                    ensure_ascii=False
                )
                + "\n"
            )

    report = {
        "component": "adaptive_product_prioritization",
        "version": "0.1",
        "product_mode": True,
        "master_catalog_techniques": len(final_rows),
        "scored_techniques": len(scored_rows),
        "unscored_techniques": len(unscored_rows),

        "nominal_weights": weights,

        "missing_factor_policy": (
            policy["missing_factor_policy"]
        ),

        "detection_gap_fallback": (
            policy["detection_gap_fallback"]
        ),

        "current_environment": {
            "platforms": environment.get(
                "platforms",
                []
            ),
            "assets_available": assets_available,
            "incident_history_available": (
                incident_available
            ),
            "client_detection_coverage_available": (
                client_detection_available
            )
        },

        "validation_errors": validation_errors,
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

    print("Adaptive Product Prioritization v0.1")
    print("------------------------------------")

    print(
        f"Master catalog          : "
        f"{len(final_rows)}"
    )

    print(
        f"Scored techniques       : "
        f"{len(scored_rows)}"
    )

    print(
        f"Unscored techniques     : "
        f"{len(unscored_rows)}"
    )

    print(
        "Environment platforms  : "
        + ", ".join(
            environment.get("platforms", [])
        )
    )

    print(
        f"Assets available        : "
        f"{assets_available}"
    )

    print(
        f"Incident history        : "
        f"{incident_available}"
    )

    print(
        f"Client detection cov.   : "
        f"{client_detection_available}"
    )

    if scored_rows:
        print()
        print(
            "Effective weights for current environment:"
        )

        print(
            "  Telemetry            : "
            f"{scored_rows[0]['effective_telemetry_weight']}"
        )

        print(
            "  Detection gap        : "
            f"{scored_rows[0]['effective_detection_gap_weight']}"
        )

        print()
        print("Top 15 Techniques")
        print("-----------------")

        for row in scored_rows[:15]:
            print(
                f"#{row['rank']:>3} "
                f"{row['technique_id']:<10} "
                f"Score={row['priority_score']:>6.2f} "
                f"Sub={str(row['is_subtechnique']):<5} "
                f"{row['technique_name']}"
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