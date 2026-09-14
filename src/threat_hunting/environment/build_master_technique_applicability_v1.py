import csv
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]

ATTACK_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "knowledge"
    / "attack_techniques_active.jsonl"
)

PLATFORM_CATALOG_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "environment"
    / "environment_platform_catalog_v1.jsonl"
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
    / "master_technique_applicability_v1.csv"
)

JSONL_OUTPUT = (
    OUTPUT_DIR
    / "master_technique_applicability_v1.jsonl"
)

REPORT_OUTPUT = (
    REPORT_DIR
    / "master_technique_applicability_v1_summary.json"
)


def read_jsonl(path):
    rows = []

    with path.open(
        "r",
        encoding="utf-8"
    ) as f:
        for line_number, line in enumerate(
            f,
            start=1
        ):
            line = line.strip()

            if not line:
                continue

            try:
                rows.append(
                    json.loads(line)
                )
            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    f"Invalid JSONL at "
                    f"{path}:{line_number}: {exc}"
                ) from exc

    return rows


def pipe(values):
    return "|".join(
        str(v)
        for v in values
        if v is not None
    )


def classify_technique(
    technique_platforms,
    platform_map
):
    observed = []
    collection_gap = []
    unknown = []
    special_scope = []
    confirmed_absent = []

    for platform in technique_platforms:
        state = platform_map.get(
            platform
        )

        if state is None:
            continue

        presence_status = state.get(
            "presence_status"
        )

        telemetry_status = state.get(
            "telemetry_status"
        )

        current_state = state.get(
            "current_environment_state"
        )

        is_collection_gap = bool(
            state.get(
                "collection_gap",
                False
            )
        )

        if platform == "PRE" or (
            presence_status
            == "special_attack_scope"
        ):
            special_scope.append(
                platform
            )
            continue

        if (
            telemetry_status == "observed"
            or current_state
            == "active_observed_platform"
        ):
            observed.append(
                platform
            )
            continue

        if is_collection_gap:
            collection_gap.append(
                platform
            )
            continue

        if presence_status in {
            "known_present",
            "present"
        }:
            # Platform presence is known but
            # telemetry is not observed.
            collection_gap.append(
                platform
            )
            continue

        if presence_status == "unknown":
            unknown.append(
                platform
            )
            continue

        if presence_status in {
            "known_absent",
            "absent",
            "not_present"
        }:
            confirmed_absent.append(
                platform
            )
            continue

        # Preserve ambiguity instead of
        # converting it to absence.
        unknown.append(
            platform
        )

    # Precedence:
    # actual observed applicability
    # > known-present telemetry gap
    # > unknown presence
    # > PRE-only
    # > confirmed absence

    if observed:
        status = (
            "observed_environment_applicable"
        )

        applicability = "applicable"

        prioritization_posture = (
            "eligible_for_prioritization"
        )

    elif collection_gap:
        status = (
            "known_present_collection_gap"
        )

        applicability = "applicable"

        prioritization_posture = (
            "retain_as_collection_gap_candidate"
        )

    elif unknown:
        status = (
            "environment_presence_unknown"
        )

        applicability = "unknown"

        prioritization_posture = (
            "retain_unscored_until_presence_known"
        )

    elif special_scope:
        status = "pre_attack_scope"

        applicability = "special_scope"

        prioritization_posture = (
            "route_to_pre_attack_workflow"
        )

    elif confirmed_absent:
        status = (
            "confirmed_not_present"
        )

        applicability = (
            "not_applicable_current_environment"
        )

        prioritization_posture = (
            "exclude_from_current_environment_only"
        )

    else:
        status = (
            "environment_presence_unknown"
        )

        applicability = "unknown"

        prioritization_posture = (
            "retain_unscored_until_presence_known"
        )

    return {
        "status": status,
        "applicability": applicability,
        "prioritization_posture": (
            prioritization_posture
        ),
        "observed": sorted(
            observed
        ),
        "collection_gap": sorted(
            collection_gap
        ),
        "unknown": sorted(
            unknown
        ),
        "special_scope": sorted(
            special_scope
        ),
        "confirmed_absent": sorted(
            confirmed_absent
        ),
    }


def main():
    for path in [
        ATTACK_FILE,
        PLATFORM_CATALOG_FILE,
    ]:
        if not path.exists():
            raise FileNotFoundError(
                f"Missing required input: {path}"
            )

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    techniques = read_jsonl(
        ATTACK_FILE
    )

    platform_catalog = read_jsonl(
        PLATFORM_CATALOG_FILE
    )

    platform_map = {
        row["platform"]: row
        for row in platform_catalog
    }

    platform_universe = set(
        platform_map
    )

    output_rows = []

    validation_errors = []

    attack_platform_values = {
        platform
        for technique in techniques
        for platform in (
            technique.get("platforms")
            or []
        )
    }

    missing_platforms = sorted(
        attack_platform_values
        - platform_universe
    )

    if missing_platforms:
        validation_errors.append(
            "ATT&CK platforms missing from "
            "environment platform catalog: "
            + ", ".join(
                missing_platforms
            )
        )

    if len(techniques) != 697:
        validation_errors.append(
            f"Expected 697 active techniques, "
            f"found {len(techniques)}"
        )

    if len(platform_catalog) != 11:
        validation_errors.append(
            f"Expected 11 ATT&CK platforms, "
            f"found {len(platform_catalog)}"
        )

    unsupported_platforms = [
        row["platform"]
        for row in platform_catalog
        if not row.get(
            "product_supported",
            False
        )
    ]

    if unsupported_platforms:
        validation_errors.append(
            "Product platform catalog contains "
            "unsupported ATT&CK platforms: "
            + ", ".join(
                sorted(
                    unsupported_platforms
                )
            )
        )

    for technique in techniques:
        technique_id = technique.get(
            "technique_id"
        )

        technique_name = technique.get(
            "name"
        )

        platforms = sorted(
            technique.get(
                "platforms"
            )
            or []
        )

        result = classify_technique(
            platforms,
            platform_map
        )

        product_supported = all(
            platform_map.get(
                platform,
                {}
            ).get(
                "product_supported",
                False
            )
            for platform in platforms
        )

        row = {
            "technique_id": technique_id,
            "technique_name": (
                technique_name
            ),

            "is_subtechnique": bool(
                technique.get(
                    "is_subtechnique",
                    False
                )
            ),

            "parent_technique_id": (
                technique.get(
                    "parent_technique_id"
                )
            ),

            "tactics": sorted(
                technique.get(
                    "tactics"
                )
                or []
            ),

            "attack_platforms": (
                platforms
            ),

            "product_supported": (
                product_supported
            ),

            "current_environment_applicability": (
                result[
                    "applicability"
                ]
            ),

            "applicability_status": (
                result[
                    "status"
                ]
            ),

            "prioritization_posture": (
                result[
                    "prioritization_posture"
                ]
            ),

            "observed_platform_matches": (
                result[
                    "observed"
                ]
            ),

            "collection_gap_platform_matches": (
                result[
                    "collection_gap"
                ]
            ),

            "unknown_platform_matches": (
                result[
                    "unknown"
                ]
            ),

            "special_scope_platform_matches": (
                result[
                    "special_scope"
                ]
            ),

            "confirmed_absent_platform_matches": (
                result[
                    "confirmed_absent"
                ]
            ),
        }

        output_rows.append(
            row
        )

    status_counter = Counter(
        row["applicability_status"]
        for row in output_rows
    )

    applicability_counter = Counter(
        row[
            "current_environment_applicability"
        ]
        for row in output_rows
    )

    posture_counter = Counter(
        row["prioritization_posture"]
        for row in output_rows
    )

    if len(output_rows) != 697:
        validation_errors.append(
            "Output row count is not 697"
        )

    ids = [
        row["technique_id"]
        for row in output_rows
    ]

    if len(set(ids)) != len(ids):
        validation_errors.append(
            "Duplicate technique IDs detected"
        )

    if any(
        not row["product_supported"]
        for row in output_rows
    ):
        validation_errors.append(
            "At least one active ATT&CK technique "
            "was incorrectly marked unsupported"
        )

    if sum(
        status_counter.values()
    ) != 697:
        validation_errors.append(
            "Applicability status counts "
            "do not reconcile to 697"
        )

    forbidden_statuses = {
        "platform_ineligible",
        "unsupported",
        "telemetry_ineligible",
    }

    observed_forbidden = sorted(
        forbidden_statuses
        & set(
            status_counter.keys()
        )
    )

    if observed_forbidden:
        validation_errors.append(
            "Legacy invalid applicability statuses "
            "were produced: "
            + ", ".join(
                observed_forbidden
            )
        )

    if (
        status_counter[
            "observed_environment_applicable"
        ]
        == 0
    ):
        validation_errors.append(
            "No techniques were mapped to "
            "observed environment platforms"
        )

    validation_status = (
        "PASS"
        if not validation_errors
        else "FAIL"
    )

    # JSONL output preserves native arrays.
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

    # CSV output flattens arrays only for
    # analyst-friendly inspection.
    csv_fields = [
        "technique_id",
        "technique_name",
        "is_subtechnique",
        "parent_technique_id",
        "tactics",
        "attack_platforms",
        "product_supported",
        "current_environment_applicability",
        "applicability_status",
        "prioritization_posture",
        "observed_platform_matches",
        "collection_gap_platform_matches",
        "unknown_platform_matches",
        "special_scope_platform_matches",
        "confirmed_absent_platform_matches",
    ]

    with CSV_OUTPUT.open(
        "w",
        encoding="utf-8-sig",
        newline=""
    ) as f:
        writer = csv.DictWriter(
            f,
            fieldnames=csv_fields
        )

        writer.writeheader()

        for row in output_rows:
            csv_row = dict(
                row
            )

            for field in [
                "tactics",
                "attack_platforms",
                "observed_platform_matches",
                "collection_gap_platform_matches",
                "unknown_platform_matches",
                "special_scope_platform_matches",
                "confirmed_absent_platform_matches",
            ]:
                csv_row[field] = pipe(
                    csv_row[field]
                )

            writer.writerow(
                csv_row
            )

    report = {
        "component": (
            "master_technique_applicability"
        ),

        "version": "1.0",

        "generated_at_utc": (
            datetime.now(
                timezone.utc
            ).isoformat()
        ),

        "master_attack_techniques": (
            len(techniques)
        ),

        "platform_catalog_count": (
            len(platform_catalog)
        ),

        "platform_universe": sorted(
            platform_universe
        ),

        "output_techniques": (
            len(output_rows)
        ),

        "applicability_status_counts": (
            dict(
                sorted(
                    status_counter.items()
                )
            )
        ),

        "environment_applicability_counts": (
            dict(
                sorted(
                    applicability_counter.items()
                )
            )
        ),

        "prioritization_posture_counts": (
            dict(
                sorted(
                    posture_counter.items()
                )
            )
        ),

        "product_supported_techniques": sum(
            1
            for row in output_rows
            if row[
                "product_supported"
            ]
        ),

        "validation_errors": (
            validation_errors
        ),

        "status": (
            validation_status
        ),
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
        "Master Technique Applicability v1.0"
    )
    print(
        "-----------------------------------"
    )

    print(
        f"Master ATT&CK techniques : "
        f"{len(techniques)}"
    )

    print(
        f"Platform catalog         : "
        f"{len(platform_catalog)}"
    )

    print(
        f"Output techniques        : "
        f"{len(output_rows)}"
    )

    print(
        f"Product supported        : "
        f"{sum(1 for r in output_rows if r['product_supported'])}"
    )

    print()
    print(
        "Applicability statuses:"
    )

    for key, value in sorted(
        status_counter.items()
    ):
        print(
            f"  {key:<38} {value}"
        )

    print()
    print(
        "Environment applicability:"
    )

    for key, value in sorted(
        applicability_counter.items()
    ):
        print(
            f"  {key:<38} {value}"
        )

    print()
    print(
        "Prioritization posture:"
    )

    for key, value in sorted(
        posture_counter.items()
    ):
        print(
            f"  {key:<44} {value}"
        )

    print()
    print(
        f"Validation               : "
        f"{validation_status}"
    )

    if validation_errors:
        print()
        print(
            "Validation errors:"
        )

        for error in validation_errors:
            print(
                " - " + error
            )

    print()
    print(
        f"CSV    : {CSV_OUTPUT}"
    )

    print(
        f"JSONL  : {JSONL_OUTPUT}"
    )

    print(
        f"Report : {REPORT_OUTPUT}"
    )


if __name__ == "__main__":
    main()