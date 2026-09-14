import csv
import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]

ATTACK_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "knowledge"
    / "attack_techniques_active.jsonl"
)

ENVIRONMENT_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "environment"
    / "dynamic_environment_profile_v0_1.json"
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
    / "master_technique_eligibility_v0_1.csv"
)

JSONL_OUTPUT = (
    OUTPUT_DIR
    / "master_technique_eligibility_v0_1.jsonl"
)

REPORT_OUTPUT = (
    REPORT_DIR
    / "master_technique_eligibility_v0_1_summary.json"
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
                    f"Invalid JSON on line "
                    f"{line_number}: {exc}"
                ) from exc

    return rows


def normalize_platform(value):
    return str(value or "").strip().lower()


def stringify_list(values):
    return "|".join(
        str(value)
        for value in values
        if value not in (None, "")
    )


def main():
    if not ATTACK_FILE.exists():
        raise FileNotFoundError(
            f"Missing ATT&CK input: {ATTACK_FILE}"
        )

    if not ENVIRONMENT_FILE.exists():
        raise FileNotFoundError(
            f"Missing environment profile: "
            f"{ENVIRONMENT_FILE}"
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

    environment = json.loads(
        ENVIRONMENT_FILE.read_text(
            encoding="utf-8"
        )
    )

    discovered_platforms = environment.get(
        "platforms",
        []
    )

    environment_platform_map = {
        normalize_platform(platform): platform
        for platform in discovered_platforms
    }

    output_rows = []

    counts = {
        "eligible": 0,
        "ineligible_platform": 0,
        "unknown_platform": 0
    }

    for technique in techniques:
        technique_id = technique.get(
            "technique_id"
        )

        technique_name = technique.get(
            "name"
        )

        technique_platforms = technique.get(
            "platforms",
            []
        ) or []

        normalized_technique_platforms = {
            normalize_platform(platform)
            for platform in technique_platforms
        }

        matched_normalized = (
            normalized_technique_platforms
            & set(environment_platform_map)
        )

        matched_platforms = sorted(
            environment_platform_map[value]
            for value in matched_normalized
        )

        if not technique_platforms:
            status = "unknown_platform"

            eligible = False

            reason = (
                "ATT&CK technique has no platform "
                "metadata available."
            )

        elif matched_platforms:
            status = "eligible"

            eligible = True

            reason = (
                "Technique platform metadata intersects "
                "with dynamically discovered environment "
                "platforms."
            )

        else:
            status = "ineligible_platform"

            eligible = False

            reason = (
                "Technique platform metadata does not "
                "intersect with the currently discovered "
                "environment platforms."
            )

        counts[status] += 1

        output_rows.append({
            "technique_id": technique_id,
            "technique_name": technique_name,
            "is_subtechnique": technique.get(
                "is_subtechnique",
                False
            ),
            "parent_technique_id": technique.get(
                "parent_technique_id"
            ),
            "tactics": stringify_list(
                technique.get(
                    "tactics",
                    []
                )
            ),
            "technique_platforms": stringify_list(
                technique_platforms
            ),
            "environment_platforms": stringify_list(
                discovered_platforms
            ),
            "matched_platforms": stringify_list(
                matched_platforms
            ),
            "platform_eligibility_status": status,
            "eligible_for_current_environment": (
                eligible
            ),
            "eligibility_reason": reason,
            "product_scope": "master_catalog"
        })

    output_rows.sort(
        key=lambda row: row["technique_id"]
    )

    fields = [
        "technique_id",
        "technique_name",
        "is_subtechnique",
        "parent_technique_id",
        "tactics",
        "technique_platforms",
        "environment_platforms",
        "matched_platforms",
        "platform_eligibility_status",
        "eligible_for_current_environment",
        "eligibility_reason",
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

    validation_errors = []

    if not techniques:
        validation_errors.append(
            "ATT&CK master catalog is empty"
        )

    if len(output_rows) != len(techniques):
        validation_errors.append(
            "Output count does not match "
            "ATT&CK input count"
        )

    if not discovered_platforms:
        validation_errors.append(
            "Dynamic environment contains "
            "no discovered platforms"
        )

    status = (
        "PASS"
        if not validation_errors
        else "FAIL"
    )

    report = {
        "component": (
            "master_technique_eligibility"
        ),
        "version": "0.1",
        "product_mode": True,
        "master_catalog_techniques": len(
            techniques
        ),
        "discovered_environment_platforms": (
            discovered_platforms
        ),
        "eligible_for_current_environment": (
            counts["eligible"]
        ),
        "ineligible_for_current_environment": (
            counts["ineligible_platform"]
        ),
        "unknown_platform": (
            counts["unknown_platform"]
        ),
        "output_techniques": len(
            output_rows
        ),
        "validation_errors": (
            validation_errors
        ),
        "status": status
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
        "Master Technique Eligibility v0.1"
    )
    print(
        "---------------------------------"
    )

    print(
        f"Master ATT&CK catalog   : "
        f"{len(techniques)}"
    )

    print(
        "Environment platforms  : "
        + ", ".join(discovered_platforms)
    )

    print(
        f"Eligible               : "
        f"{counts['eligible']}"
    )

    print(
        f"Ineligible platform    : "
        f"{counts['ineligible_platform']}"
    )

    print(
        f"Unknown platform       : "
        f"{counts['unknown_platform']}"
    )

    print(
        f"Output techniques      : "
        f"{len(output_rows)}"
    )

    print(
        f"Validation             : "
        f"{status}"
    )

    print()
    print(f"CSV    : {CSV_OUTPUT}")
    print(f"JSONL  : {JSONL_OUTPUT}")
    print(f"Report : {REPORT_OUTPUT}")


if __name__ == "__main__":
    main()