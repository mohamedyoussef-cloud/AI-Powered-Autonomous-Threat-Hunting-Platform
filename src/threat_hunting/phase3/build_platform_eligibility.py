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

CSV_OUTPUT = OUTPUT_DIR / "attack_platform_eligibility.csv"
JSONL_OUTPUT = OUTPUT_DIR / "attack_platform_eligibility.jsonl"
SUMMARY_OUTPUT = REPORT_DIR / "platform_filter_summary.json"


def normalize_platform(value):
    return str(value).strip().casefold()


def load_jsonl(path):
    records = []

    with path.open("r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, start=1):
            line = line.strip()

            if not line:
                continue

            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    f"Invalid JSON in {path} at line {line_number}: {exc}"
                ) from exc

    return records


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    if not ATTACK_FILE.exists():
        raise FileNotFoundError(f"ATT&CK file not found: {ATTACK_FILE}")

    if not PROFILE_FILE.exists():
        raise FileNotFoundError(f"Environment profile not found: {PROFILE_FILE}")

    with PROFILE_FILE.open("r", encoding="utf-8") as f:
        profile = json.load(f)

    environment_platforms = profile.get("platforms", [])

    normalized_environment = {
        normalize_platform(platform)
        for platform in environment_platforms
    }

    techniques = load_jsonl(ATTACK_FILE)

    rows = []

    compatible_count = 0
    incompatible_count = 0
    unspecified_count = 0

    for technique in techniques:
        technique_id = technique.get("technique_id")
        name = technique.get("name")
        platforms = technique.get("platforms") or []

        normalized_technique_platforms = {
            normalize_platform(platform)
            for platform in platforms
            if str(platform).strip()
        }

        matched_platforms = sorted(
            [
                platform
                for platform in platforms
                if normalize_platform(platform) in normalized_environment
            ]
        )

        if not normalized_technique_platforms:
            status = "platform_unspecified"
            eligible = False
            reason = "ATT&CK technique has no platform metadata."
            unspecified_count += 1

        elif normalized_environment.intersection(
            normalized_technique_platforms
        ):
            status = "compatible"
            eligible = True
            reason = (
                "Technique supports at least one platform present "
                "in the environment profile."
            )
            compatible_count += 1

        else:
            status = "incompatible"
            eligible = False
            reason = (
                "Technique platforms do not overlap with the "
                "environment profile platforms."
            )
            incompatible_count += 1

        row = {
            "technique_id": technique_id,
            "name": name,
            "is_subtechnique": technique.get("is_subtechnique", False),
            "tactics": technique.get("tactics", []),
            "technique_platforms": platforms,
            "environment_platforms": environment_platforms,
            "matched_platforms": matched_platforms,
            "platform_status": status,
            "platform_eligible": eligible,
            "reason": reason,
        }

        rows.append(row)

    with JSONL_OUTPUT.open("w", encoding="utf-8", newline="\n") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    csv_fields = [
        "technique_id",
        "name",
        "is_subtechnique",
        "tactics",
        "technique_platforms",
        "environment_platforms",
        "matched_platforms",
        "platform_status",
        "platform_eligible",
        "reason",
    ]

    with CSV_OUTPUT.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=csv_fields)
        writer.writeheader()

        for row in rows:
            csv_row = row.copy()

            for field in [
                "tactics",
                "technique_platforms",
                "environment_platforms",
                "matched_platforms",
            ]:
                csv_row[field] = "|".join(
                    str(value) for value in csv_row[field]
                )

            writer.writerow(csv_row)

    summary = {
        "phase": 3,
        "component": "platform_compatibility",
        "environment_id": profile.get("environment_id"),
        "environment_platforms": environment_platforms,
        "input_active_techniques": len(techniques),
        "compatible": compatible_count,
        "incompatible": incompatible_count,
        "platform_unspecified": unspecified_count,
        "eligible_total": compatible_count,
        "output_csv": str(CSV_OUTPUT.relative_to(PROJECT_ROOT)),
        "output_jsonl": str(JSONL_OUTPUT.relative_to(PROJECT_ROOT)),
        "status": "PASS"
        if len(techniques) == (
            compatible_count
            + incompatible_count
            + unspecified_count
        )
        else "FAIL",
    }

    with SUMMARY_OUTPUT.open("w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    print(f"Active ATT&CK techniques : {len(techniques)}")
    print(f"Compatible               : {compatible_count}")
    print(f"Incompatible             : {incompatible_count}")
    print(f"Platform unspecified     : {unspecified_count}")
    print(f"Eligible for next gate   : {compatible_count}")
    print(f"Validation               : {summary['status']}")
    print()
    print(f"CSV    : {CSV_OUTPUT}")
    print(f"JSONL  : {JSONL_OUTPUT}")
    print(f"Report : {SUMMARY_OUTPUT}")


if __name__ == "__main__":
    main()