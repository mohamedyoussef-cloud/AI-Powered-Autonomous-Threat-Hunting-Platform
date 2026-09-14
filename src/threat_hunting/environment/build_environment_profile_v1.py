import csv
import json
from collections import defaultdict
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

BOTS_SOURCETYPE_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "telemetry"
    / "botsv3"
    / "sourcetype_profile.csv"
)

BOTS_SOURCE_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "telemetry"
    / "botsv3"
    / "source_profile.csv"
)

EVTX_INVENTORY_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "telemetry"
    / "evtx_source_file_inventory.csv"
)

SIGNATURE_FILE = (
    PROJECT_ROOT
    / "config"
    / "phase3"
    / "platform_evidence_signatures_v1.json"
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

PROFILE_OUTPUT = (
    OUTPUT_DIR
    / "environment_profile_product_v1.json"
)

PLATFORM_CATALOG_OUTPUT = (
    OUTPUT_DIR
    / "environment_platform_catalog_v1.jsonl"
)

REPORT_OUTPUT = (
    REPORT_DIR
    / "environment_profile_product_v1_summary.json"
)


def read_csv(path):
    if not path.exists():
        return []

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
                    f"Invalid JSON line "
                    f"{line_number}: {exc}"
                ) from exc

    return rows


def normalize(value):
    return str(value or "").strip().lower()


def build_attack_platform_universe(
    techniques
):
    return sorted({
        platform
        for technique in techniques
        for platform in (
            technique.get("platforms")
            or []
        )
        if platform
    })


def inspect_rows(
    rows,
    field_name,
    dataset_name,
    rules
):
    findings = []

    seen = set()

    for row in rows:
        raw_value = row.get(
            field_name,
            ""
        )

        normalized_value = normalize(
            raw_value
        )

        if not normalized_value:
            continue

        for rule in rules:
            if rule["field"] != field_name:
                continue

            for pattern in rule["patterns"]:
                pattern_norm = normalize(
                    pattern
                )

                if pattern_norm not in normalized_value:
                    continue

                key = (
                    rule["platform"],
                    dataset_name,
                    field_name,
                    raw_value,
                    pattern_norm,
                )

                if key in seen:
                    continue

                seen.add(key)

                findings.append({
                    "platform": (
                        rule["platform"]
                    ),
                    "dataset": dataset_name,
                    "field": field_name,
                    "observed_value": raw_value,
                    "matched_pattern": pattern,
                    "confidence": float(
                        rule["confidence"]
                    ),
                    "reason": rule["reason"],
                    "event_count": row.get(
                        "event_count"
                    ),
                })

    return findings


def main():
    required = [
        ATTACK_FILE,
        BOTS_SOURCETYPE_FILE,
        BOTS_SOURCE_FILE,
        SIGNATURE_FILE,
    ]

    for path in required:
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

    sourcetypes = read_csv(
        BOTS_SOURCETYPE_FILE
    )

    sources = read_csv(
        BOTS_SOURCE_FILE
    )

    signature_config = json.loads(
        SIGNATURE_FILE.read_text(
            encoding="utf-8"
        )
    )

    rules = signature_config[
        "rules"
    ]

    attack_platforms = (
        build_attack_platform_universe(
            techniques
        )
    )

    attack_platform_set = set(
        attack_platforms
    )

    invalid_rule_platforms = sorted({
        rule["platform"]
        for rule in rules
        if rule["platform"]
        not in attack_platform_set
    })

    findings = []

    findings.extend(
        inspect_rows(
            sourcetypes,
            "sourcetype",
            "BOTS v3",
            rules,
        )
    )

    findings.extend(
        inspect_rows(
            sources,
            "source",
            "BOTS v3",
            rules,
        )
    )

    # EVTX itself is strong Windows telemetry evidence.
    if EVTX_INVENTORY_FILE.exists():
        evtx_rows = read_csv(
            EVTX_INVENTORY_FILE
        )

        if evtx_rows:
            findings.append({
                "platform": "Windows",
                "dataset": "EVTX",
                "field": (
                    "source_file_inventory"
                ),
                "observed_value": str(
                    EVTX_INVENTORY_FILE
                ),
                "matched_pattern": "EVTX",
                "confidence": 1.0,
                "reason": (
                    "Windows EVTX inventory observed"
                ),
                "event_count": None,
            })

    evidence_by_platform = defaultdict(
        list
    )

    for finding in findings:
        if finding["platform"] in (
            attack_platform_set
        ):
            evidence_by_platform[
                finding["platform"]
            ].append(
                finding
            )

    platform_catalog = []

    observed_platforms = []

    for platform in attack_platforms:
        evidence = evidence_by_platform.get(
            platform,
            []
        )

        if platform == "PRE":
            telemetry_status = (
                "not_applicable_runtime_telemetry"
            )

            presence_status = (
                "special_attack_scope"
            )

            environment_state = (
                "pre_attack_scope"
            )

            confidence = None

        elif evidence:
            telemetry_status = "observed"

            presence_status = (
                "inferred_present_from_telemetry"
            )

            environment_state = (
                "active_observed_platform"
            )

            confidence = max(
                item["confidence"]
                for item in evidence
            )

            observed_platforms.append(
                platform
            )

        else:
            telemetry_status = (
                "not_observed_in_current_inputs"
            )

            presence_status = "unknown"

            environment_state = (
                "environment_unknown"
            )

            confidence = None

        platform_catalog.append({
            "platform": platform,

            # Product support and current observation
            # are deliberately separate.
            "product_supported": True,

            "presence_status": (
                presence_status
            ),

            "telemetry_status": (
                telemetry_status
            ),

            "current_environment_state": (
                environment_state
            ),

            "confidence": (
                round(confidence, 2)
                if confidence is not None
                else None
            ),

            "evidence_count": len(
                evidence
            ),

            "evidence_datasets": sorted({
                item["dataset"]
                for item in evidence
            }),

            "evidence": evidence,

            "collection_gap": False,

            "collection_gap_reason": (
                None
            ),

            "interpretation": (
                "Absence of telemetry evidence does "
                "not mean the platform is unsupported "
                "or absent from the environment."
            ),
        })

    unknown_platforms = [
        row["platform"]
        for row in platform_catalog
        if row[
            "current_environment_state"
        ] == "environment_unknown"
    ]

    profile = {
        "profile_version": "1.0",

        "profile_mode": (
            "product_environment_discovery"
        ),

        "environment_id": (
            "reference-botsv3-evtx"
        ),

        "environment_name": (
            "BOTS v3 + EVTX Reference Environment"
        ),

        "generated_at_utc": (
            datetime.now(
                timezone.utc
            ).isoformat()
        ),

        "product_platform_universe": (
            attack_platforms
        ),

        "product_supported_platforms": (
            attack_platforms
        ),

        "observed_platforms": sorted(
            observed_platforms
        ),

        "unknown_platform_presence": (
            unknown_platforms
        ),

        "platform_states": (
            platform_catalog
        ),

        "telemetry_inventory": {
            "datasets": [
                "BOTS v3",
                "EVTX",
            ],

            "bots_sourcetype_count": len(
                sourcetypes
            ),

            "bots_source_count": len(
                sources
            ),

            "evtx_inventory_available": (
                EVTX_INVENTORY_FILE.exists()
            ),
        },

        "assets": [],

        "incident_history": [],

        "detection_coverage": [],

        "unknown_context": {
            "asset_inventory": True,
            "asset_criticality": True,
            "incident_history": True,
            "client_detection_coverage": True,
        },

        "environment_semantics": {
            "product_supported": (
                "Platform is supported by the "
                "product knowledge and processing "
                "architecture."
            ),

            "presence_status": (
                "Whether current environment "
                "presence is known or inferred."
            ),

            "telemetry_status": (
                "Whether current telemetry inputs "
                "contain evidence for the platform."
            ),

            "environment_unknown": (
                "Unknown is preserved and must not "
                "be converted to absent."
            ),

            "collection_gap": (
                "A collection gap can only be "
                "asserted when platform presence is "
                "known but required telemetry is "
                "missing."
            ),
        },
    }

    validation_errors = []

    if len(techniques) != 697:
        validation_errors.append(
            "ATT&CK active technique count "
            "is not 697"
        )

    if len(platform_catalog) != len(
        attack_platforms
    ):
        validation_errors.append(
            "Platform catalog count mismatch"
        )

    if invalid_rule_platforms:
        validation_errors.append(
            "Signature config contains "
            "non-ATT&CK platforms: "
            + ", ".join(
                invalid_rule_platforms
            )
        )

    if any(
        not row["product_supported"]
        for row in platform_catalog
    ):
        validation_errors.append(
            "At least one ATT&CK platform was "
            "incorrectly marked unsupported"
        )

    if not observed_platforms:
        validation_errors.append(
            "No telemetry-backed platforms "
            "were discovered"
        )

    status = (
        "PASS"
        if not validation_errors
        else "FAIL"
    )

    PROFILE_OUTPUT.write_text(
        json.dumps(
            profile,
            indent=2,
            ensure_ascii=False
        ),
        encoding="utf-8"
    )

    with PLATFORM_CATALOG_OUTPUT.open(
        "w",
        encoding="utf-8",
        newline="\n"
    ) as f:
        for row in platform_catalog:
            f.write(
                json.dumps(
                    row,
                    ensure_ascii=False
                )
                + "\n"
            )

    report = {
        "component": (
            "product_environment_profiler"
        ),

        "version": "1.0",

        "master_attack_techniques": len(
            techniques
        ),

        "attack_platform_universe_count": (
            len(attack_platforms)
        ),

        "attack_platform_universe": (
            attack_platforms
        ),

        "product_supported_platforms": (
            len(platform_catalog)
        ),

        "observed_platform_count": len(
            observed_platforms
        ),

        "observed_platforms": sorted(
            observed_platforms
        ),

        "unknown_presence_count": len(
            unknown_platforms
        ),

        "unknown_presence_platforms": (
            unknown_platforms
        ),

        "platform_evidence_records": len(
            findings
        ),

        "bots_sourcetypes_inspected": len(
            sourcetypes
        ),

        "bots_sources_inspected": len(
            sources
        ),

        "validation_errors": (
            validation_errors
        ),

        "status": status,
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
        "Product Environment Profiler v1.0"
    )
    print(
        "---------------------------------"
    )

    print(
        f"Master ATT&CK techniques : "
        f"{len(techniques)}"
    )

    print(
        f"ATT&CK platform universe : "
        f"{len(attack_platforms)}"
    )

    print()

    print(
        "Product-supported platforms:"
    )

    for platform in attack_platforms:
        print(
            f"  {platform}"
        )

    print()

    print(
        f"Observed platforms       : "
        f"{len(observed_platforms)}"
    )

    for platform in sorted(
        observed_platforms
    ):
        item = next(
            row
            for row in platform_catalog
            if row["platform"] == platform
        )

        print(
            f"  {platform:<18} "
            f"telemetry=observed "
            f"evidence={item['evidence_count']} "
            f"confidence={item['confidence']}"
        )

    print()

    print(
        f"Unknown presence         : "
        f"{len(unknown_platforms)}"
    )

    for platform in unknown_platforms:
        print(
            f"  {platform}"
        )

    print()

    print(
        f"Platform evidence rows   : "
        f"{len(findings)}"
    )

    print(
        f"Validation               : "
        f"{status}"
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
        f"Profile  : {PROFILE_OUTPUT}"
    )

    print(
        f"Catalog  : {PLATFORM_CATALOG_OUTPUT}"
    )

    print(
        f"Report   : {REPORT_OUTPUT}"
    )


if __name__ == "__main__":
    main()