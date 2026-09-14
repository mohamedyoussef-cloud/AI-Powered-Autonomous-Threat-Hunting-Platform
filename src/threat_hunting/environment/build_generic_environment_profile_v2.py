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

INVENTORY_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "telemetry"
    / "canonical"
    / "canonical_telemetry_inventory_v1.jsonl"
)

POLICY_FILE = (
    PROJECT_ROOT
    / "config"
    / "ingestion"
    / "platform_discovery_policy_v2.json"
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
    / "environment_profile_product_v2.json"
)

CATALOG_OUTPUT = (
    OUTPUT_DIR
    / "environment_platform_catalog_v2.jsonl"
)

REPORT_OUTPUT = (
    REPORT_DIR
    / "environment_profile_product_v2_summary.json"
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
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    f"Invalid JSONL at "
                    f"{path}:{line_number}: {exc}"
                ) from exc

            if not isinstance(value, dict):
                raise RuntimeError(
                    f"JSONL record at "
                    f"{path}:{line_number} "
                    f"is not an object"
                )

            rows.append(value)

    return rows


def normalize(value):
    return str(
        value or ""
    ).strip().lower()


def attack_platform_universe(
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


def make_evidence(
    record,
    platform,
    field,
    value,
    confidence,
    reason,
    evidence_type,
    matched_pattern=None,
):
    return {
        "platform": platform,
        "record_id": (
            record.get("record_id")
        ),
        "environment_id": (
            record.get("environment_id")
        ),
        "source_id": (
            record.get("source_id")
        ),
        "dataset_name": (
            record.get("dataset_name")
        ),
        "connector_type": (
            record.get("connector_type")
        ),
        "record_type": (
            record.get("record_type")
        ),
        "field": field,
        "observed_value": value,
        "matched_pattern": (
            matched_pattern
        ),
        "evidence_type": (
            evidence_type
        ),
        "event_count": (
            record.get("event_count")
        ),
        "confidence": round(
            float(confidence),
            2
        ),
        "reason": reason,
    }


def main():
    for path in [
        ATTACK_FILE,
        INVENTORY_FILE,
        POLICY_FILE,
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

    inventory = read_jsonl(
        INVENTORY_FILE
    )

    policy = json.loads(
        POLICY_FILE.read_text(
            encoding="utf-8"
        )
    )

    platform_universe = (
        attack_platform_universe(
            techniques
        )
    )

    platform_set = set(
        platform_universe
    )

    rules = policy.get(
        "rules",
        []
    )

    explicit_confidence = float(
        policy.get(
            "explicit_platform_hint_confidence",
            1.0
        )
    )

    validation_errors = []

    invalid_rule_platforms = sorted({
        rule.get("platform")
        for rule in rules
        if rule.get("platform")
        not in platform_set
    })

    if invalid_rule_platforms:
        validation_errors.append(
            "Discovery rules contain "
            "non-ATT&CK platforms: "
            + ", ".join(
                invalid_rule_platforms
            )
        )

    evidence_by_platform = defaultdict(
        list
    )

    evidence_keys = set()

    def add_evidence(evidence):
        key = (
            evidence["platform"],
            evidence["record_id"],
            evidence["field"],
            evidence["matched_pattern"],
            evidence["evidence_type"],
        )

        if key in evidence_keys:
            return

        evidence_keys.add(key)

        evidence_by_platform[
            evidence["platform"]
        ].append(
            evidence
        )

    # Highest quality signal:
    # adapter-provided explicit platform_hint.
    for record in inventory:
        hint = record.get(
            "platform_hint"
        )

        if (
            hint
            and hint in platform_set
            and hint != "PRE"
        ):
            add_evidence(
                make_evidence(
                    record=record,
                    platform=hint,
                    field="platform_hint",
                    value=hint,
                    confidence=(
                        explicit_confidence
                    ),
                    reason=(
                        "Explicit canonical "
                        "platform hint provided "
                        "by source adapter"
                    ),
                    evidence_type=(
                        "explicit_platform_hint"
                    ),
                )
            )

    # Generic signatures over canonical fields.
    for record in inventory:
        for rule in rules:
            platform = rule[
                "platform"
            ]

            field = rule[
                "field"
            ]

            raw_value = record.get(
                field
            )

            normalized_value = normalize(
                raw_value
            )

            if not normalized_value:
                continue

            for pattern in rule.get(
                "patterns",
                []
            ):
                normalized_pattern = (
                    normalize(pattern)
                )

                if (
                    normalized_pattern
                    not in normalized_value
                ):
                    continue

                add_evidence(
                    make_evidence(
                        record=record,
                        platform=platform,
                        field=field,
                        value=raw_value,
                        matched_pattern=pattern,
                        confidence=rule[
                            "confidence"
                        ],
                        reason=rule[
                            "reason"
                        ],
                        evidence_type=(
                            "canonical_signature"
                        ),
                    )
                )

    platform_catalog = []

    observed_platforms = []
    unknown_platforms = []

    for platform in platform_universe:
        evidence = evidence_by_platform.get(
            platform,
            []
        )

        if platform == "PRE":
            row = {
                "platform": platform,

                "product_supported": True,

                "presence_status": (
                    "special_attack_scope"
                ),

                "telemetry_status": (
                    "not_applicable_runtime_telemetry"
                ),

                "current_environment_state": (
                    "pre_attack_scope"
                ),

                "confidence": None,

                "evidence_count": 0,

                "evidence_datasets": [],

                "evidence": [],

                "collection_gap": False,

                "collection_gap_reason": None,
            }

        elif evidence:
            confidence = max(
                item["confidence"]
                for item in evidence
            )

            datasets = sorted({
                item["dataset_name"]
                for item in evidence
                if item.get(
                    "dataset_name"
                )
            })

            row = {
                "platform": platform,

                "product_supported": True,

                "presence_status": (
                    "inferred_present_from_telemetry"
                ),

                "telemetry_status": (
                    "observed"
                ),

                "current_environment_state": (
                    "active_observed_platform"
                ),

                "confidence": round(
                    confidence,
                    2
                ),

                "evidence_count": len(
                    evidence
                ),

                "evidence_datasets": (
                    datasets
                ),

                "evidence": evidence,

                "collection_gap": False,

                "collection_gap_reason": None,
            }

            observed_platforms.append(
                platform
            )

        else:
            row = {
                "platform": platform,

                "product_supported": True,

                "presence_status": (
                    "unknown"
                ),

                "telemetry_status": (
                    "not_observed_in_current_inputs"
                ),

                "current_environment_state": (
                    "environment_unknown"
                ),

                "confidence": None,

                "evidence_count": 0,

                "evidence_datasets": [],

                "evidence": [],

                "collection_gap": False,

                "collection_gap_reason": None,
            }

            unknown_platforms.append(
                platform
            )

        row["interpretation"] = (
            "Product support, environment "
            "presence, and telemetry observation "
            "are separate concepts. Missing "
            "telemetry does not prove that a "
            "platform is absent or unsupported."
        )

        platform_catalog.append(
            row
        )

    if len(techniques) != 697:
        validation_errors.append(
            f"Expected 697 active ATT&CK "
            f"techniques, found "
            f"{len(techniques)}"
        )

    if len(platform_universe) != 11:
        validation_errors.append(
            f"Expected 11 ATT&CK platforms, "
            f"found {len(platform_universe)}"
        )

    if len(platform_catalog) != 11:
        validation_errors.append(
            "Platform catalog does not "
            "contain all ATT&CK platforms"
        )

    unsupported = [
        row["platform"]
        for row in platform_catalog
        if not row[
            "product_supported"
        ]
    ]

    if unsupported:
        validation_errors.append(
            "Some ATT&CK platforms were "
            "incorrectly marked unsupported"
        )

    state_total = (
        len(observed_platforms)
        + len(unknown_platforms)
        + 1
    )

    if state_total != 11:
        validation_errors.append(
            "Platform states do not "
            "reconcile to 11"
        )

    environment_ids = sorted({
        row.get(
            "environment_id"
        )
        for row in inventory
        if row.get(
            "environment_id"
        )
    })

    if len(environment_ids) != 1:
        validation_errors.append(
            "Canonical inventory must represent "
            "exactly one environment per profiler run"
        )

    environment_id = (
        environment_ids[0]
        if len(environment_ids) == 1
        else None
    )

    validation_status = (
        "PASS"
        if not validation_errors
        else "FAIL"
    )

    profile = {
        "profile_version": "2.0",

        "profile_mode": (
            "generic_canonical_environment_discovery"
        ),

        "environment_id": (
            environment_id
        ),

        "generated_at_utc": (
            datetime.now(
                timezone.utc
            ).isoformat()
        ),

        "input_contract": (
            "canonical_telemetry_inventory_v1"
        ),

        "product_platform_universe": (
            platform_universe
        ),

        "product_supported_platforms": (
            platform_universe
        ),

        "observed_platforms": sorted(
            observed_platforms
        ),

        "unknown_platform_presence": (
            sorted(
                unknown_platforms
            )
        ),

        "platform_states": (
            platform_catalog
        ),

        "inventory_record_count": len(
            inventory
        ),

        "asset_inventory": {
            "available": False
        },

        "incident_history": {
            "available": False
        },

        "client_detection_coverage": {
            "available": False
        },

        "semantics": {
            "observed_platform": (
                "Telemetry evidence supports "
                "inference that the platform is "
                "present in the current environment."
            ),

            "unknown_platform": (
                "No current evidence establishes "
                "presence or absence."
            ),

            "collection_gap": (
                "May only be asserted when "
                "independent environment inventory "
                "confirms platform presence while "
                "required telemetry is unavailable."
            ),

            "product_supported": (
                "All ATT&CK platforms remain "
                "inside product scope regardless "
                "of current environment evidence."
            ),
        },
    }

    PROFILE_OUTPUT.write_text(
        json.dumps(
            profile,
            indent=2,
            ensure_ascii=False
        ),
        encoding="utf-8"
    )

    with CATALOG_OUTPUT.open(
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
            "generic_environment_profiler"
        ),

        "version": "2.0",

        "input_contract": (
            "canonical_telemetry_inventory_v1"
        ),

        "canonical_inventory_records": (
            len(inventory)
        ),

        "master_attack_techniques": (
            len(techniques)
        ),

        "attack_platform_count": (
            len(platform_universe)
        ),

        "product_supported_platform_count": (
            len(platform_catalog)
        ),

        "observed_platform_count": (
            len(observed_platforms)
        ),

        "observed_platforms": sorted(
            observed_platforms
        ),

        "unknown_platform_count": (
            len(unknown_platforms)
        ),

        "unknown_platforms": sorted(
            unknown_platforms
        ),

        "special_scope_platforms": [
            "PRE"
        ],

        "platform_evidence_records": sum(
            len(values)
            for values
            in evidence_by_platform.values()
        ),

        "validation_errors": (
            validation_errors
        ),

        "status": validation_status,
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
        "Generic Environment Profiler v2.0"
    )

    print(
        "---------------------------------"
    )

    print(
        f"Canonical inventory      : "
        f"{len(inventory)}"
    )

    print(
        f"Master ATT&CK techniques : "
        f"{len(techniques)}"
    )

    print(
        f"ATT&CK platform universe : "
        f"{len(platform_universe)}"
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
            f"evidence="
            f"{item['evidence_count']} "
            f"confidence="
            f"{item['confidence']}"
        )

    print()

    print(
        f"Unknown presence         : "
        f"{len(unknown_platforms)}"
    )

    for platform in sorted(
        unknown_platforms
    ):
        print(
            f"  {platform}"
        )

    print()

    print(
        "PRE                     : "
        "special_attack_scope"
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
        f"Profile : {PROFILE_OUTPUT}"
    )

    print(
        f"Catalog : {CATALOG_OUTPUT}"
    )

    print(
        f"Report  : {REPORT_OUTPUT}"
    )


if __name__ == "__main__":
    main()