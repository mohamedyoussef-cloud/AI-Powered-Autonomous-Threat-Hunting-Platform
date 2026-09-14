import csv
import json
from pathlib import Path
from datetime import datetime, timezone


PROJECT_ROOT = Path(__file__).resolve().parents[3]

TELEMETRY_SUMMARY = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "telemetry"
    / "integrated"
    / "technique_telemetry_evidence_summary_v1_1.csv"
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
    / "dynamic_environment_profile_v0_1.json"
)

REPORT_OUTPUT = (
    REPORT_DIR
    / "dynamic_environment_profile_v0_1_summary.json"
)


# These signatures are discovery evidence.
# A source only contributes a platform when the association is strong.
SOURCE_SIGNATURES = {
    "EVTX": {
        "platforms": ["Windows"],
        "confidence": 1.0,
        "reason": "Windows Event Log EVTX telemetry observed"
    },
    "SYS MON": {
        "platforms": ["Windows"],
        "confidence": 1.0,
        "reason": "Windows Sysmon telemetry observed"
    },
    "SYSMON": {
        "platforms": ["Windows"],
        "confidence": 1.0,
        "reason": "Windows Sysmon telemetry observed"
    },
    "WINDOWS EVENT LOG": {
        "platforms": ["Windows"],
        "confidence": 1.0,
        "reason": "Windows Event Log telemetry observed"
    },
    "AUDITD": {
        "platforms": ["Linux"],
        "confidence": 1.0,
        "reason": "Linux auditd telemetry observed"
    },
    "JOURNALD": {
        "platforms": ["Linux"],
        "confidence": 1.0,
        "reason": "Linux journald telemetry observed"
    },
    "LINUX AUDIT": {
        "platforms": ["Linux"],
        "confidence": 1.0,
        "reason": "Linux audit telemetry observed"
    },
    "MACOS UNIFIED LOG": {
        "platforms": ["macOS"],
        "confidence": 1.0,
        "reason": "macOS Unified Log telemetry observed"
    },
    "CLOUDTRAIL": {
        "platforms": ["IaaS"],
        "cloud_providers": ["AWS"],
        "confidence": 0.95,
        "reason": "AWS CloudTrail telemetry observed"
    },
    "AZURE ACTIVITY": {
        "platforms": ["IaaS"],
        "cloud_providers": ["Azure"],
        "confidence": 0.95,
        "reason": "Azure activity telemetry observed"
    },
    "GCP AUDIT": {
        "platforms": ["IaaS"],
        "cloud_providers": ["GCP"],
        "confidence": 0.95,
        "reason": "GCP audit telemetry observed"
    }
}


def read_csv(path):
    with path.open(
        "r",
        encoding="utf-8-sig",
        newline=""
    ) as f:
        return list(csv.DictReader(f))


def normalize(value):
    return str(value or "").strip().upper()


def extract_evidence_sources(rows):
    sources = set()

    for row in rows:
        raw = row.get("evidence_sources") or ""

        for item in raw.split("|"):
            item = item.strip()

            if item:
                sources.add(item)

    return sorted(sources)


def discover_environment(source_inventory):
    platform_scores = {}
    platform_reasons = {}

    cloud_providers = set()

    matched_sources = []
    unmatched_sources = []

    for source in source_inventory:
        normalized_source = normalize(source)
        matched = False

        for signature, metadata in SOURCE_SIGNATURES.items():
            if signature in normalized_source:
                matched = True

                matched_sources.append({
                    "source": source,
                    "signature": signature,
                    "confidence": metadata["confidence"],
                    "reason": metadata["reason"]
                })

                for platform in metadata.get(
                    "platforms",
                    []
                ):
                    previous = platform_scores.get(
                        platform,
                        0.0
                    )

                    platform_scores[platform] = max(
                        previous,
                        metadata["confidence"]
                    )

                    platform_reasons.setdefault(
                        platform,
                        []
                    ).append(
                        metadata["reason"]
                    )

                for provider in metadata.get(
                    "cloud_providers",
                    []
                ):
                    cloud_providers.add(provider)

        if not matched:
            unmatched_sources.append(source)

    discovered_platforms = []

    for platform, confidence in sorted(
        platform_scores.items(),
        key=lambda item: (
            -item[1],
            item[0]
        )
    ):
        discovered_platforms.append({
            "platform": platform,
            "confidence": round(
                confidence,
                2
            ),
            "reasons": sorted(
                set(
                    platform_reasons.get(
                        platform,
                        []
                    )
                )
            )
        })

    return {
        "discovered_platforms": discovered_platforms,
        "cloud_providers": sorted(
            cloud_providers
        ),
        "matched_sources": matched_sources,
        "unmatched_sources": unmatched_sources,
    }


def main():
    if not TELEMETRY_SUMMARY.exists():
        raise FileNotFoundError(
            f"Missing input: {TELEMETRY_SUMMARY}"
        )

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    rows = read_csv(
        TELEMETRY_SUMMARY
    )

    source_inventory = extract_evidence_sources(
        rows
    )

    discovery = discover_environment(
        source_inventory
    )

    platforms = [
        item["platform"]
        for item in discovery[
            "discovered_platforms"
        ]
    ]

    profile = {
        "profile_version": "0.1",
        "profile_mode": "dynamic_discovery",
        "environment_id": "auto-discovered-reference",
        "environment_name": (
            "Auto-Discovered Threat Hunting Environment"
        ),
        "generated_at_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "platforms": platforms,
        "platform_discovery": discovery[
            "discovered_platforms"
        ],
        "cloud_providers": discovery[
            "cloud_providers"
        ],
        "telemetry_source_inventory": (
            source_inventory
        ),
        "matched_discovery_sources": discovery[
            "matched_sources"
        ],
        "unmatched_discovery_sources": discovery[
            "unmatched_sources"
        ],
        "assets": [],
        "incident_history": [],
        "detection_coverage": [],
        "unknown_context": {
            "assets": True,
            "asset_criticality": True,
            "incident_history": True,
            "client_detection_coverage": True
        },
        "discovery_policy": {
            "do_not_infer_platform_without_evidence": True,
            "do_not_infer_assets": True,
            "do_not_infer_incident_history": True,
            "do_not_infer_detection_coverage": True
        }
    }

    validation_errors = []

    if not source_inventory:
        validation_errors.append(
            "No telemetry sources discovered"
        )

    if not platforms:
        validation_errors.append(
            "No platform could be inferred from "
            "strong telemetry evidence"
        )

    validation = (
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

    report = {
        "component": (
            "dynamic_environment_profiler"
        ),
        "version": "0.1",
        "input_techniques": len(rows),
        "telemetry_sources_discovered": len(
            source_inventory
        ),
        "platforms_discovered": platforms,
        "cloud_providers_discovered": (
            discovery["cloud_providers"]
        ),
        "matched_sources": len(
            discovery["matched_sources"]
        ),
        "unmatched_sources": len(
            discovery["unmatched_sources"]
        ),
        "validation_errors": (
            validation_errors
        ),
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

    print(
        "Dynamic Environment Profiler v0.1"
    )
    print(
        "---------------------------------"
    )

    print(
        f"Input techniques       : "
        f"{len(rows)}"
    )

    print(
        f"Telemetry sources      : "
        f"{len(source_inventory)}"
    )

    print(
        "Source inventory       : "
        + (
            ", ".join(source_inventory)
            if source_inventory
            else "NONE"
        )
    )

    print(
        "Platforms discovered   : "
        + (
            ", ".join(platforms)
            if platforms
            else "NONE"
        )
    )

    print(
        "Cloud providers        : "
        + (
            ", ".join(
                discovery["cloud_providers"]
            )
            if discovery["cloud_providers"]
            else "NONE"
        )
    )

    print(
        f"Matched sources        : "
        f"{len(discovery['matched_sources'])}"
    )

    print(
        f"Unmatched sources      : "
        f"{len(discovery['unmatched_sources'])}"
    )

    print(
        f"Validation             : "
        f"{validation}"
    )

    if validation_errors:
        print()
        print("Validation errors:")

        for error in validation_errors:
            print(" -", error)

    print()
    print(
        f"Profile : {PROFILE_OUTPUT}"
    )

    print(
        f"Report  : {REPORT_OUTPUT}"
    )


if __name__ == "__main__":
    main()