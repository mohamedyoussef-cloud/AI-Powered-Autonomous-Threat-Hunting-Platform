from __future__ import annotations

import csv
import gzip
import json
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

INPUT = (
    ROOT
    / "data"
    / "processed"
    / "telemetry"
    / "evtx_canonical_events_direct_29_v0_4_candidate.jsonl.gz"
)

REPORT_DIR = (
    ROOT
    / "reports"
    / "evtx_full_v0_4"
)

REPORT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)

PROFILE_OUTPUT = (
    REPORT_DIR
    / "evtx_direct_29_mapping_profile.csv"
)

WARNING_OUTPUT = (
    REPORT_DIR
    / "evtx_direct_29_warning_profile.csv"
)

SUMMARY_OUTPUT = (
    REPORT_DIR
    / "evtx_direct_29_mapping_audit_summary.json"
)


grouped = defaultdict(
    lambda: {
        "count": 0,
        "source_files": set(),
        "warnings": Counter(),
    }
)

warning_groups = defaultdict(
    lambda: {
        "count": 0,
        "source_files": set(),
    }
)

total = 0
other_count = 0


with gzip.open(
    INPUT,
    "rt",
    encoding="utf-8",
) as f:

    for line in f:

        if not line.strip():
            continue

        event = json.loads(line)
        total += 1

        ev = event["event"]

        provider = (
            ev.get("provider")
            or ""
        )

        provider_normalized = (
            ev.get("provider_normalized")
            or ""
        )

        channel = (
            ev.get("channel")
            or ""
        )

        event_id = str(
            ev.get("id")
            or ""
        )

        category = (
            ev.get("category")
            or ""
        )

        action = (
            ev.get("action")
            or ""
        )

        source_file = (
            event["lineage"]
            .get("source_file")
            or ""
        )

        warnings = (
            event["data_quality"]
            .get("mapping_warnings")
            or []
        )

        key = (
            provider,
            provider_normalized,
            channel,
            event_id,
            category,
            action,
        )

        item = grouped[key]

        item["count"] += 1
        item["source_files"].add(
            source_file
        )

        for warning in warnings:

            item["warnings"][warning] += 1

            wkey = (
                warning,
                provider,
                provider_normalized,
                channel,
                event_id,
                category,
                action,
            )

            warning_groups[
                wkey
            ]["count"] += 1

            warning_groups[
                wkey
            ]["source_files"].add(
                source_file
            )

        if category == "other":
            other_count += 1


profile_rows = []

for key, item in grouped.items():

    (
        provider,
        provider_normalized,
        channel,
        event_id,
        category,
        action,
    ) = key

    profile_rows.append(
        {
            "event_count":
                item["count"],

            "provider":
                provider,

            "provider_normalized":
                provider_normalized,

            "channel":
                channel,

            "event_id":
                event_id,

            "canonical_category":
                category,

            "canonical_action":
                action,

            "warning_count":
                sum(
                    item["warnings"].values()
                ),

            "warnings":
                " | ".join(
                    f"{k}:{v}"
                    for k, v
                    in item["warnings"].most_common()
                ),

            "unique_source_files":
                len(
                    item["source_files"]
                ),

            "example_source_files":
                " | ".join(
                    sorted(
                        item["source_files"]
                    )[:10]
                ),
        }
    )


profile_rows.sort(
    key=lambda r: (
        -r["event_count"],
        r["provider"],
        r["event_id"],
    )
)


with PROFILE_OUTPUT.open(
    "w",
    encoding="utf-8",
    newline="",
) as f:

    writer = csv.DictWriter(
        f,
        fieldnames=list(
            profile_rows[0].keys()
        ),
    )

    writer.writeheader()
    writer.writerows(
        profile_rows
    )


warning_rows = []

for key, item in warning_groups.items():

    (
        warning,
        provider,
        provider_normalized,
        channel,
        event_id,
        category,
        action,
    ) = key

    warning_rows.append(
        {
            "warning":
                warning,

            "event_count":
                item["count"],

            "provider":
                provider,

            "provider_normalized":
                provider_normalized,

            "channel":
                channel,

            "event_id":
                event_id,

            "canonical_category":
                category,

            "canonical_action":
                action,

            "unique_source_files":
                len(
                    item["source_files"]
                ),

            "example_source_files":
                " | ".join(
                    sorted(
                        item["source_files"]
                    )[:10]
                ),
        }
    )


warning_rows.sort(
    key=lambda r: (
        -r["event_count"],
        r["warning"],
    )
)


warning_fields = [
    "warning",
    "event_count",
    "provider",
    "provider_normalized",
    "channel",
    "event_id",
    "canonical_category",
    "canonical_action",
    "unique_source_files",
    "example_source_files",
]


with WARNING_OUTPUT.open(
    "w",
    encoding="utf-8",
    newline="",
) as f:

    writer = csv.DictWriter(
        f,
        fieldnames=warning_fields,
    )

    writer.writeheader()
    writer.writerows(
        warning_rows
    )


top_other = [
    row
    for row in profile_rows
    if row[
        "canonical_category"
    ] == "other"
][:20]


top_warnings = warning_rows[:20]


summary = {
    "artifact":
        "EVTX v0.4 Mapping Audit",

    "direct_events":
        total,

    "mapping_profile_rows":
        len(profile_rows),

    "other_category_events":
        other_count,

    "other_category_pct":
        round(
            other_count
            / total
            * 100,
            6,
        )
        if total
        else 0,

    "warning_events":
        sum(
            1
            for row in profile_rows
            if row[
                "warning_count"
            ] > 0
        ),

    "top_other_groups":
        top_other,

    "top_warning_groups":
        top_warnings,

    "status":
        "PASS"
        if total == 32731
        else "FAIL",
}


with SUMMARY_OUTPUT.open(
    "w",
    encoding="utf-8",
) as f:

    json.dump(
        summary,
        f,
        indent=2,
    )


print(
    json.dumps(
        summary,
        indent=2,
    )
)

print()
print(
    f"Mapping profile: {PROFILE_OUTPUT}"
)
print(
    f"Warning profile: {WARNING_OUTPUT}"
)
print(
    f"Summary:         {SUMMARY_OUTPUT}"
)
