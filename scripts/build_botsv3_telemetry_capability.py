from __future__ import annotations

import csv
import json
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

BASE = (
    ROOT
    / "datasets"
    / "processed"
    / "botsv3"
)

MAPPING = (
    BASE
    / "mappings"
    / "botsv3_canonical_field_mapping_v1_2.csv"
)

SEARCH_INVENTORY = (
    BASE
    / "profiling"
    / "sourcetype_search_inventory.csv"
)

OUTPUT_DIR = BASE / "telemetry"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

MATRIX_OUTPUT = (
    OUTPUT_DIR
    / "botsv3_telemetry_capability_matrix.csv"
)

FIELD_OUTPUT = (
    OUTPUT_DIR
    / "botsv3_canonical_field_coverage.csv"
)

SUMMARY_OUTPUT = (
    OUTPUT_DIR
    / "botsv3_telemetry_capability_summary.json"
)


CAPABILITIES = {
    "host_context": [
        "host.name",
        "host.id",
    ],

    "identity": [
        "user.name",
        "user.id",
        "user.context.name",
    ],

    "authentication": [
        "user.name",
        "authentication.logon_id",
        "authentication.logon_type",
        "source.ip",
    ],

    "process": [
        "process.name",
        "process.pid",
        "process.command_line",
        "process.parent.pid",
        "process.working_directory",
    ],

    "network_connection": [
        "source.ip",
        "source.port",
        "destination.ip",
        "destination.port",
        "network.protocol",
        "network.transport",
        "network.application",
        "network.flow.id",
    ],

    "dns": [
        "dns.question.name",
        "dns.question.type",
        "dns.response.code",
        "dns.transaction.id",
        "dns.message.type",
    ],

    "file": [
        "file.name",
        "file.path",
    ],

    "service": [
        "service.name",
    ],

    "web": [
        "http.response.bytes",
    ],

    "database": [
        "database.query",
    ],

    "cloud": [
        "cloud.region",
    ],
}


with MAPPING.open(
    "r",
    encoding="utf-8-sig",
    newline="",
) as f:
    mappings = list(csv.DictReader(f))

if len(mappings) != 4502:
    raise RuntimeError(
        f"Expected 4502 mapping rows, found {len(mappings)}"
    )


with SEARCH_INVENTORY.open(
    "r",
    encoding="utf-8-sig",
    newline="",
) as f:
    inventory = list(csv.DictReader(f))

if len(inventory) != 107:
    raise RuntimeError(
        f"Expected 107 sourcetypes, found {len(inventory)}"
    )


inventory_by_st = {
    r["sourcetype"]: r
    for r in inventory
}


# Maximum observed availability for each
# canonical field within each sourcetype.
#
# We deliberately do not sum aliases because aliases
# may overlap on the same event.
field_availability = defaultdict(dict)


for row in mappings:

    if row["mapping_status"] != "mapped":
        continue

    canonical = row["canonical_field"]

    if not canonical:
        continue

    st = row["sourcetype"]

    availability = float(
        row.get("availability_pct") or 0
    )

    previous = field_availability[st].get(
        canonical,
        0.0,
    )

    field_availability[st][canonical] = max(
        previous,
        availability,
    )


matrix_rows = []


for st in sorted(inventory_by_st):

    inv = inventory_by_st[st]

    search_rows = int(
        float(inv["search_rows"])
    )

    unique_events = int(
        float(inv["unique_events"])
    )

    st_fields = field_availability.get(
        st,
        {},
    )

    for capability, expected_fields in CAPABILITIES.items():

        observed = [
            field
            for field in expected_fields
            if field in st_fields
        ]

        expected_count = len(
            expected_fields
        )

        observed_count = len(
            observed
        )

        field_coverage_pct = (
            observed_count
            / expected_count
            * 100.0
        )

        weighted_coverage = (
            sum(
                st_fields.get(field, 0.0)
                for field in expected_fields
            )
            / expected_count
        )

        matrix_rows.append(
            {
                "sourcetype": st,
                "capability": capability,
                "search_rows": search_rows,
                "unique_events": unique_events,
                "expected_field_count": expected_count,
                "observed_field_count": observed_count,
                "field_coverage_pct": round(
                    field_coverage_pct,
                    6,
                ),
                "availability_weighted_coverage_pct": round(
                    weighted_coverage,
                    6,
                ),
                "observed": (
                    "yes"
                    if observed_count > 0
                    else "no"
                ),
                "expected_fields": " | ".join(
                    expected_fields
                ),
                "observed_fields": " | ".join(
                    observed
                ),
            }
        )


matrix_fields = [
    "sourcetype",
    "capability",
    "search_rows",
    "unique_events",
    "expected_field_count",
    "observed_field_count",
    "field_coverage_pct",
    "availability_weighted_coverage_pct",
    "observed",
    "expected_fields",
    "observed_fields",
]


with MATRIX_OUTPUT.open(
    "w",
    encoding="utf-8",
    newline="",
) as f:

    writer = csv.DictWriter(
        f,
        fieldnames=matrix_fields,
    )

    writer.writeheader()
    writer.writerows(matrix_rows)


# --------------------------------------------------
# Canonical field coverage across the entire dataset
# --------------------------------------------------

canonical_stats = defaultdict(
    lambda: {
        "sourcetypes": set(),
        "max_availability_pct": 0.0,
        "availability_sum": 0.0,
        "availability_count": 0,
    }
)


for st, fields in field_availability.items():

    for canonical, availability in fields.items():

        item = canonical_stats[canonical]

        item["sourcetypes"].add(st)

        item["max_availability_pct"] = max(
            item["max_availability_pct"],
            availability,
        )

        item["availability_sum"] += availability
        item["availability_count"] += 1


field_rows = []


for canonical, data in canonical_stats.items():

    mean_availability = (
        data["availability_sum"]
        / data["availability_count"]
        if data["availability_count"]
        else 0
    )

    field_rows.append(
        {
            "canonical_field": canonical,
            "sourcetype_count": len(
                data["sourcetypes"]
            ),
            "max_availability_pct": round(
                data["max_availability_pct"],
                6,
            ),
            "mean_availability_pct": round(
                mean_availability,
                6,
            ),
            "example_sourcetypes": " | ".join(
                sorted(
                    data["sourcetypes"]
                )[:15]
            ),
        }
    )


field_rows.sort(
    key=lambda r: (
        -r["sourcetype_count"],
        r["canonical_field"],
    )
)


with FIELD_OUTPUT.open(
    "w",
    encoding="utf-8",
    newline="",
) as f:

    writer = csv.DictWriter(
        f,
        fieldnames=[
            "canonical_field",
            "sourcetype_count",
            "max_availability_pct",
            "mean_availability_pct",
            "example_sourcetypes",
        ],
    )

    writer.writeheader()
    writer.writerows(field_rows)


invalid_matrix_rows = [
    row
    for row in matrix_rows
    if not (
        0 <= row["field_coverage_pct"] <= 100
        and
        0 <= row[
            "availability_weighted_coverage_pct"
        ] <= 100
    )
]


summary = {
    "dataset": "BOTS v3",
    "canonical_mapping_version": "botsv3-canonical-v1.2",
    "sourcetypes": len(inventory),
    "capabilities_defined": len(CAPABILITIES),
    "matrix_rows": len(matrix_rows),
    "canonical_fields_observed": len(field_rows),
    "unique_searchable_events": sum(
        int(float(r["unique_events"]))
        for r in inventory
    ),
    "search_time_rows": sum(
        int(float(r["search_rows"]))
        for r in inventory
    ),
    "invalid_matrix_rows": len(
        invalid_matrix_rows
    ),
    "status": (
        "PASS"
        if (
            len(inventory) == 107
            and len(matrix_rows)
            == 107 * len(CAPABILITIES)
            and not invalid_matrix_rows
        )
        else "FAIL"
    ),
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
print(f"Capability matrix: {MATRIX_OUTPUT}")
print(f"Field coverage:     {FIELD_OUTPUT}")
print(f"Summary:            {SUMMARY_OUTPUT}")
