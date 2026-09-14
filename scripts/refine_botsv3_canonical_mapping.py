from __future__ import annotations

import csv
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

MAPPING_DIR = (
    ROOT
    / "datasets"
    / "processed"
    / "botsv3"
    / "mappings"
)

INPUT = MAPPING_DIR / "botsv3_canonical_field_mapping.csv"

OUTPUT = MAPPING_DIR / "botsv3_canonical_field_mapping_v1_1.csv"
REVIEW_OUTPUT = MAPPING_DIR / "botsv3_semantic_review_candidates_v1_1.csv"
SUMMARY_OUTPUT = MAPPING_DIR / "botsv3_canonical_mapping_summary_v1_1.json"

VERSION = "botsv3-canonical-v1.1"


PLATFORM_METADATA = {
    "index",
    "linecount",
    "splunk_server",
    "punct",
    "date_hour",
    "date_mday",
    "date_minute",
    "date_month",
    "date_wday",
    "date_year",
    "date_zone",
    "date_second",
    "timeendpos",
    "timestartpos",
}


SAFE_GLOBAL = {
    "bytes_in": "network.bytes.in",
    "bytes_out": "network.bytes.out",
    "flow_id": "network.flow.id",
    "src_mac": "source.mac",
    "dest_mac": "destination.mac",
    "packets_in": "network.packets.in",
    "packets_out": "network.packets.out",
}


def contextual_mapping(sourcetype: str, field: str):
    st = sourcetype.lower()
    nf = field.lower()

    # Splunk Stream family
    if st.startswith("stream:"):

        if nf == "protocol_stack":
            return "network.protocol_stack"

        if nf == "bytes":
            return "network.bytes.total"

        if nf == "app":
            return "network.application"

    # DNS semantic query
    if st == "stream:dns" and nf in {"query", "query{}"}:
        return "dns.question.name"

    # SQL semantic query
    if st == "stream:mysql" and nf in {"query", "query{}"}:
        return "database.query"

    # Apache access response size
    if st == "access_combined" and nf == "bytes":
        return "http.response.bytes"

    # osquery envelope metadata
    if st == "osquery:results":

        if nf in {"calendartime", "unixtime"}:
            return "event.timestamp"

        if nf == "decorations_username":
            return "user.context.name"

        if nf == "decorations_host_uuid":
            return "host.id"

        if nf == "columns_pid":
            return "process.pid"

        if nf == "columns_parent":
            return "process.parent.pid"

        if nf == "columns_cmdline":
            return "process.command_line"

        if nf == "columns_cwd":
            return "process.working_directory"

        if nf == "columns_uid":
            return "user.id"

    return None


with INPUT.open("r", encoding="utf-8-sig", newline="") as f:
    rows = list(csv.DictReader(f))

if len(rows) != 4502:
    raise RuntimeError(
        f"Expected 4502 mapping rows, found {len(rows)}"
    )


updated = []

for row in rows:

    row["mapping_version"] = VERSION

    st = row["sourcetype"]
    nf = row["normalized_source_field"]

    # Preserve already-approved mappings.
    if row["mapping_status"] == "mapped":
        updated.append(row)
        continue

    # Splunk/search implementation metadata.
    if nf in PLATFORM_METADATA:
        row["canonical_field"] = ""
        row["mapping_status"] = "platform_metadata"
        row["mapping_method"] = "platform_classification"
        row["confidence"] = "high"

        updated.append(row)
        continue

    # Safe global semantic mappings.
    if nf in SAFE_GLOBAL:
        row["canonical_field"] = SAFE_GLOBAL[nf]
        row["extension_field"] = ""
        row["mapping_status"] = "mapped"
        row["mapping_method"] = "approved_alias_v1_1"
        row["confidence"] = "high"

        updated.append(row)
        continue

    # Sourcetype-aware mappings.
    canonical = contextual_mapping(st, nf)

    if canonical:
        row["canonical_field"] = canonical
        row["extension_field"] = ""
        row["mapping_status"] = "mapped"
        row["mapping_method"] = "context_rule_v1_1"
        row["confidence"] = "high"

    updated.append(row)


fieldnames = list(updated[0].keys())

with OUTPUT.open("w", encoding="utf-8", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(updated)


mapped = [
    r for r in updated
    if r["mapping_status"] == "mapped"
]

platform = [
    r for r in updated
    if r["mapping_status"] == "platform_metadata"
]

retained = [
    r for r in updated
    if r["mapping_status"] == "source_specific_retained"
]

unclassified = [
    r for r in updated
    if r["mapping_status"] not in {
        "mapped",
        "platform_metadata",
        "source_specific_retained",
    }
]


# Semantic review candidates:
# source-specific fields only, ranked by occurrence.
review = sorted(
    retained,
    key=lambda r: int(float(r["field_present_count"] or 0)),
    reverse=True,
)

review_fields = [
    "sourcetype",
    "source_field",
    "normalized_source_field",
    "field_present_count",
    "availability_pct",
    "missingness_pct",
    "distinct_count",
    "inferred_type",
]

with REVIEW_OUTPUT.open(
    "w",
    encoding="utf-8",
    newline="",
) as f:
    writer = csv.DictWriter(
        f,
        fieldnames=review_fields,
        extrasaction="ignore",
    )
    writer.writeheader()
    writer.writerows(review)


canonical_fields = sorted({
    r["canonical_field"]
    for r in mapped
    if r["canonical_field"]
})


summary = {
    "dataset": "BOTS v3",
    "mapping_version": VERSION,
    "mapping_rows": len(updated),
    "sourcetypes": len({
        r["sourcetype"]
        for r in updated
    }),
    "mapped_rows": len(mapped),
    "platform_metadata_rows": len(platform),
    "source_specific_retained_rows": len(retained),
    "canonical_fields_count": len(canonical_fields),
    "canonical_fields": canonical_fields,
    "semantic_review_candidates": len(review),
    "unclassified_rows": len(unclassified),
    "status": (
        "PASS"
        if (
            len(updated) == 4502
            and len(unclassified) == 0
        )
        else "FAIL"
    ),
}

with SUMMARY_OUTPUT.open("w", encoding="utf-8") as f:
    json.dump(summary, f, indent=2)


print(json.dumps(summary, indent=2))
print()
print(f"Mapping v1.1:     {OUTPUT}")
print(f"Review candidates:{REVIEW_OUTPUT}")
print(f"Summary:          {SUMMARY_OUTPUT}")
