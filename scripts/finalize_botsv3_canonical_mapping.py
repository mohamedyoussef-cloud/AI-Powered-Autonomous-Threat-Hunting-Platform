from __future__ import annotations

import csv
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

DIR = (
    ROOT
    / "datasets"
    / "processed"
    / "botsv3"
    / "mappings"
)

INPUT = DIR / "botsv3_canonical_field_mapping_v1_1.csv"
OUTPUT = DIR / "botsv3_canonical_field_mapping_v1_2.csv"
SUMMARY = DIR / "botsv3_canonical_mapping_summary_v1_2.json"

VERSION = "botsv3-canonical-v1.2"


def apply_context_mapping(sourcetype: str, normalized_field: str):

    st = sourcetype.lower()
    f = normalized_field.lower()

    rules = {
        ("osquery:results", "hostidentifier"):
            "host.id",

        ("syslog", "process"):
            "process.name",

        ("stream:dns", "reply_code"):
            "dns.response.code",

        ("stream:dns", "query_type"):
            "dns.question.type",

        ("stream:dns", "transaction_id"):
            "dns.transaction.id",

        ("stream:dns", "message_type"):
            "dns.message.type",

        ("stream:dns", "transport"):
            "network.transport",

        ("stream:ip", "protoid"):
            "network.iana_number",
    }

    return rules.get((st, f))


with INPUT.open(
    "r",
    encoding="utf-8-sig",
    newline="",
) as f:
    rows = list(csv.DictReader(f))

if len(rows) != 4502:
    raise RuntimeError(
        f"Expected 4502 rows, found {len(rows)}"
    )


newly_mapped = 0

for row in rows:

    row["mapping_version"] = VERSION

    if row["mapping_status"] != "source_specific_retained":
        continue

    canonical = apply_context_mapping(
        row["sourcetype"],
        row["normalized_source_field"],
    )

    if canonical:

        row["canonical_field"] = canonical
        row["extension_field"] = ""
        row["mapping_status"] = "mapped"
        row["mapping_method"] = "approved_context_v1_2"
        row["confidence"] = "high"

        newly_mapped += 1


with OUTPUT.open(
    "w",
    encoding="utf-8",
    newline="",
) as f:

    writer = csv.DictWriter(
        f,
        fieldnames=list(rows[0].keys()),
    )

    writer.writeheader()
    writer.writerows(rows)


mapped = [
    r for r in rows
    if r["mapping_status"] == "mapped"
]

platform = [
    r for r in rows
    if r["mapping_status"] == "platform_metadata"
]

retained = [
    r for r in rows
    if r["mapping_status"] == "source_specific_retained"
]

invalid = [
    r for r in rows
    if r["mapping_status"] not in {
        "mapped",
        "platform_metadata",
        "source_specific_retained",
    }
]

canonical = sorted({
    r["canonical_field"]
    for r in mapped
    if r["canonical_field"]
})


summary = {
    "dataset": "BOTS v3",
    "mapping_version": VERSION,
    "mapping_rows": len(rows),
    "sourcetypes": len({
        r["sourcetype"]
        for r in rows
    }),
    "newly_mapped_rows": newly_mapped,
    "mapped_rows": len(mapped),
    "platform_metadata_rows": len(platform),
    "source_specific_retained_rows": len(retained),
    "canonical_fields_count": len(canonical),
    "canonical_fields": canonical,
    "unclassified_rows": len(invalid),
    "status": (
        "PASS"
        if len(rows) == 4502
        and len(invalid) == 0
        else "FAIL"
    ),
}

with SUMMARY.open(
    "w",
    encoding="utf-8",
) as f:
    json.dump(summary, f, indent=2)


print(json.dumps(summary, indent=2))
print()
print(f"Final mapping: {OUTPUT}")
print(f"Summary:       {SUMMARY}")
