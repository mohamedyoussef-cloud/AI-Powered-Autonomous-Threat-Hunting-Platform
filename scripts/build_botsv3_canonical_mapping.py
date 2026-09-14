from __future__ import annotations

import csv
import json
import re
from collections import defaultdict
from pathlib import Path


# Portable root:
# ...\ThreatHunting\project\scripts\this_file.py
#                ^ parents[2] = ThreatHunting
ROOT = Path(__file__).resolve().parents[2]

MASTER = (
    ROOT
    / "datasets"
    / "processed"
    / "botsv3"
    / "profiling"
    / "botsv3_master_field_profile.csv"
)

OUTPUT_DIR = (
    ROOT
    / "datasets"
    / "processed"
    / "botsv3"
    / "mappings"
)

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

MAPPING_OUTPUT = OUTPUT_DIR / "botsv3_canonical_field_mapping.csv"
UNMAPPED_OUTPUT = OUTPUT_DIR / "botsv3_unmapped_field_candidates.csv"
SUMMARY_OUTPUT = OUTPUT_DIR / "botsv3_canonical_mapping_summary.json"

MAPPING_VERSION = "botsv3-canonical-v1.0"


def normalize_field(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9]+", "_", value)
    return value.strip("_")


# Approved high-confidence aliases.
ALIASES = {
    "source.file": {
        "source",
    },
    "source.sourcetype": {
        "sourcetype",
    },
    "source.record_id": {
        "_cd",
    },
    "event.original": {
        "_raw",
        "raw_event",
        "event_original",
    },
    "event.timestamp": {
        "_time",
        "timestamp",
        "event_time",
        "eventtime",
        "system_time",
        "systemtime",
    },
    "event.code": {
        "eventcode",
        "event_code",
        "eventid",
        "event_id",
    },
    "event.action": {
        "action",
        "event_action",
    },
    "event.outcome": {
        "outcome",
        "event_outcome",
    },
    "host.name": {
        "host",
        "hostname",
        "computer",
        "computername",
        "computer_name",
    },
    "host.id": {
        "host_id",
        "hostid",
    },
    "host.ip": {
        "host_ip",
        "hostip",
    },
    "user.name": {
        "user",
        "username",
        "user_name",
        "account_name",
        "accountname",
    },
    "user.domain": {
        "user_domain",
        "userdomain",
    },
    "user.id": {
        "user_id",
        "userid",
        "uid",
    },
    "process.name": {
        "process_name",
        "processname",
    },
    "process.executable": {
        "process_executable",
        "executable",
        "process_path",
        "processpath",
    },
    "process.command_line": {
        "commandline",
        "command_line",
        "process_command_line",
        "processcommandline",
    },
    "process.pid": {
        "process_id",
        "processid",
        "process_pid",
        "pid",
    },
    "process.parent.pid": {
        "parent_process_id",
        "parentprocessid",
        "parent_pid",
        "ppid",
    },
    "process.parent.name": {
        "parent_process_name",
        "parentprocessname",
    },
    "process.parent.executable": {
        "parent_process_path",
        "parentprocesspath",
        "parent_image",
        "parentimage",
    },
    "source.ip": {
        "src",
        "src_ip",
        "srcip",
        "source_ip",
        "sourceip",
        "source_address",
        "sourceaddress",
    },
    "source.port": {
        "src_port",
        "srcport",
        "source_port",
        "sourceport",
    },
    "destination.ip": {
        "dest",
        "dst",
        "dest_ip",
        "dst_ip",
        "destip",
        "dstip",
        "destination_ip",
        "destinationip",
    },
    "destination.port": {
        "dest_port",
        "dst_port",
        "destport",
        "dstport",
        "destination_port",
        "destinationport",
    },
    "network.protocol": {
        "protocol",
        "proto",
        "network_protocol",
        "transport_protocol",
    },
    "network.direction": {
        "direction",
        "network_direction",
    },
    "authentication.outcome": {
        "authentication_outcome",
        "auth_outcome",
        "auth_result",
        "login_result",
        "logon_result",
    },
    "authentication.type": {
        "authentication_type",
        "auth_type",
    },
    "authentication.logon_id": {
        "logon_id",
        "logonid",
    },
    "authentication.logon_type": {
        "logon_type",
        "logontype",
    },
    "file.path": {
        "file_path",
        "filepath",
        "target_filename",
        "targetfilename",
    },
    "file.name": {
        "file_name",
        "filename",
    },
    "registry.path": {
        "registry_path",
        "registrypath",
    },
    "service.name": {
        "service_name",
        "servicename",
    },
    "application.name": {
        "application_name",
        "app_name",
    },
    "cloud.account.id": {
        "cloud_account_id",
        "aws_account_id",
        "awsaccountid",
    },
    "cloud.region": {
        "cloud_region",
        "aws_region",
        "awsregion",
    },
    "message": {
        "message",
        "msg",
    },
}


REVERSE_ALIASES = {}

for canonical, aliases in ALIASES.items():
    for alias in aliases:
        key = normalize_field(alias)

        if key in REVERSE_ALIASES:
            raise RuntimeError(
                f"Duplicate alias mapping detected: {alias}"
            )

        REVERSE_ALIASES[key] = canonical


def contextual_mapping(sourcetype: str, field: str):
    st = sourcetype.lower()
    nf = normalize_field(field)

    # Preserve role-specific user semantics.
    if nf == "subjectusername":
        return "user.subject.name", "context_rule", "high"

    if nf == "targetusername":
        return "user.target.name", "context_rule", "high"

    if nf in {"src_user", "source_user"}:
        return "user.source.name", "context_rule", "high"

    if nf in {"dest_user", "destination_user"}:
        return "user.destination.name", "context_rule", "high"

    # Windows process fields.
    windows_like = (
        "wineventlog" in st
        or "xmlwineventlog" in st
        or "sysmon" in st
    )

    if windows_like and nf in {"image", "newprocessname"}:
        return "process.executable", "context_rule", "high"

    if windows_like and nf == "parentimage":
        return "process.parent.executable", "context_rule", "high"

    # Common Windows network/logon field.
    if windows_like and nf == "ipaddress":
        return "source.ip", "context_rule", "high"

    if nf == "destinationip":
        return "destination.ip", "context_rule", "high"

    return None


with MASTER.open("r", encoding="utf-8-sig", newline="") as f:
    master_rows = list(csv.DictReader(f))

if not master_rows:
    raise RuntimeError("Master BOTS profile is empty.")

if len(master_rows) != 4502:
    raise RuntimeError(
        f"Expected 4502 master profile rows, found {len(master_rows)}"
    )


mapping_rows = []
unmapped_aggregate = defaultdict(
    lambda: {
        "fields": set(),
        "sourcetypes": set(),
        "total_present_count": 0,
        "max_availability_pct": 0.0,
    }
)


for row in master_rows:
    sourcetype = row["sourcetype"]
    source_field = row["field"]
    normalized = normalize_field(source_field)

    canonical_field = ""
    mapping_method = ""
    confidence = ""
    mapping_status = ""

    contextual = contextual_mapping(
        sourcetype=sourcetype,
        field=source_field,
    )

    if contextual:
        canonical_field, mapping_method, confidence = contextual
        mapping_status = "mapped"

    elif normalized in REVERSE_ALIASES:
        canonical_field = REVERSE_ALIASES[normalized]
        mapping_method = "approved_alias"
        confidence = "high"
        mapping_status = "mapped"

    else:
        # Do not invent semantics.
        # Preserve the source-specific field for investigation.
        mapping_status = "source_specific_retained"
        mapping_method = "extension"
        confidence = "not_applicable"

        item = unmapped_aggregate[normalized]

        item["fields"].add(source_field)
        item["sourcetypes"].add(sourcetype)
        item["total_present_count"] += int(
            float(row.get("field_present_count") or 0)
        )

        availability = float(
            row.get("availability_pct") or 0
        )

        item["max_availability_pct"] = max(
            item["max_availability_pct"],
            availability,
        )

    extension_field = (
        ""
        if canonical_field
        else f"source.fields.{normalized}"
    )

    mapping_rows.append(
        {
            "mapping_version": MAPPING_VERSION,
            "sourcetype": sourcetype,
            "source_field": source_field,
            "normalized_source_field": normalized,
            "canonical_field": canonical_field,
            "extension_field": extension_field,
            "mapping_status": mapping_status,
            "mapping_method": mapping_method,
            "confidence": confidence,
            "search_rows": row["search_rows"],
            "field_present_count": row["field_present_count"],
            "availability_pct": row["availability_pct"],
            "missingness_pct": row["missingness_pct"],
            "distinct_count": row["distinct_count"],
            "inferred_type": row["inferred_type"],
        }
    )


mapping_fieldnames = [
    "mapping_version",
    "sourcetype",
    "source_field",
    "normalized_source_field",
    "canonical_field",
    "extension_field",
    "mapping_status",
    "mapping_method",
    "confidence",
    "search_rows",
    "field_present_count",
    "availability_pct",
    "missingness_pct",
    "distinct_count",
    "inferred_type",
]

with MAPPING_OUTPUT.open(
    "w",
    encoding="utf-8",
    newline="",
) as f:
    writer = csv.DictWriter(
        f,
        fieldnames=mapping_fieldnames,
    )
    writer.writeheader()
    writer.writerows(mapping_rows)


unmapped_rows = []

for normalized, data in unmapped_aggregate.items():
    unmapped_rows.append(
        {
            "normalized_field": normalized,
            "example_source_fields": " | ".join(
                sorted(data["fields"])[:10]
            ),
            "sourcetype_count": len(data["sourcetypes"]),
            "total_present_count": data["total_present_count"],
            "max_availability_pct": round(
                data["max_availability_pct"],
                6,
            ),
            "example_sourcetypes": " | ".join(
                sorted(data["sourcetypes"])[:10]
            ),
        }
    )

unmapped_rows.sort(
    key=lambda x: (
        -x["total_present_count"],
        x["normalized_field"],
    )
)

unmapped_fieldnames = [
    "normalized_field",
    "example_source_fields",
    "sourcetype_count",
    "total_present_count",
    "max_availability_pct",
    "example_sourcetypes",
]

with UNMAPPED_OUTPUT.open(
    "w",
    encoding="utf-8",
    newline="",
) as f:
    writer = csv.DictWriter(
        f,
        fieldnames=unmapped_fieldnames,
    )
    writer.writeheader()
    writer.writerows(unmapped_rows)


mapped_rows = [
    row for row in mapping_rows
    if row["mapping_status"] == "mapped"
]

source_specific_rows = [
    row for row in mapping_rows
    if row["mapping_status"] == "source_specific_retained"
]

canonical_fields = sorted(
    {
        row["canonical_field"]
        for row in mapped_rows
        if row["canonical_field"]
    }
)

sourcetypes = {
    row["sourcetype"]
    for row in mapping_rows
}

unclassified = [
    row for row in mapping_rows
    if row["mapping_status"] not in {
        "mapped",
        "source_specific_retained",
    }
]


summary = {
    "dataset": "BOTS v3",
    "mapping_version": MAPPING_VERSION,
    "master_profile_rows": len(master_rows),
    "mapping_rows": len(mapping_rows),
    "sourcetypes": len(sourcetypes),
    "mapped_rows": len(mapped_rows),
    "source_specific_retained_rows": len(source_specific_rows),
    "mapped_row_pct": round(
        (len(mapped_rows) / len(mapping_rows)) * 100,
        4,
    ),
    "canonical_fields_count": len(canonical_fields),
    "canonical_fields": canonical_fields,
    "unmapped_candidate_fields": len(unmapped_rows),
    "unclassified_rows": len(unclassified),
    "semantic_review_required": True,
    "status": (
        "PASS"
        if (
            len(mapping_rows) == 4502
            and len(sourcetypes) == 107
            and len(unclassified) == 0
        )
        else "FAIL"
    ),
}

with SUMMARY_OUTPUT.open(
    "w",
    encoding="utf-8",
) as f:
    json.dump(summary, f, indent=2)


print(json.dumps(summary, indent=2))
print()
print(f"Mapping matrix:       {MAPPING_OUTPUT}")
print(f"Unmapped candidates:  {UNMAPPED_OUTPUT}")
print(f"Summary:              {SUMMARY_OUTPUT}")
