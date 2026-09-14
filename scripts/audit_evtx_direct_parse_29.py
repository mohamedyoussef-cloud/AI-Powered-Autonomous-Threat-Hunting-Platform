from __future__ import annotations

import csv
import hashlib
import json
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

from Evtx.Evtx import Evtx


PROJECT_ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = PROJECT_ROOT.parent

RAW_ROOT = (
    WORKSPACE_ROOT
    / "datasets"
    / "raw"
    / "EVTX-ATTACK-SAMPLES"
)

INVENTORY = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "telemetry"
    / "evtx_unparsed_files.csv"
)

OUTPUT_DIR = (
    PROJECT_ROOT
    / "reports"
    / "evtx_direct_parse"
)

OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)

AUDIT_OUTPUT = (
    OUTPUT_DIR
    / "evtx_direct_parse_29_audit.csv"
)

SUMMARY_OUTPUT = (
    OUTPUT_DIR
    / "evtx_direct_parse_29_summary.json"
)


NS = {
    "e": "http://schemas.microsoft.com/win/2004/08/events/event"
}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()

    with path.open("rb") as f:
        for chunk in iter(
            lambda: f.read(1024 * 1024),
            b"",
        ):
            h.update(chunk)

    return h.hexdigest()


def first_text(node, xpath: str) -> str:
    item = node.find(xpath, NS)

    if item is None:
        return ""

    return (
        item.text.strip()
        if item.text
        else ""
    )


with INVENTORY.open(
    "r",
    encoding="utf-8-sig",
    newline="",
) as f:
    inventory = list(csv.DictReader(f))


if len(inventory) != 29:
    raise RuntimeError(
        f"Expected 29 pending EVTX files, found {len(inventory)}"
    )


audit_rows = []


for index, item in enumerate(
    inventory,
    start=1,
):

    relative_path = item["relative_path"]

    path = RAW_ROOT / Path(relative_path)

    print(
        f"[{index:02d}/29] {relative_path}",
        flush=True,
    )

    expected_sha = (
        item["sha256"]
        .strip()
        .lower()
    )

    exists = path.exists()

    actual_sha = ""
    hash_match = False

    records_seen = 0
    xml_parse_success = 0
    xml_parse_errors = 0

    event_ids = Counter()
    channels = Counter()
    providers = Counter()

    timestamp_min = ""
    timestamp_max = ""

    file_error_type = ""
    file_error_message = ""

    if exists:

        actual_sha = sha256_file(path)
        hash_match = (
            actual_sha == expected_sha
        )

        try:

            with Evtx(str(path)) as log:

                for record in log.records():

                    records_seen += 1

                    try:

                        xml_text = record.xml()

                        root = ET.fromstring(
                            xml_text
                        )

                        xml_parse_success += 1

                        event_id = first_text(
                            root,
                            "./e:System/e:EventID",
                        )

                        channel = first_text(
                            root,
                            "./e:System/e:Channel",
                        )

                        provider_node = root.find(
                            "./e:System/e:Provider",
                            NS,
                        )

                        provider = ""

                        if provider_node is not None:
                            provider = (
                                provider_node
                                .attrib
                                .get(
                                    "Name",
                                    "",
                                )
                            )

                        time_node = root.find(
                            "./e:System/e:TimeCreated",
                            NS,
                        )

                        timestamp = ""

                        if time_node is not None:
                            timestamp = (
                                time_node
                                .attrib
                                .get(
                                    "SystemTime",
                                    "",
                                )
                            )

                        if event_id:
                            event_ids[event_id] += 1

                        if channel:
                            channels[channel] += 1

                        if provider:
                            providers[provider] += 1

                        if timestamp:

                            if (
                                not timestamp_min
                                or timestamp < timestamp_min
                            ):
                                timestamp_min = timestamp

                            if (
                                not timestamp_max
                                or timestamp > timestamp_max
                            ):
                                timestamp_max = timestamp

                    except Exception:
                        xml_parse_errors += 1

        except Exception as exc:

            file_error_type = (
                type(exc).__name__
            )

            file_error_message = str(exc)


    if not exists:

        status = "missing_file"

    elif not hash_match:

        status = "hash_mismatch"

    elif file_error_type:

        status = "parser_error"

    elif records_seen == 0:

        status = "empty_but_valid"

    elif xml_parse_errors > 0:

        status = "parsed_with_record_errors"

    else:

        status = "parsed_successfully"


    audit_rows.append(
        {
            "relative_path":
                relative_path,

            "file_name":
                item["file_name"],

            "tactic_from_path":
                item["tactic_from_path"],

            "size_bytes":
                item["size_bytes"],

            "expected_sha256":
                expected_sha,

            "actual_sha256":
                actual_sha,

            "exists":
                exists,

            "hash_match":
                hash_match,

            "records_seen":
                records_seen,

            "xml_parse_success":
                xml_parse_success,

            "xml_parse_errors":
                xml_parse_errors,

            "unique_event_ids":
                len(event_ids),

            "event_ids":
                " | ".join(
                    f"{key}:{value}"
                    for key, value
                    in event_ids.most_common()
                ),

            "unique_channels":
                len(channels),

            "channels":
                " | ".join(
                    f"{key}:{value}"
                    for key, value
                    in channels.most_common()
                ),

            "unique_providers":
                len(providers),

            "providers":
                " | ".join(
                    f"{key}:{value}"
                    for key, value
                    in providers.most_common()
                ),

            "timestamp_min":
                timestamp_min,

            "timestamp_max":
                timestamp_max,

            "status":
                status,

            "file_error_type":
                file_error_type,

            "file_error_message":
                file_error_message,
        }
    )


fieldnames = list(
    audit_rows[0].keys()
)


with AUDIT_OUTPUT.open(
    "w",
    encoding="utf-8",
    newline="",
) as f:

    writer = csv.DictWriter(
        f,
        fieldnames=fieldnames,
    )

    writer.writeheader()
    writer.writerows(audit_rows)


status_counts = Counter(
    row["status"]
    for row in audit_rows
)


total_records = sum(
    row["records_seen"]
    for row in audit_rows
)

total_xml_success = sum(
    row["xml_parse_success"]
    for row in audit_rows
)

total_xml_errors = sum(
    row["xml_parse_errors"]
    for row in audit_rows
)


summary = {
    "artifact":
        "EVTX Direct Parse Audit",

    "artifact_version":
        "1.0.0",

    "raw_repository_commit":
        "4ceed2f4706daf601c212a8f91c113dd85349a2c",

    "pending_files":
        len(inventory),

    "files_present":
        sum(
            1
            for row in audit_rows
            if row["exists"]
        ),

    "hash_verified_files":
        sum(
            1
            for row in audit_rows
            if row["hash_match"]
        ),

    "total_records_seen":
        total_records,

    "xml_parse_success":
        total_xml_success,

    "xml_parse_errors":
        total_xml_errors,

    "status_counts":
        dict(
            sorted(
                status_counts.items()
            )
        ),

    "status": (
        "PASS"
        if (
            len(inventory) == 29
            and
            all(
                row["exists"]
                for row in audit_rows
            )
            and
            all(
                row["hash_match"]
                for row in audit_rows
            )
            and
            not any(
                row["status"]
                in {
                    "missing_file",
                    "hash_mismatch",
                    "parser_error",
                }
                for row in audit_rows
            )
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


print()
print(
    json.dumps(
        summary,
        indent=2,
    )
)

print()
print(f"Audit:   {AUDIT_OUTPUT}")
print(f"Summary: {SUMMARY_OUTPUT}")
