from __future__ import annotations

import csv
import gzip
import json
import sys
import xml.etree.ElementTree as ET

from collections import Counter, defaultdict
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path

import pandas as pd
import yaml

from Evtx.Evtx import Evtx
from jsonschema.validators import validator_for


PROJECT_ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = PROJECT_ROOT.parent

sys.path.insert(
    0,
    str(PROJECT_ROOT / "src"),
)

from threat_hunting_data.evtx_preparation import (
    _canonical_event,
    _file_tactic,
)


# =========================================================
# Paths
# =========================================================

RAW_ROOT = (
    WORKSPACE_ROOT
    / "datasets"
    / "raw"
    / "EVTX-ATTACK-SAMPLES"
)

TELEMETRY_DIR = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "telemetry"
)

INTERIM_DIR = (
    PROJECT_ROOT
    / "data"
    / "interim"
    / "evtx_direct_parsed"
)

REPORT_DIR = (
    PROJECT_ROOT
    / "reports"
    / "evtx_full_v0_4"
)

INTERIM_DIR.mkdir(
    parents=True,
    exist_ok=True,
)

REPORT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


PENDING_INVENTORY = (
    TELEMETRY_DIR
    / "evtx_unparsed_files.csv"
)

DIRECT_AUDIT_SUMMARY = (
    PROJECT_ROOT
    / "reports"
    / "evtx_direct_parse"
    / "evtx_direct_parse_29_summary.json"
)

EXISTING_CANONICAL = (
    TELEMETRY_DIR
    / "evtx_canonical_events.jsonl.gz"
)

FIELD_MAPPING_PATH = (
    PROJECT_ROOT
    / "mappings"
    / "evtx_samples_csv_field_mapping.yaml"
)

EVENT_MAPPING_PATH = (
    PROJECT_ROOT
    / "configs"
    / "evtx_event_mapping.yaml"
)

ATTACK_ACTIVE_PATH = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "knowledge"
    / "attack_techniques_active.jsonl"
)

SCHEMA_PATH = (
    PROJECT_ROOT
    / "schemas"
    / "canonical_event.schema.json"
)


PARSED_DIRECT_OUTPUT = (
    INTERIM_DIR
    / "evtx_direct_29_source_native.jsonl.gz"
)

DIRECT_CANONICAL_OUTPUT = (
    TELEMETRY_DIR
    / "evtx_canonical_events_direct_29_v0_4_candidate.jsonl.gz"
)

FULL_CANONICAL_OUTPUT = (
    TELEMETRY_DIR
    / "evtx_canonical_events_full_v0_4_candidate.jsonl.gz"
)

FULL_EVENT_PROFILE_OUTPUT = (
    TELEMETRY_DIR
    / "evtx_event_id_profile_full_v0_4_candidate.csv"
)

SCHEMA_FAILURE_OUTPUT = (
    REPORT_DIR
    / "evtx_direct_29_schema_failures.csv"
)

SUMMARY_OUTPUT = (
    REPORT_DIR
    / "evtx_full_v0_4_candidate_summary.json"
)


PIPELINE_VERSION = "0.4.0"
EXPECTED_REPOSITORY_COMMIT = (
    "4ceed2f4706daf601c212a8f91c113dd85349a2c"
)


# =========================================================
# Helpers
# =========================================================

def local_name(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[1]

    return tag


def namespace_uri(tag: str) -> str:
    if tag.startswith("{") and "}" in tag:
        return tag[1:].split("}", 1)[0]

    return ""


def add_value(
    target: dict,
    key: str,
    value,
) -> None:

    if value is None:
        return

    if isinstance(value, str):
        value = value.strip()

        if not value:
            return

    if key not in target:
        target[key] = value
        return

    existing = target[key]

    # Preserve repeated XML fields without
    # destroying the first source-native value.
    repeat_key = f"{key}{{}}"

    if repeat_key not in target:

        if isinstance(existing, list):
            target[repeat_key] = list(existing)
        else:
            target[repeat_key] = [existing]

    target[repeat_key].append(value)


def first_child(
    node: ET.Element,
    name: str,
):
    for child in node:
        if local_name(child.tag) == name:
            return child

    return None


def evtx_xml_to_source_row(
    xml_text: str,
    relative_path: str,
) -> dict:

    root = ET.fromstring(xml_text)

    row: dict = {}

    # -----------------------------------------------------
    # System block
    # -----------------------------------------------------

    system = first_child(
        root,
        "System",
    )

    if system is not None:

        for child in system:

            name = local_name(
                child.tag
            )

            if name == "Provider":

                add_value(
                    row,
                    "ProviderName",
                    child.attrib.get("Name"),
                )

                add_value(
                    row,
                    "Guid",
                    child.attrib.get("Guid"),
                )

                add_value(
                    row,
                    "EventSourceName",
                    child.attrib.get(
                        "EventSourceName"
                    ),
                )

            elif name == "TimeCreated":

                add_value(
                    row,
                    "SystemTime",
                    child.attrib.get(
                        "SystemTime"
                    ),
                )

            elif name == "Execution":

                # Keep capitalization compatible with
                # the published EVTX source table.
                add_value(
                    row,
                    "ProcessID",
                    child.attrib.get(
                        "ProcessID"
                    ),
                )

                add_value(
                    row,
                    "ThreadID",
                    child.attrib.get(
                        "ThreadID"
                    ),
                )

                add_value(
                    row,
                    "ProcessorID",
                    child.attrib.get(
                        "ProcessorID"
                    ),
                )

                add_value(
                    row,
                    "SessionID",
                    child.attrib.get(
                        "SessionID"
                    ),
                )

            elif name == "Correlation":

                add_value(
                    row,
                    "ActivityID",
                    child.attrib.get(
                        "ActivityID"
                    ),
                )

                add_value(
                    row,
                    "RelatedActivityID",
                    child.attrib.get(
                        "RelatedActivityID"
                    ),
                )

            elif name == "Security":

                add_value(
                    row,
                    "UserID",
                    child.attrib.get(
                        "UserID"
                    ),
                )

            else:

                add_value(
                    row,
                    name,
                    child.text,
                )


    # -----------------------------------------------------
    # EventData
    # -----------------------------------------------------

    event_data = first_child(
        root,
        "EventData",
    )

    if event_data is not None:

        unnamed_index = 0

        for child in event_data:

            child_name = local_name(
                child.tag
            )

            if child_name == "Data":

                field_name = (
                    child.attrib.get("Name")
                )

                if not field_name:
                    unnamed_index += 1
                    field_name = (
                        f"Data_{unnamed_index}"
                    )

                add_value(
                    row,
                    field_name,
                    child.text,
                )

            else:

                add_value(
                    row,
                    child_name,
                    child.text,
                )


    # -----------------------------------------------------
    # UserData / provider-specific nested payloads
    # -----------------------------------------------------

    user_data = first_child(
        root,
        "UserData",
    )

    if user_data is not None:

        for node in user_data.iter():

            if node is user_data:
                continue

            if len(list(node)) != 0:
                continue

            key = local_name(
                node.tag
            )

            add_value(
                row,
                key,
                node.text,
            )

            # Existing canonicalizer explicitly looks
            # for these aliases for Event 1149.
            if key in {
                "Param1",
                "Param2",
                "Param3",
            }:

                add_value(
                    row,
                    f"{{Event_NS}}{key}",
                    node.text,
                )


    # -----------------------------------------------------
    # Other provider payloads
    # -----------------------------------------------------

    for section in root:

        section_name = local_name(
            section.tag
        )

        if section_name in {
            "System",
            "EventData",
            "UserData",
        }:
            continue

        for node in section.iter():

            if node is section:
                continue

            if len(list(node)) != 0:
                continue

            add_value(
                row,
                local_name(node.tag),
                node.text,
            )


    path = Path(
        relative_path.replace("\\", "/")
    )

    row["EVTX_FileName"] = path.name

    tactic = _file_tactic(
        relative_path
    )

    row["EVTX_Tactic"] = (
        tactic
        if tactic
        else None
    )

    # Raw XML preservation for auditability.
    row["RawXML"] = xml_text

    row["EVTX_SourcePath"] = (
        relative_path
    )

    return row


def load_jsonl_gz(
    path: Path,
):

    with gzip.open(
        path,
        "rt",
        encoding="utf-8",
    ) as f:

        for line in f:

            if line.strip():
                yield json.loads(line)


def load_active_techniques() -> set[str]:

    result = set()

    with ATTACK_ACTIVE_PATH.open(
        "r",
        encoding="utf-8",
    ) as f:

        for line in f:

            if not line.strip():
                continue

            record = json.loads(line)

            tid = record.get(
                "technique_id"
            )

            if tid:
                result.add(
                    str(tid)
                )

    return result


# =========================================================
# Input validation
# =========================================================

with PENDING_INVENTORY.open(
    "r",
    encoding="utf-8-sig",
    newline="",
) as f:

    pending = list(
        csv.DictReader(f)
    )


if len(pending) != 29:
    raise RuntimeError(
        f"Expected 29 pending files, found {len(pending)}"
    )


with DIRECT_AUDIT_SUMMARY.open(
    "r",
    encoding="utf-8",
) as f:

    direct_audit = json.load(f)


expected_direct_records = int(
    direct_audit[
        "total_records_seen"
    ]
)


if expected_direct_records != 32731:
    raise RuntimeError(
        "Direct parsing audit changed unexpectedly: "
        f"{expected_direct_records}"
    )


field_mapping = yaml.safe_load(
    FIELD_MAPPING_PATH.read_text(
        encoding="utf-8"
    )
)

event_mapping = yaml.safe_load(
    EVENT_MAPPING_PATH.read_text(
        encoding="utf-8"
    )
)

valid_techniques = (
    load_active_techniques()
)


schema = json.loads(
    SCHEMA_PATH.read_text(
        encoding="utf-8"
    )
)

Validator = validator_for(
    schema
)

Validator.check_schema(
    schema
)

validator = Validator(
    schema
)


# =========================================================
# Existing canonical corpus
# =========================================================

existing_events = []

existing_uids = set()

existing_source_files = set()


for event in load_jsonl_gz(
    EXISTING_CANONICAL
):

    existing_events.append(
        event
    )

    existing_uids.add(
        event["event_uid"]
    )

    existing_source_files.add(
        event[
            "lineage"
        ][
            "source_file"
        ]
    )


existing_count = len(
    existing_events
)


if existing_count != 4633:
    raise RuntimeError(
        "Expected 4633 existing canonical events, "
        f"found {existing_count}"
    )


# =========================================================
# Direct parse → same canonicalizer
# =========================================================

ingested_at = (
    datetime.now(
        timezone.utc
    )
    .isoformat()
    .replace(
        "+00:00",
        "Z",
    )
)


direct_events = []

direct_uids = set()

direct_source_files = set()

schema_failures = []

duplicate_direct_uids = []

cross_corpus_duplicate_uids = []

missing_required_counts = Counter()

warning_counts = Counter()

category_counts = Counter()

action_counts = Counter()

event_profile = defaultdict(
    lambda: {
        "event_count": 0,
        "source_files": set(),
    }
)


direct_index = 0


with gzip.open(
    PARSED_DIRECT_OUTPUT,
    "wt",
    encoding="utf-8",
) as parsed_output:

    with gzip.open(
        DIRECT_CANONICAL_OUTPUT,
        "wt",
        encoding="utf-8",
    ) as canonical_output:

        for file_index, item in enumerate(
            pending,
            start=1,
        ):

            relative_path = (
                item["relative_path"]
                .replace("\\", "/")
            )

            source_path = (
                RAW_ROOT
                / Path(relative_path)
            )

            if not source_path.exists():
                raise FileNotFoundError(
                    source_path
                )

            print(
                f"[{file_index:02d}/29] "
                f"{relative_path}",
                flush=True,
            )

            direct_source_files.add(
                relative_path
            )

            with Evtx(
                str(source_path)
            ) as log:

                for record_index, record in enumerate(
                    log.records()
                ):

                    xml_text = (
                        record.xml()
                    )

                    row_dict = (
                        evtx_xml_to_source_row(
                            xml_text,
                            relative_path,
                        )
                    )

                    row_dict[
                        "_direct_record_index"
                    ] = record_index

                    row_dict[
                        "_direct_parser"
                    ] = "python-evtx"

                    row_dict[
                        "_direct_parser_version"
                    ] = version(
                        "python-evtx"
                    )

                    parsed_output.write(
                        json.dumps(
                            row_dict,
                            ensure_ascii=False,
                            separators=(",", ":"),
                        )
                        + "\n"
                    )

                    row = pd.Series(
                        row_dict
                    )

                    event = _canonical_event(
                        row=row,
                        row_index=direct_index,
                        source_path=relative_path,
                        event_mapping=event_mapping,
                        field_mapping=field_mapping,
                        valid_techniques=valid_techniques,
                        ingested_at=ingested_at,
                    )

                    # This event was created by the
                    # direct-EVTX extension pipeline.
                    event[
                        "lineage"
                    ][
                        "pipeline_version"
                    ] = PIPELINE_VERSION

                    event[
                        "raw"
                    ][
                        "_parser"
                    ] = "python-evtx"

                    event[
                        "raw"
                    ][
                        "_parser_version"
                    ] = version(
                        "python-evtx"
                    )

                    uid = event[
                        "event_uid"
                    ]

                    if uid in direct_uids:
                        duplicate_direct_uids.append(
                            uid
                        )

                    direct_uids.add(
                        uid
                    )

                    if uid in existing_uids:
                        cross_corpus_duplicate_uids.append(
                            uid
                        )

                    errors = sorted(
                        validator.iter_errors(
                            event
                        ),
                        key=lambda e: list(
                            e.absolute_path
                        ),
                    )

                    if errors:

                        schema_failures.append(
                            {
                                "source_file":
                                    relative_path,

                                "direct_record_index":
                                    direct_index,

                                "event_uid":
                                    uid,

                                "error_count":
                                    len(errors),

                                "errors":
                                    " | ".join(
                                        (
                                            f'{"/".join(map(str, error.absolute_path))}: '
                                            f'{error.message}'
                                        )
                                        for error in errors[:20]
                                    ),
                            }
                        )

                    for missing in event[
                        "data_quality"
                    ][
                        "missing_required_fields"
                    ]:

                        missing_required_counts[
                            missing
                        ] += 1

                    for warning in event[
                        "data_quality"
                    ][
                        "mapping_warnings"
                    ]:

                        warning_counts[
                            warning
                        ] += 1

                    category = event[
                        "event"
                    ][
                        "category"
                    ]

                    action = event[
                        "event"
                    ][
                        "action"
                    ]

                    category_counts[
                        category
                    ] += 1

                    action_counts[
                        action
                    ] += 1

                    provider = event[
                        "event"
                    ][
                        "provider"
                    ]

                    provider_normalized = (
                        event[
                            "event"
                        ][
                            "provider_normalized"
                        ]
                    )

                    channel = event[
                        "event"
                    ][
                        "channel"
                    ]

                    event_id = event[
                        "event"
                    ][
                        "id"
                    ]

                    profile_key = (
                        provider or "",
                        provider_normalized or "",
                        channel or "",
                        str(event_id),
                        category,
                        action,
                    )

                    event_profile[
                        profile_key
                    ][
                        "event_count"
                    ] += 1

                    event_profile[
                        profile_key
                    ][
                        "source_files"
                    ].add(
                        relative_path
                    )

                    canonical_output.write(
                        json.dumps(
                            event,
                            ensure_ascii=False,
                            separators=(",", ":"),
                        )
                        + "\n"
                    )

                    direct_events.append(
                        event
                    )

                    direct_index += 1


# =========================================================
# Schema failure report
# =========================================================

failure_fields = [
    "source_file",
    "direct_record_index",
    "event_uid",
    "error_count",
    "errors",
]


with SCHEMA_FAILURE_OUTPUT.open(
    "w",
    encoding="utf-8",
    newline="",
) as f:

    writer = csv.DictWriter(
        f,
        fieldnames=failure_fields,
    )

    writer.writeheader()
    writer.writerows(
        schema_failures
    )


# =========================================================
# Quality gates BEFORE merge
# =========================================================

direct_count = len(
    direct_events
)


all_29_represented = (
    len(direct_source_files)
    == 29
)


candidate_merge_allowed = (
    direct_count
    == expected_direct_records
    and
    all_29_represented
    and
    len(schema_failures) == 0
    and
    len(duplicate_direct_uids) == 0
    and
    len(cross_corpus_duplicate_uids) == 0
)


# =========================================================
# Produce full candidate only if safe
# =========================================================

full_count = 0

combined_uids = set()


if candidate_merge_allowed:

    with gzip.open(
        FULL_CANONICAL_OUTPUT,
        "wt",
        encoding="utf-8",
    ) as output:

        for event in existing_events:

            uid = event[
                "event_uid"
            ]

            if uid in combined_uids:
                raise RuntimeError(
                    "Duplicate UID in existing corpus: "
                    f"{uid}"
                )

            combined_uids.add(
                uid
            )

            output.write(
                json.dumps(
                    event,
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                + "\n"
            )

            full_count += 1


        for event in direct_events:

            uid = event[
                "event_uid"
            ]

            if uid in combined_uids:
                raise RuntimeError(
                    "Cross-corpus duplicate UID: "
                    f"{uid}"
                )

            combined_uids.add(
                uid
            )

            output.write(
                json.dumps(
                    event,
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                + "\n"
            )

            full_count += 1


# =========================================================
# Full candidate Event-ID profile
# =========================================================

full_profile = defaultdict(
    lambda: {
        "event_count": 0,
        "source_files": set(),
        "category": "",
        "action": "",
    }
)


if candidate_merge_allowed:

    for event in (
        existing_events
        + direct_events
    ):

        provider = (
            event["event"]
            .get("provider")
            or ""
        )

        provider_normalized = (
            event["event"]
            .get(
                "provider_normalized"
            )
            or ""
        )

        channel = (
            event["event"]
            .get("channel")
            or ""
        )

        event_id = str(
            event["event"]
            .get("id")
            or ""
        )

        category = (
            event["event"]
            .get("category")
            or ""
        )

        action = (
            event["event"]
            .get("action")
            or ""
        )

        key = (
            provider,
            provider_normalized,
            channel,
            event_id,
        )

        full_profile[
            key
        ][
            "event_count"
        ] += 1

        full_profile[
            key
        ][
            "source_files"
        ].add(
            event[
                "lineage"
            ][
                "source_file"
            ]
        )

        full_profile[
            key
        ][
            "category"
        ] = category

        full_profile[
            key
        ][
            "action"
        ] = action


    profile_rows = []

    for (
        provider,
        provider_normalized,
        channel,
        event_id,
    ), data in full_profile.items():

        profile_rows.append(
            {
                "provider":
                    provider,

                "provider_normalized":
                    provider_normalized,

                "channel":
                    channel,

                "event_id":
                    event_id,

                "event_count":
                    data[
                        "event_count"
                    ],

                "unique_files":
                    len(
                        data[
                            "source_files"
                        ]
                    ),

                "canonical_category":
                    data[
                        "category"
                    ],

                "canonical_action":
                    data[
                        "action"
                    ],
            }
        )


    profile_rows.sort(
        key=lambda r: (
            -r["event_count"],
            r["provider"],
            r["event_id"],
        )
    )


    with FULL_EVENT_PROFILE_OUTPUT.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=[
                "provider",
                "provider_normalized",
                "channel",
                "event_id",
                "event_count",
                "unique_files",
                "canonical_category",
                "canonical_action",
            ],
        )

        writer.writeheader()

        writer.writerows(
            profile_rows
        )


# =========================================================
# Final candidate summary
# =========================================================

expected_full_count = (
    existing_count
    + expected_direct_records
)


summary = {
    "artifact":
        "EVTX Full Preparation Candidate",

    "artifact_version":
        "0.4.0",

    "source_repository_commit":
        EXPECTED_REPOSITORY_COMMIT,

    "raw_evtx_files":
        278,

    "existing_published_csv_files":
        249,

    "direct_parsed_files":
        len(
            direct_source_files
        ),

    "total_source_files_represented":
        (
            249
            +
            len(
                direct_source_files
            )
        ),

    "existing_canonical_events":
        existing_count,

    "expected_direct_records_from_audit":
        expected_direct_records,

    "direct_canonical_events":
        direct_count,

    "expected_full_event_count":
        expected_full_count,

    "full_candidate_event_count":
        full_count,

    "direct_schema_failures":
        len(
            schema_failures
        ),

    "duplicate_direct_event_uids":
        len(
            duplicate_direct_uids
        ),

    "cross_corpus_duplicate_event_uids":
        len(
            cross_corpus_duplicate_uids
        ),

    "combined_unique_event_uids":
        len(
            combined_uids
        ),

    "direct_missing_required_field_counts":
        dict(
            sorted(
                missing_required_counts.items()
            )
        ),

    "direct_mapping_warning_counts":
        dict(
            warning_counts.most_common()
        ),

    "direct_category_counts":
        dict(
            sorted(
                category_counts.items()
            )
        ),

    "direct_action_counts_top_30":
        dict(
            action_counts.most_common(
                30
            )
        ),

    "python_evtx_version":
        version(
            "python-evtx"
        ),

    "candidate_merge_allowed":
        candidate_merge_allowed,

    "important_note": (
        "The original 4633 canonical events remain unchanged. "
        "The additional 32731 records were directly parsed from "
        "the 29 source EVTX files and passed through the existing "
        "_canonical_event mapping logic. The full v0.4 file is a "
        "candidate artifact until final validation is completed."
    ),

    "status": (
        "PASS"
        if (
            candidate_merge_allowed
            and
            len(direct_source_files) == 29
            and
            expected_full_count == 37364
            and
            full_count == 37364
            and
            len(combined_uids) == 37364
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
print(
    f"Parsed direct:   {PARSED_DIRECT_OUTPUT}"
)
print(
    f"Direct canonical:{DIRECT_CANONICAL_OUTPUT}"
)
print(
    f"Full candidate:  {FULL_CANONICAL_OUTPUT}"
)
print(
    f"Event profile:   {FULL_EVENT_PROFILE_OUTPUT}"
)
print(
    f"Schema failures: {SCHEMA_FAILURE_OUTPUT}"
)
print(
    f"Summary:         {SUMMARY_OUTPUT}"
)
