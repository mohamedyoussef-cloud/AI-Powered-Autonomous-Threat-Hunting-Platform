from __future__ import annotations

import csv
import hashlib
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]


DATA_COMPONENTS_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "knowledge"
    / "attack_data_components.jsonl"
)

OUTPUT_DIR = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "knowledge"
)

REPORT_DIR = (
    PROJECT_ROOT
    / "reports"
    / "telemetry"
)

JSONL_OUTPUT = (
    OUTPUT_DIR
    / "attack_data_component_requirements_v2.jsonl"
)

CSV_OUTPUT = (
    OUTPUT_DIR
    / "attack_data_component_log_source_requirements_v2.csv"
)

REPORT_OUTPUT = (
    REPORT_DIR
    / "attack_data_component_requirements_v2_summary.json"
)


EVENT_MARKER_PATTERN = re.compile(
    r"(?i)\b("
    r"event\s*code|"
    r"event\s*id|"
    r"eventid|"
    r"eid"
    r")\s*[=:]?\s*"
    r"([0-9]{1,5}(?:\s*[,/]\s*[0-9]{1,5})*)"
)


def read_jsonl(path):
    rows = []

    with path.open(
        "r",
        encoding="utf-8",
    ) as f:

        for line_number, line in enumerate(
            f,
            start=1,
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
                    f"Expected JSON object at "
                    f"{path}:{line_number}"
                )

            rows.append(value)

    return rows


def slug(value):
    value = str(
        value or ""
    ).strip().lower()

    value = re.sub(
        r"[^a-z0-9]+",
        "_",
        value,
    )

    return value.strip("_")


def normalize_source_name(value):
    value = str(
        value or ""
    ).strip().lower()

    value = re.sub(
        r"\s+",
        "",
        value,
    )

    return value


def source_family(value):
    value = str(
        value or ""
    ).strip()

    if not value:
        return None

    if ":" in value:
        return value.split(
            ":",
            1,
        )[0].strip().lower()

    return value.lower()


def extract_explicit_event_ids(text):
    if not text:
        return []

    event_ids = set()

    for match in EVENT_MARKER_PATTERN.finditer(
        str(text)
    ):
        value_block = match.group(2)

        for value in re.findall(
            r"\b[0-9]{1,5}\b",
            value_block,
        ):
            event_ids.add(
                str(int(value))
            )

    return sorted(
        event_ids,
        key=lambda value: int(value),
    )


def make_requirement_id(
    component_id,
    index,
    source_name,
    channel,
):
    raw = (
        f"{component_id}|"
        f"{index}|"
        f"{source_name}|"
        f"{channel}"
    )

    digest = hashlib.sha256(
        raw.encode("utf-8")
    ).hexdigest()[:12]

    return (
        f"{component_id}:"
        f"REQ{index:03d}:"
        f"{digest}"
    )


def main():

    if not DATA_COMPONENTS_FILE.exists():
        raise FileNotFoundError(
            f"Missing input: "
            f"{DATA_COMPONENTS_FILE}"
        )

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    components = read_jsonl(
        DATA_COMPONENTS_FILE
    )

    validation_errors = []

    if len(components) != 109:
        validation_errors.append(
            f"Expected 109 ATT&CK data "
            f"components, found "
            f"{len(components)}"
        )

    ids = [
        row.get(
            "external_id"
        )
        for row in components
    ]

    if len(ids) != len(
        set(ids)
    ):
        validation_errors.append(
            "Duplicate ATT&CK data "
            "component IDs detected"
        )

    if any(
        not value
        for value in ids
    ):
        validation_errors.append(
            "One or more data components "
            "lack external_id"
        )

    output_rows = []

    flattened_requirements = []

    for component in sorted(
        components,
        key=lambda row: (
            row.get(
                "external_id"
            )
            or ""
        ),
    ):

        component_id = component[
            "external_id"
        ]

        component_name = component.get(
            "name"
        )

        description = component.get(
            "description"
        ) or ""

        raw = component.get(
            "raw"
        ) or {}

        log_sources = raw.get(
            "x_mitre_log_sources"
        ) or []

        operational_requirements = []

        for index, log_source in enumerate(
            log_sources,
            start=1,
        ):

            if not isinstance(
                log_source,
                dict,
            ):
                continue

            name = str(
                log_source.get(
                    "name"
                )
                or ""
            ).strip()

            channel = str(
                log_source.get(
                    "channel"
                )
                or ""
            ).strip()

            event_ids = (
                extract_explicit_event_ids(
                    channel
                )
            )

            if event_ids:
                requirement_type = (
                    "exact_event"
                )

            else:
                requirement_type = (
                    "source_activity"
                )

            requirement = {
                "requirement_id": (
                    make_requirement_id(
                        component_id,
                        index,
                        name,
                        channel,
                    )
                ),

                "requirement_index": index,

                "requirement_type": (
                    requirement_type
                ),

                "log_source_name": (
                    name
                ),

                "log_source_normalized": (
                    normalize_source_name(
                        name
                    )
                ),

                "source_family": (
                    source_family(
                        name
                    )
                ),

                "channel": (
                    channel
                ),

                "exact_event_ids": (
                    event_ids
                ),

                "exact_event_required": (
                    bool(
                        event_ids
                    )
                ),

                "requirement_role": (
                    "operational_attack_requirement"
                ),

                "requirement_source": (
                    "attack_x_mitre_log_sources"
                ),
            }

            operational_requirements.append(
                requirement
            )

            flat = {
                "component_id": (
                    component_id
                ),

                "component_name": (
                    component_name
                ),

                "component_action_key": (
                    slug(
                        component_name
                    )
                ),

                **requirement,
            }

            flat[
                "exact_event_ids"
            ] = " | ".join(
                event_ids
            )

            flattened_requirements.append(
                flat
            )

        description_event_ids = (
            extract_explicit_event_ids(
                description
            )
        )

        exact_requirement_count = sum(
            1
            for requirement
            in operational_requirements
            if requirement[
                "requirement_type"
            ] == "exact_event"
        )

        source_requirement_count = sum(
            1
            for requirement
            in operational_requirements
            if requirement[
                "requirement_type"
            ] == "source_activity"
        )

        if operational_requirements:

            operational_status = (
                "requirements_specified"
            )

        else:

            operational_status = (
                "requirement_unspecified"
            )

        row = {
            "catalog_version": "2.0",

            "component_id": (
                component_id
            ),

            "stix_id": (
                component.get(
                    "stix_id"
                )
            ),

            "component_name": (
                component_name
            ),

            "component_action_key": (
                slug(
                    component_name
                )
            ),

            "description": (
                description
            ),

            "deprecated": bool(
                component.get(
                    "deprecated",
                    False,
                )
            ),

            "revoked": bool(
                component.get(
                    "revoked",
                    False,
                )
            ),

            "component_platforms": (
                component.get(
                    "platforms"
                )
                or []
            ),

            "platform_resolution_source": (
                "technique_platforms_not_data_component"
            ),

            "operational_requirement_status": (
                operational_status
            ),

            "operational_requirement_count": (
                len(
                    operational_requirements
                )
            ),

            "exact_event_requirement_count": (
                exact_requirement_count
            ),

            "source_activity_requirement_count": (
                source_requirement_count
            ),

            "operational_requirements": (
                operational_requirements
            ),

            # Event IDs mentioned in prose may be
            # useful later, but they are NOT promoted
            # to operational requirements here.
            "description_event_id_candidates": (
                description_event_ids
            ),

            "description_event_ids_operational": (
                False
            ),

            "requirement_semantics": {
                "exact_event": (
                    "ATT&CK log-source requirement "
                    "contains an explicit event ID "
                    "or event code."
                ),

                "source_activity": (
                    "ATT&CK specifies a log source "
                    "or activity requirement without "
                    "a machine-verifiable exact "
                    "event ID."
                ),

                "requirement_unspecified": (
                    "No x_mitre_log_sources "
                    "requirements are available for "
                    "this data component in the "
                    "prepared ATT&CK artifact."
                ),

                "description_event_id_candidate": (
                    "Event identifier found in "
                    "descriptive prose only. It is "
                    "retained for review and is not "
                    "used as operational evidence "
                    "without validation."
                ),
            },
        }

        output_rows.append(
            row
        )

    # Add one flattened placeholder for components
    # with no operational requirements so the CSV
    # still represents the complete 109 catalog.
    components_with_flat_rows = {
        row[
            "component_id"
        ]
        for row in flattened_requirements
    }

    for component in output_rows:

        component_id = component[
            "component_id"
        ]

        if (
            component_id
            in components_with_flat_rows
        ):
            continue

        flattened_requirements.append({
            "component_id": (
                component_id
            ),

            "component_name": (
                component[
                    "component_name"
                ]
            ),

            "component_action_key": (
                component[
                    "component_action_key"
                ]
            ),

            "requirement_id": None,
            "requirement_index": None,

            "requirement_type": (
                "requirement_unspecified"
            ),

            "log_source_name": None,
            "log_source_normalized": None,
            "source_family": None,
            "channel": None,
            "exact_event_ids": None,
            "exact_event_required": False,

            "requirement_role": (
                "operational_attack_requirement"
            ),

            "requirement_source": (
                "attack_x_mitre_log_sources"
            ),
        })

    if len(output_rows) != 109:
        validation_errors.append(
            f"Expected 109 component catalog "
            f"records, found "
            f"{len(output_rows)}"
        )

    invalid_platform_claims = [
        row[
            "component_id"
        ]
        for row in output_rows
        if row[
            "platform_resolution_source"
        ]
        != "technique_platforms_not_data_component"
    ]

    if invalid_platform_claims:
        validation_errors.append(
            "Unexpected data-component "
            "platform resolution behavior"
        )

    exact_components = [
        row
        for row in output_rows
        if row[
            "exact_event_requirement_count"
        ] > 0
    ]

    source_only_components = [
        row
        for row in output_rows
        if (
            row[
                "operational_requirement_count"
            ] > 0
            and row[
                "exact_event_requirement_count"
            ] == 0
        )
    ]

    unspecified_components = [
        row
        for row in output_rows
        if row[
            "operational_requirement_status"
        ]
        == "requirement_unspecified"
    ]

    mixed_components = [
        row
        for row in output_rows
        if (
            row[
                "exact_event_requirement_count"
            ] > 0
            and row[
                "source_activity_requirement_count"
            ] > 0
        )
    ]

    description_candidate_components = [
        row
        for row in output_rows
        if row[
            "description_event_id_candidates"
        ]
    ]

    requirement_type_counter = Counter(
        row[
            "requirement_type"
        ]
        for row in flattened_requirements
    )

    source_family_counter = Counter(
        row[
            "source_family"
        ]
        for row in flattened_requirements
        if row.get(
            "source_family"
        )
    )

    validation_status = (
        "PASS"
        if not validation_errors
        else "FAIL"
    )

    with JSONL_OUTPUT.open(
        "w",
        encoding="utf-8",
        newline="\n",
    ) as f:

        for row in output_rows:

            f.write(
                json.dumps(
                    row,
                    ensure_ascii=False,
                )
                + "\n"
            )

    csv_fields = [
        "component_id",
        "component_name",
        "component_action_key",

        "requirement_id",
        "requirement_index",
        "requirement_type",

        "log_source_name",
        "log_source_normalized",
        "source_family",

        "channel",

        "exact_event_ids",
        "exact_event_required",

        "requirement_role",
        "requirement_source",
    ]

    with CSV_OUTPUT.open(
        "w",
        encoding="utf-8-sig",
        newline="",
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=csv_fields,
        )

        writer.writeheader()

        for row in (
            flattened_requirements
        ):

            writer.writerow({
                field: row.get(
                    field
                )
                for field in csv_fields
            })

    report = {
        "component": (
            "attack_data_component_requirement_catalog"
        ),

        "version": "2.0",

        "generated_at_utc": (
            datetime.now(
                timezone.utc
            ).isoformat()
        ),

        "attack_data_components": (
            len(
                output_rows
            )
        ),

        "flattened_requirement_rows": (
            len(
                flattened_requirements
            )
        ),

        "components_with_exact_event_requirements": (
            len(
                exact_components
            )
        ),

        "components_with_source_only_requirements": (
            len(
                source_only_components
            )
        ),

        "components_with_mixed_requirements": (
            len(
                mixed_components
            )
        ),

        "components_requirement_unspecified": (
            len(
                unspecified_components
            )
        ),

        "components_with_description_event_id_candidates": (
            len(
                description_candidate_components
            )
        ),

        "requirement_type_counts": dict(
            sorted(
                requirement_type_counter.items()
            )
        ),

        "source_family_counts": dict(
            sorted(
                source_family_counter.items()
            )
        ),

        "description_event_ids_used_operationally": (
            False
        ),

        "platform_resolution_source": (
            "ATT&CK technique platform metadata"
        ),

        "validation_errors": (
            validation_errors
        ),

        "status": (
            validation_status
        ),
    }

    REPORT_OUTPUT.write_text(
        json.dumps(
            report,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    print(
        "ATT&CK Data Component "
        "Requirement Catalog v2.0"
    )

    print(
        "-------------------------------------"
    )

    print(
        f"Data components         : "
        f"{len(output_rows)}"
    )

    print(
        f"Requirement rows        : "
        f"{len(flattened_requirements)}"
    )

    print()

    print(
        f"Exact-event components  : "
        f"{len(exact_components)}"
    )

    print(
        f"Source-only components  : "
        f"{len(source_only_components)}"
    )

    print(
        f"Mixed components        : "
        f"{len(mixed_components)}"
    )

    print(
        f"Requirement unspecified : "
        f"{len(unspecified_components)}"
    )

    print()

    print(
        "Requirement rows by type:"
    )

    for key, value in sorted(
        requirement_type_counter.items()
    ):

        print(
            f"  {key:<26} {value}"
        )

    print()

    print(
        f"Description event IDs "
        f"used operationally : NO"
    )

    print(
        "Platform source          : "
        "TECHNIQUE metadata"
    )

    print()

    print(
        f"Validation               : "
        f"{validation_status}"
    )

    if validation_errors:

        print()

        for error in validation_errors:

            print(
                " - " + error
            )

    print()

    print(
        f"JSONL  : {JSONL_OUTPUT}"
    )

    print(
        f"CSV    : {CSV_OUTPUT}"
    )

    print(
        f"Report : {REPORT_OUTPUT}"
    )


if __name__ == "__main__":
    main()