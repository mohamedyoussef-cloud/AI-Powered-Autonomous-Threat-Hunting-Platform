from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]
WORKSPACE_ROOT = PROJECT_ROOT.parent

MANIFEST_FILE = (
    PROJECT_ROOT
    / "config"
    / "ingestion"
    / "reference_telemetry_evidence_v2.json"
)

OUTPUT_DIR = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "telemetry"
    / "canonical"
)

REPORT_DIR = (
    PROJECT_ROOT
    / "reports"
    / "ingestion"
)

JSONL_OUTPUT = (
    OUTPUT_DIR
    / "canonical_telemetry_evidence_v2.jsonl"
)

CSV_OUTPUT = (
    OUTPUT_DIR
    / "canonical_telemetry_evidence_v2.csv"
)

REPORT_OUTPUT = (
    REPORT_DIR
    / "canonical_telemetry_evidence_v2_summary.json"
)


ALLOWED_EVIDENCE_KINDS = {
    "field_observation",
    "capability_observation",
    "exact_event_observation",
}


CANONICAL_FIELDS = [
    "evidence_version",
    "evidence_id",
    "environment_id",

    "adapter_id",
    "dataset_name",
    "connector_type",

    "evidence_kind",
    "evidence_role",

    "telemetry_source_type",
    "telemetry_source_name",
    "platform_hint",

    "capability_id",
    "capability_name",

    "canonical_field",
    "source_field",

    "provider",
    "channel",
    "event_id",

    "canonical_category",
    "canonical_action",

    "observed",
    "confidence",
    "confidence_label",

    "event_count",
    "unique_event_count",
    "unique_file_count",

    "observed_count",
    "total_count",
    "unique_value_count",

    "availability_ratio",

    "expected_field_count",
    "observed_field_count",

    "field_coverage_ratio",
    "availability_weighted_coverage_ratio",

    "expected_fields",
    "observed_fields",

    "source_reference",
    "metadata",
]


INTEGER_FIELDS = {
    "event_count",
    "unique_event_count",
    "unique_file_count",
    "observed_count",
    "total_count",
    "unique_value_count",
    "expected_field_count",
    "observed_field_count",
}


RATIO_FIELDS = {
    "availability_ratio",
    "field_coverage_ratio",
    "availability_weighted_coverage_ratio",
}


CONFIDENCE_LABELS = {
    "very_high": 1.0,
    "high": 0.95,
    "medium": 0.75,
    "low": 0.50,
}


def read_json(path: Path):
    return json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )


def read_csv(path: Path):
    with path.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as f:
        return list(
            csv.DictReader(f)
        )


def read_jsonl(path: Path):
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
                    f"JSONL row at "
                    f"{path}:{line_number} "
                    f"is not an object"
                )

            rows.append(value)

    return rows


def resolve_input_path(config):
    root_name = config.get(
        "root",
        "project",
    )

    if root_name == "project":
        root = PROJECT_ROOT

    elif root_name == "workspace":
        root = WORKSPACE_ROOT

    else:
        raise RuntimeError(
            f"Unsupported manifest root: "
            f"{root_name}"
        )

    path = Path(
        config["path"]
    )

    if path.is_absolute():
        return path

    return root / path


def normalize_int(value):
    if value is None:
        return None

    text = str(value).strip()

    if not text:
        return None

    try:
        return int(float(text))
    except ValueError:
        return None


def normalize_float(value):
    if value is None:
        return None

    text = str(value).strip()

    if not text:
        return None

    text = text.replace(
        "%",
        "",
    )

    try:
        return float(text)
    except ValueError:
        return None


def normalize_bool(value):
    if isinstance(value, bool):
        return value

    if value is None:
        return None

    text = str(
        value
    ).strip().lower()

    if text in {
        "true",
        "yes",
        "1",
        "observed",
        "present",
    }:
        return True

    if text in {
        "false",
        "no",
        "0",
        "not_observed",
        "absent",
    }:
        return False

    return None


def normalize_confidence_label(value):
    if value is None:
        return None

    text = (
        str(value)
        .strip()
        .lower()
        .replace("-", "_")
        .replace(" ", "_")
    )

    return text or None


def empty_record():
    return {
        field: None
        for field in CANONICAL_FIELDS
    }


def row_matches_filter(
    raw_row,
    filter_config,
):
    for field, expected in (
        filter_config or {}
    ).items():

        actual = raw_row.get(
            field
        )

        if (
            str(actual or "")
            .strip()
            .lower()
            !=
            str(expected or "")
            .strip()
            .lower()
        ):
            return False

    return True


def build_evidence_id(
    config,
    raw_row,
    row_index,
):
    identity_fields = config.get(
        "identity_fields",
        [],
    )

    identity = []

    for field in identity_fields:
        identity.append(
            str(
                raw_row.get(field)
                or ""
            ).strip()
        )

    if not identity:
        identity = [
            str(row_index)
        ]

    signature = {
        "adapter_id": config[
            "adapter_id"
        ],
        "evidence_kind": config[
            "evidence_kind"
        ],
        "identity": identity,
    }

    raw = json.dumps(
        signature,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )

    return hashlib.sha256(
        raw.encode("utf-8")
    ).hexdigest()[:32]


def load_raw_rows(
    config,
    path,
):
    mode = config.get(
        "mode",
        "csv",
    )

    if mode == "csv":
        return read_csv(path)

    if mode == "jsonl":
        return read_jsonl(path)

    raise RuntimeError(
        f"Unsupported input mode: {mode}"
    )


def map_row(
    config,
    raw_row,
    row_index,
    environment_id,
):
    record = empty_record()

    record["evidence_version"] = (
        "2.0"
    )

    record["evidence_id"] = (
        build_evidence_id(
            config,
            raw_row,
            row_index,
        )
    )

    record["environment_id"] = (
        environment_id
    )

    record["adapter_id"] = (
        config["adapter_id"]
    )

    record["dataset_name"] = (
        config["dataset_name"]
    )

    record["connector_type"] = (
        config["connector_type"]
    )

    record["evidence_kind"] = (
        config["evidence_kind"]
    )

    record["evidence_role"] = (
        config.get(
            "evidence_role",
            "operational",
        )
    )

    defaults = config.get(
        "defaults",
        {}
    )

    for field, value in (
        defaults.items()
    ):
        if field not in record:
            raise RuntimeError(
                f"{config['adapter_id']}: "
                f"unknown default field "
                f"{field}"
            )

        record[field] = value

    field_map = config.get(
        "field_map",
        {}
    )

    mapped_source_fields = set()

    for canonical_field, source_field in (
        field_map.items()
    ):
        if canonical_field not in record:
            raise RuntimeError(
                f"{config['adapter_id']}: "
                f"unknown canonical field "
                f"{canonical_field}"
            )

        record[
            canonical_field
        ] = raw_row.get(
            source_field
        )

        mapped_source_fields.add(
            source_field
        )

    scales = config.get(
        "scales",
        {}
    )

    for field in INTEGER_FIELDS:
        record[field] = normalize_int(
            record.get(field)
        )

    for field in RATIO_FIELDS:
        value = normalize_float(
            record.get(field)
        )

        if value is not None:
            scale = float(
                scales.get(
                    field,
                    1.0,
                )
            )

            value *= scale

        record[field] = (
            round(value, 8)
            if value is not None
            else None
        )

    record["observed"] = (
        normalize_bool(
            record.get(
                "observed"
            )
        )
    )

    record["confidence_label"] = (
        normalize_confidence_label(
            record.get(
                "confidence_label"
            )
        )
    )

    confidence = normalize_float(
        record.get(
            "confidence"
        )
    )

    if (
        confidence is None
        and record[
            "confidence_label"
        ]
    ):
        confidence = (
            CONFIDENCE_LABELS.get(
                record[
                    "confidence_label"
                ]
            )
        )

    if confidence is None:
        confidence = 1.0

    record["confidence"] = round(
        confidence,
        4,
    )

    # If the adapter does not explicitly
    # provide observed=true/false, derive
    # observation conservatively.
    if record["observed"] is None:

        if (
            record[
                "evidence_kind"
            ]
            == "exact_event_observation"
        ):
            record["observed"] = (
                record["event_count"] is not None
                and record["event_count"] > 0
            )

        elif (
            record[
                "evidence_kind"
            ]
            == "field_observation"
        ):
            if (
                record["observed_count"]
                is not None
            ):
                record["observed"] = (
                    record["observed_count"] > 0
                )

            elif (
                record["availability_ratio"]
                is not None
            ):
                record["observed"] = (
                    record[
                        "availability_ratio"
                    ] > 0
                )

            else:
                record["observed"] = False

    record["source_reference"] = (
        config["path"]
    )

    metadata = {}

    for key, value in raw_row.items():
        if key in mapped_source_fields:
            continue

        metadata[key] = value

    record["metadata"] = metadata

    return record


def main():
    if not MANIFEST_FILE.exists():
        raise FileNotFoundError(
            f"Missing manifest: "
            f"{MANIFEST_FILE}"
        )

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    manifest = read_json(
        MANIFEST_FILE
    )

    environment_id = manifest[
        "environment_id"
    ]

    inputs = manifest.get(
        "inputs",
        [],
    )

    validation_errors = []

    if not inputs:
        validation_errors.append(
            "Manifest contains no evidence inputs"
        )

    output_rows = []

    adapter_counts = {}

    for config in inputs:

        evidence_kind = config.get(
            "evidence_kind"
        )

        if (
            evidence_kind
            not in ALLOWED_EVIDENCE_KINDS
        ):
            validation_errors.append(
                f"{config.get('adapter_id')}: "
                f"unsupported evidence kind "
                f"{evidence_kind}"
            )

            continue

        path = resolve_input_path(
            config
        )

        if not path.exists():
            raise FileNotFoundError(
                f"{config['adapter_id']}: "
                f"missing input {path}"
            )

        raw_rows = load_raw_rows(
            config,
            path,
        )

        filtered_rows = [
            row
            for row in raw_rows
            if row_matches_filter(
                row,
                config.get("filter"),
            )
        ]

        adapter_counts[
            config["adapter_id"]
        ] = len(filtered_rows)

        expected_rows = config.get(
            "expected_rows"
        )

        if (
            expected_rows is not None
            and len(filtered_rows)
            != int(expected_rows)
        ):
            validation_errors.append(
                f"{config['adapter_id']}: "
                f"expected {expected_rows} rows, "
                f"found {len(filtered_rows)}"
            )

        min_rows = config.get(
            "min_rows"
        )

        if (
            min_rows is not None
            and len(filtered_rows)
            < int(min_rows)
        ):
            validation_errors.append(
                f"{config['adapter_id']}: "
                f"expected at least "
                f"{min_rows} rows, found "
                f"{len(filtered_rows)}"
            )

        for row_index, raw_row in enumerate(
            filtered_rows,
            start=1,
        ):
            output_rows.append(
                map_row(
                    config,
                    raw_row,
                    row_index,
                    environment_id,
                )
            )

    ids = [
        row["evidence_id"]
        for row in output_rows
    ]

    if len(ids) != len(set(ids)):
        validation_errors.append(
            "Duplicate evidence IDs detected"
        )

    for row in output_rows:

        kind = row[
            "evidence_kind"
        ]

        if kind == "field_observation":
            if not row[
                "canonical_field"
            ]:
                validation_errors.append(
                    f"{row['evidence_id']}: "
                    f"field evidence missing "
                    f"canonical_field"
                )

        elif kind == (
            "capability_observation"
        ):
            if not row[
                "capability_id"
            ]:
                validation_errors.append(
                    f"{row['evidence_id']}: "
                    f"capability evidence missing "
                    f"capability_id"
                )

        elif kind == (
            "exact_event_observation"
        ):
            if not row[
                "event_id"
            ]:
                validation_errors.append(
                    f"{row['evidence_id']}: "
                    f"exact event evidence "
                    f"missing event_id"
                )

        confidence = row[
            "confidence"
        ]

        if not (
            0.0 <= confidence <= 1.0
        ):
            validation_errors.append(
                f"{row['evidence_id']}: "
                f"confidence outside 0..1"
            )

        for ratio_field in (
            RATIO_FIELDS
        ):
            ratio = row.get(
                ratio_field
            )

            if ratio is None:
                continue

            if not (
                0.0 <= ratio <= 1.0
            ):
                validation_errors.append(
                    f"{row['evidence_id']}: "
                    f"{ratio_field} outside "
                    f"0..1"
                )

    operational_rows = [
        row
        for row in output_rows
        if row[
            "evidence_role"
        ] == "operational"
    ]

    regression_rows = [
        row
        for row in output_rows
        if row[
            "evidence_role"
        ] == "regression_reference"
    ]

    operational_field_rows = [
        row
        for row in operational_rows
        if row[
            "evidence_kind"
        ] == "field_observation"
    ]

    operational_event_rows = [
        row
        for row in operational_rows
        if row[
            "evidence_kind"
        ] == "exact_event_observation"
    ]

    if not operational_field_rows:
        validation_errors.append(
            "No operational field evidence"
        )

    if not operational_event_rows:
        validation_errors.append(
            "No operational exact-event evidence"
        )

    kind_counter = Counter(
        row["evidence_kind"]
        for row in output_rows
    )

    role_counter = Counter(
        row["evidence_role"]
        for row in output_rows
    )

    dataset_counter = Counter(
        row["dataset_name"]
        for row in output_rows
    )

    observed_counter = Counter(
        (
            row["evidence_kind"],
            row["observed"],
        )
        for row in output_rows
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

    with CSV_OUTPUT.open(
        "w",
        encoding="utf-8-sig",
        newline="",
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=CANONICAL_FIELDS,
        )

        writer.writeheader()

        for row in output_rows:
            csv_row = dict(row)

            csv_row["metadata"] = (
                json.dumps(
                    row["metadata"],
                    ensure_ascii=False,
                    sort_keys=True,
                )
            )

            writer.writerow(
                csv_row
            )

    report = {
        "component": (
            "canonical_telemetry_evidence"
        ),

        "version": "2.0",

        "generated_at_utc": (
            datetime.now(
                timezone.utc
            ).isoformat()
        ),

        "environment_id": (
            environment_id
        ),

        "input_adapter_count": len(
            inputs
        ),

        "canonical_evidence_records": (
            len(output_rows)
        ),

        "operational_evidence_records": (
            len(operational_rows)
        ),

        "regression_reference_records": (
            len(regression_rows)
        ),

        "records_by_adapter": dict(
            sorted(
                adapter_counts.items()
            )
        ),

        "records_by_evidence_kind": dict(
            sorted(
                kind_counter.items()
            )
        ),

        "records_by_role": dict(
            sorted(
                role_counter.items()
            )
        ),

        "records_by_dataset": dict(
            sorted(
                dataset_counter.items()
            )
        ),

        "observed_status_counts": {
            (
                f"{kind}:"
                f"{observed}"
            ): count
            for (
                kind,
                observed
            ), count
            in sorted(
                observed_counter.items(),
                key=lambda x: (
                    x[0][0],
                    str(x[0][1]),
                )
            )
        },

        "semantics": {
            "field_observation": (
                "Observed availability of a "
                "canonical telemetry field."
            ),

            "capability_observation": (
                "Normalized telemetry capability "
                "evidence. Reference capability "
                "matrices may be retained for "
                "regression but are not required "
                "by the product core."
            ),

            "exact_event_observation": (
                "Observed provider/channel/event "
                "identity or equivalent exact "
                "event primitive."
            ),

            "operational": (
                "Evidence eligible for use by "
                "downstream generic resolvers."
            ),

            "regression_reference": (
                "Evidence retained only to compare "
                "new generic derivation against a "
                "previous validated implementation."
            ),
        },

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
        "Canonical Telemetry Evidence v2.0"
    )

    print(
        "---------------------------------"
    )

    print(
        f"Environment              : "
        f"{environment_id}"
    )

    print(
        f"Input adapters           : "
        f"{len(inputs)}"
    )

    print(
        f"Canonical evidence       : "
        f"{len(output_rows)}"
    )

    print(
        f"Operational evidence     : "
        f"{len(operational_rows)}"
    )

    print(
        f"Regression references    : "
        f"{len(regression_rows)}"
    )

    print()

    print(
        "Evidence kinds:"
    )

    for key, value in sorted(
        kind_counter.items()
    ):
        print(
            f"  {key:<30} {value}"
        )

    print()

    print(
        "Records by adapter:"
    )

    for key, value in sorted(
        adapter_counts.items()
    ):
        print(
            f"  {key:<38} {value}"
        )

    print()

    print(
        f"Operational fields       : "
        f"{len(operational_field_rows)}"
    )

    print(
        f"Operational exact events : "
        f"{len(operational_event_rows)}"
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