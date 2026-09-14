import csv
import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]

MANIFEST_FILE = (
    PROJECT_ROOT
    / "config"
    / "ingestion"
    / "reference_environment_v1.json"
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
    / "canonical_telemetry_inventory_v1.jsonl"
)

CSV_OUTPUT = (
    OUTPUT_DIR
    / "canonical_telemetry_inventory_v1.csv"
)

REPORT_OUTPUT = (
    REPORT_DIR
    / "canonical_telemetry_inventory_v1_summary.json"
)


CANONICAL_FIELDS = [
    "inventory_version",
    "record_id",
    "environment_id",
    "source_id",
    "dataset_name",
    "connector_type",
    "record_type",
    "source_type",
    "source_name",
    "host",
    "canonical_domain",
    "event_family",
    "platform_hint",
    "service_hint",
    "event_count",
    "first_seen_utc",
    "last_seen_utc",
    "mapping_confidence",
    "raw_reference",
    "metadata",
]


def load_manifest():
    if not MANIFEST_FILE.exists():
        raise FileNotFoundError(
            f"Missing manifest: {MANIFEST_FILE}"
        )

    return json.loads(
        MANIFEST_FILE.read_text(
            encoding="utf-8"
        )
    )


def resolve_path(value):
    path = Path(value)

    if path.is_absolute():
        return path

    return PROJECT_ROOT / path


def read_csv(path):
    with path.open(
        "r",
        encoding="utf-8-sig",
        newline=""
    ) as f:
        return list(csv.DictReader(f))


def read_jsonl(path):
    rows = []

    with path.open(
        "r",
        encoding="utf-8"
    ) as f:
        for line_number, line in enumerate(
            f,
            start=1
        ):
            line = line.strip()

            if not line:
                continue

            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    f"Invalid JSONL at "
                    f"{path}:{line_number}: {exc}"
                ) from exc

            if not isinstance(row, dict):
                raise RuntimeError(
                    f"JSONL record at "
                    f"{path}:{line_number} "
                    f"is not an object"
                )

            rows.append(row)

    return rows


def normalize_int(value):
    if value is None:
        return None

    value = str(value).strip()

    if not value:
        return None

    try:
        return int(float(value))
    except ValueError:
        return None


def make_record_id(
    environment_id,
    source_id,
    index
):
    raw = (
        f"{environment_id}|"
        f"{source_id}|"
        f"{index}"
    )

    return hashlib.sha256(
        raw.encode("utf-8")
    ).hexdigest()[:24]


def canonical_empty_record():
    return {
        "inventory_version": "1.0",
        "record_id": None,
        "environment_id": None,
        "source_id": None,
        "dataset_name": None,
        "connector_type": None,
        "record_type": None,
        "source_type": None,
        "source_name": None,
        "host": None,
        "canonical_domain": None,
        "event_family": None,
        "platform_hint": None,
        "service_hint": None,
        "event_count": None,
        "first_seen_utc": None,
        "last_seen_utc": None,
        "mapping_confidence": None,
        "raw_reference": None,
        "metadata": {},
    }


def map_record(
    source_config,
    raw_row,
    environment_id,
    index
):
    record = canonical_empty_record()

    record["record_id"] = make_record_id(
        environment_id,
        source_config["source_id"],
        index,
    )

    record["environment_id"] = (
        environment_id
    )

    record["source_id"] = (
        source_config["source_id"]
    )

    record["dataset_name"] = (
        source_config["dataset_name"]
    )

    record["connector_type"] = (
        source_config["connector_type"]
    )

    record["record_type"] = (
        source_config["record_type"]
    )

    defaults = source_config.get(
        "defaults",
        {}
    )

    for key, value in defaults.items():
        if key in record:
            record[key] = value

    field_map = source_config.get(
        "field_map",
        {}
    )

    mapped_raw_fields = set()

    for canonical_field, raw_field in (
        field_map.items()
    ):
        if canonical_field not in record:
            raise RuntimeError(
                f"Unknown canonical field "
                f"{canonical_field} in "
                f"{source_config['source_id']}"
            )

        record[canonical_field] = (
            raw_row.get(raw_field)
        )

        mapped_raw_fields.add(
            raw_field
        )

    record["event_count"] = normalize_int(
        record["event_count"]
    )

    metadata = {
        key: value
        for key, value in raw_row.items()
        if key not in mapped_raw_fields
    }

    existing_metadata = record.get(
        "metadata"
    )

    if isinstance(existing_metadata, dict):
        metadata = {
            **existing_metadata,
            **metadata,
        }

    record["metadata"] = metadata

    return record


def load_source_records(
    source_config,
    environment_id
):
    mode = source_config["mode"]

    if mode == "static":
        return [
            map_record(
                source_config,
                {},
                environment_id,
                1,
            )
        ]

    path_value = source_config.get(
        "path"
    )

    if not path_value:
        raise RuntimeError(
            f"{source_config['source_id']}: "
            f"path is required for mode={mode}"
        )

    path = resolve_path(
        path_value
    )

    if not path.exists():
        raise FileNotFoundError(
            f"{source_config['source_id']}: "
            f"missing input {path}"
        )

    if mode == "csv":
        raw_rows = read_csv(path)

    elif mode == "jsonl":
        raw_rows = read_jsonl(path)

    else:
        raise RuntimeError(
            f"Unsupported ingestion mode: {mode}"
        )

    records = []

    for index, raw_row in enumerate(
        raw_rows,
        start=1
    ):
        records.append(
            map_record(
                source_config,
                raw_row,
                environment_id,
                index,
            )
        )

    return records


def main():
    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    manifest = load_manifest()

    environment_id = manifest[
        "environment_id"
    ]

    environment_name = manifest.get(
        "environment_name"
    )

    inputs = manifest.get(
        "inputs",
        []
    )

    validation_errors = []

    if not inputs:
        validation_errors.append(
            "Manifest contains no inputs"
        )

    all_records = []

    source_counts = {}

    for source_config in inputs:
        records = load_source_records(
            source_config,
            environment_id,
        )

        source_counts[
            source_config["source_id"]
        ] = len(records)

        all_records.extend(records)

    record_ids = [
        row["record_id"]
        for row in all_records
    ]

    if len(record_ids) != len(
        set(record_ids)
    ):
        validation_errors.append(
            "Duplicate canonical record IDs"
        )

    invalid_environment = [
        row["record_id"]
        for row in all_records
        if row["environment_id"]
        != environment_id
    ]

    if invalid_environment:
        validation_errors.append(
            "Environment ID mismatch in "
            "canonical inventory"
        )

    expected_total = manifest.get(
        "expected_total_records"
    )

    if (
        expected_total is not None
        and len(all_records)
        != int(expected_total)
    ):
        validation_errors.append(
            f"Expected {expected_total} "
            f"canonical records, found "
            f"{len(all_records)}"
        )

    dataset_counter = Counter(
        row["dataset_name"]
        for row in all_records
    )

    connector_counter = Counter(
        row["connector_type"]
        for row in all_records
    )

    record_type_counter = Counter(
        row["record_type"]
        for row in all_records
    )

    with JSONL_OUTPUT.open(
        "w",
        encoding="utf-8",
        newline="\n"
    ) as f:
        for row in all_records:
            f.write(
                json.dumps(
                    row,
                    ensure_ascii=False
                )
                + "\n"
            )

    with CSV_OUTPUT.open(
        "w",
        encoding="utf-8-sig",
        newline=""
    ) as f:
        writer = csv.DictWriter(
            f,
            fieldnames=CANONICAL_FIELDS
        )

        writer.writeheader()

        for row in all_records:
            csv_row = dict(row)

            csv_row["metadata"] = (
                json.dumps(
                    row["metadata"],
                    ensure_ascii=False,
                    sort_keys=True
                )
            )

            writer.writerow(
                csv_row
            )

    validation_status = (
        "PASS"
        if not validation_errors
        else "FAIL"
    )

    report = {
        "component": (
            "canonical_telemetry_ingestion"
        ),

        "version": "1.0",

        "generated_at_utc": (
            datetime.now(
                timezone.utc
            ).isoformat()
        ),

        "environment_id": environment_id,
        "environment_name": environment_name,

        "input_source_count": len(inputs),

        "canonical_record_count": len(
            all_records
        ),

        "records_by_source": dict(
            sorted(source_counts.items())
        ),

        "records_by_dataset": dict(
            sorted(dataset_counter.items())
        ),

        "records_by_connector": dict(
            sorted(
                connector_counter.items()
            )
        ),

        "records_by_record_type": dict(
            sorted(
                record_type_counter.items()
            )
        ),

        "validation_errors": (
            validation_errors
        ),

        "status": validation_status,
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
        "Canonical Telemetry Ingestion v1.0"
    )

    print(
        "----------------------------------"
    )

    print(
        f"Environment              : "
        f"{environment_id}"
    )

    print(
        f"Input sources            : "
        f"{len(inputs)}"
    )

    print(
        f"Canonical records        : "
        f"{len(all_records)}"
    )

    print()

    print(
        "Records by dataset:"
    )

    for key, value in sorted(
        dataset_counter.items()
    ):
        print(
            f"  {key:<20} {value}"
        )

    print()

    print(
        "Records by record type:"
    )

    for key, value in sorted(
        record_type_counter.items()
    ):
        print(
            f"  {key:<24} {value}"
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