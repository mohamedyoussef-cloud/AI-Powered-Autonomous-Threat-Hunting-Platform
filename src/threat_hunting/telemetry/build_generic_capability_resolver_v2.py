from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]


INVENTORY_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "telemetry"
    / "canonical"
    / "canonical_telemetry_inventory_v1.jsonl"
)

EVIDENCE_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "telemetry"
    / "canonical"
    / "canonical_telemetry_evidence_v2.jsonl"
)

REGISTRY_FILE = (
    PROJECT_ROOT
    / "config"
    / "telemetry"
    / "capability_registry_v2.json"
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
    / "telemetry"
)

JSONL_OUTPUT = (
    OUTPUT_DIR
    / "canonical_telemetry_capabilities_v2.jsonl"
)

CSV_OUTPUT = (
    OUTPUT_DIR
    / "canonical_telemetry_capabilities_v2.csv"
)

REPORT_OUTPUT = (
    REPORT_DIR
    / "canonical_telemetry_capabilities_v2_summary.json"
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


def read_json(path):
    return json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )


def normalize_source_type(value):
    value = str(
        value or ""
    ).strip()

    return value or None


def split_fields(value):
    if not value:
        return []

    if isinstance(value, list):
        return [
            str(item).strip()
            for item in value
            if str(item).strip()
        ]

    return [
        item.strip()
        for item in str(value).split("|")
        if item.strip()
    ]


def almost_equal(
    first,
    second,
    tolerance=0.000001,
):
    if first is None and second is None:
        return True

    if first is None or second is None:
        return False

    return abs(
        float(first)
        - float(second)
    ) <= tolerance


def main():

    required = [
        INVENTORY_FILE,
        EVIDENCE_FILE,
        REGISTRY_FILE,
    ]

    for path in required:

        if not path.exists():
            raise FileNotFoundError(
                f"Missing required input: {path}"
            )

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    inventory = read_jsonl(
        INVENTORY_FILE
    )

    evidence = read_jsonl(
        EVIDENCE_FILE
    )

    registry = read_json(
        REGISTRY_FILE
    )

    capabilities = registry.get(
        "capabilities",
        []
    )

    validation_errors = []

    # -----------------------------------------------------
    # Validate capability registry
    # -----------------------------------------------------

    capability_ids = [
        row.get(
            "capability_id"
        )
        for row in capabilities
    ]

    if not capabilities:
        validation_errors.append(
            "Capability registry is empty"
        )

    if len(capability_ids) != len(
        set(capability_ids)
    ):
        validation_errors.append(
            "Duplicate capability IDs "
            "in registry"
        )

    for capability in capabilities:

        capability_id = capability.get(
            "capability_id"
        )

        expected_fields = capability.get(
            "expected_fields"
        ) or []

        if not capability_id:
            validation_errors.append(
                "Capability missing capability_id"
            )

        if not expected_fields:
            validation_errors.append(
                f"{capability_id}: "
                f"no expected canonical fields"
            )

        if len(expected_fields) != len(
            set(expected_fields)
        ):
            validation_errors.append(
                f"{capability_id}: "
                f"duplicate expected fields"
            )

    # -----------------------------------------------------
    # Build observed telemetry source universe
    #
    # Important:
    # use source inventory to retain telemetry source
    # types even when they have zero mapped fields.
    # -----------------------------------------------------

    source_groups = {}

    for row in inventory:

        dataset_name = str(
            row.get(
                "dataset_name"
            )
            or ""
        ).strip()

        source_type = normalize_source_type(
            row.get(
                "source_type"
            )
        )

        if not dataset_name:
            continue

        if not source_type:
            continue

        key = (
            dataset_name,
            source_type,
        )

        state = source_groups.setdefault(
            key,
            {
                "dataset_name": dataset_name,
                "telemetry_source_type": source_type,
                "inventory_record_ids": [],
                "inventory_event_counts": [],
                "platform_hints": set(),
            },
        )

        record_id = row.get(
            "record_id"
        )

        if record_id:
            state[
                "inventory_record_ids"
            ].append(
                record_id
            )

        event_count = row.get(
            "event_count"
        )

        if event_count is not None:

            try:
                state[
                    "inventory_event_counts"
                ].append(
                    int(event_count)
                )

            except (
                TypeError,
                ValueError,
            ):
                pass

        platform_hint = row.get(
            "platform_hint"
        )

        if platform_hint:
            state[
                "platform_hints"
            ].add(
                str(
                    platform_hint
                ).strip()
            )

    if not source_groups:
        validation_errors.append(
            "No telemetry source groups "
            "found in canonical inventory"
        )

    # -----------------------------------------------------
    # Operational field evidence only
    #
    # Regression capability rows are explicitly NOT
    # used in capability derivation.
    # -----------------------------------------------------

    operational_fields = [
        row
        for row in evidence
        if (
            row.get(
                "evidence_role"
            )
            == "operational"
            and row.get(
                "evidence_kind"
            )
            == "field_observation"
        )
    ]

    regression_rows = [
        row
        for row in evidence
        if (
            row.get(
                "evidence_role"
            )
            == "regression_reference"
            and row.get(
                "evidence_kind"
            )
            == "capability_observation"
        )
    ]

    field_state = defaultdict(
        lambda: defaultdict(
            lambda: {
                "availability": 0.0,
                "evidence_ids": [],
                "confidence": [],
                "observed": False,
            }
        )
    )

    for row in operational_fields:

        dataset_name = str(
            row.get(
                "dataset_name"
            )
            or ""
        ).strip()

        source_type = normalize_source_type(
            row.get(
                "telemetry_source_type"
            )
        )

        canonical_field = str(
            row.get(
                "canonical_field"
            )
            or ""
        ).strip()

        if (
            not dataset_name
            or not source_type
            or not canonical_field
        ):
            continue

        source_key = (
            dataset_name,
            source_type,
        )

        # Evidence itself may introduce a valid
        # source group that was not present in
        # the source inventory.
        if source_key not in source_groups:

            source_groups[
                source_key
            ] = {
                "dataset_name": dataset_name,
                "telemetry_source_type": source_type,
                "inventory_record_ids": [],
                "inventory_event_counts": [],
                "platform_hints": set(),
            }

        item = field_state[
            source_key
        ][
            canonical_field
        ]

        availability = row.get(
            "availability_ratio"
        )

        if availability is None:

            availability = (
                1.0
                if row.get(
                    "observed"
                )
                is True
                else 0.0
            )

        availability = float(
            availability
        )

        # Same policy as the validated previous
        # implementation:
        # aliases are not summed because they may
        # overlap on the same events.
        item["availability"] = max(
            item["availability"],
            availability,
        )

        observed = (
            row.get(
                "observed"
            )
            is True
            or availability > 0
        )

        item["observed"] = (
            item["observed"]
            or observed
        )

        evidence_id = row.get(
            "evidence_id"
        )

        if evidence_id:
            item[
                "evidence_ids"
            ].append(
                evidence_id
            )

        confidence = row.get(
            "confidence"
        )

        if confidence is not None:

            item[
                "confidence"
            ].append(
                float(
                    confidence
                )
            )

        platform_hint = row.get(
            "platform_hint"
        )

        if platform_hint:

            source_groups[
                source_key
            ][
                "platform_hints"
            ].add(
                str(
                    platform_hint
                ).strip()
            )

    # -----------------------------------------------------
    # Derive capabilities
    # -----------------------------------------------------

    output_rows = []

    for source_key in sorted(
        source_groups,
        key=lambda value: (
            value[0].lower(),
            value[1].lower(),
        ),
    ):

        source = source_groups[
            source_key
        ]

        available_fields = field_state.get(
            source_key,
            {},
        )

        for capability in capabilities:

            capability_id = capability[
                "capability_id"
            ]

            capability_name = capability.get(
                "capability_name"
            ) or capability_id

            expected_fields = capability[
                "expected_fields"
            ]

            observed_fields = []

            availability_values = []

            evidence_ids = []

            supporting_confidences = []

            field_availability = {}

            for field in expected_fields:

                field_info = available_fields.get(
                    field
                )

                if field_info is None:
                    field_availability[
                        field
                    ] = 0.0

                    availability_values.append(
                        0.0
                    )

                    continue

                availability = float(
                    field_info[
                        "availability"
                    ]
                )

                field_availability[
                    field
                ] = round(
                    availability,
                    8,
                )

                availability_values.append(
                    availability
                )

                if field_info[
                    "observed"
                ]:

                    observed_fields.append(
                        field
                    )

                    evidence_ids.extend(
                        field_info[
                            "evidence_ids"
                        ]
                    )

                    supporting_confidences.extend(
                        field_info[
                            "confidence"
                        ]
                    )

            expected_count = len(
                expected_fields
            )

            observed_count = len(
                observed_fields
            )

            field_coverage = round(
                (
                    observed_count
                    / expected_count
                )
                if expected_count
                else 0.0,
                8,
            )

            weighted_coverage = round(
                (
                    sum(
                        availability_values
                    )
                    / expected_count
                )
                if expected_count
                else 0.0,
                8,
            )

            observed = (
                observed_count > 0
            )

            if observed:
                capability_status = (
                    "observed"
                )

                derivation_confidence = (
                    round(
                        min(
                            supporting_confidences
                        ),
                        4,
                    )
                    if supporting_confidences
                    else 1.0
                )

            else:
                capability_status = (
                    "not_observed_in_current_fields"
                )

                # Null rather than zero:
                # zero would imply certainty that the
                # capability itself is absent.
                derivation_confidence = None

            inventory_counts = source[
                "inventory_event_counts"
            ]

            inventory_event_count = (
                max(
                    inventory_counts
                )
                if inventory_counts
                else None
            )

            row = {
                "capability_version": "2.0",

                "environment_id": (
                    next(
                        (
                            item.get(
                                "environment_id"
                            )
                            for item
                            in inventory
                            if item.get(
                                "environment_id"
                            )
                        ),
                        None,
                    )
                ),

                "dataset_name": (
                    source[
                        "dataset_name"
                    ]
                ),

                "telemetry_source_type": (
                    source[
                        "telemetry_source_type"
                    ]
                ),

                "platform_hints": sorted(
                    source[
                        "platform_hints"
                    ]
                ),

                "capability_id": (
                    capability_id
                ),

                "capability_name": (
                    capability_name
                ),

                "capability_status": (
                    capability_status
                ),

                "observed": observed,

                "expected_field_count": (
                    expected_count
                ),

                "observed_field_count": (
                    observed_count
                ),

                "field_coverage_ratio": (
                    field_coverage
                ),

                "availability_weighted_coverage_ratio": (
                    weighted_coverage
                ),

                "expected_fields": (
                    expected_fields
                ),

                "observed_fields": (
                    observed_fields
                ),

                "field_availability": (
                    field_availability
                ),

                "supporting_field_evidence_ids": (
                    sorted(
                        set(
                            evidence_ids
                        )
                    )
                ),

                "supporting_field_evidence_count": (
                    len(
                        set(
                            evidence_ids
                        )
                    )
                ),

                "derivation_confidence": (
                    derivation_confidence
                ),

                "inventory_event_count": (
                    inventory_event_count
                ),

                "derivation_source": (
                    "operational_canonical_field_evidence"
                ),

                "uses_regression_reference_for_derivation": (
                    False
                ),

                "interpretation": (
                    "Capability observation is "
                    "derived from canonical field "
                    "availability in the current "
                    "environment. A not-observed "
                    "state does not prove global "
                    "capability absence."
                ),
            }

            output_rows.append(
                row
            )

    # -----------------------------------------------------
    # Structural validation
    # -----------------------------------------------------

    expected_output_count = (
        len(source_groups)
        * len(capabilities)
    )

    if len(output_rows) != (
        expected_output_count
    ):
        validation_errors.append(
            f"Expected "
            f"{expected_output_count} "
            f"derived capability rows, "
            f"found {len(output_rows)}"
        )

    output_map = {
        (
            row[
                "dataset_name"
            ],
            row[
                "telemetry_source_type"
            ],
            row[
                "capability_id"
            ],
        ): row
        for row in output_rows
    }

    if len(output_map) != len(
        output_rows
    ):
        validation_errors.append(
            "Duplicate derived capability keys"
        )

    invalid_derivation_sources = [
        row
        for row in output_rows
        if row[
            "uses_regression_reference_for_derivation"
        ]
        is not False
    ]

    if invalid_derivation_sources:
        validation_errors.append(
            "Regression references leaked "
            "into operational derivation"
        )

    # -----------------------------------------------------
    # Regression comparison
    #
    # The previous 1177 rows are only an oracle.
    # They do not influence the values above.
    # -----------------------------------------------------

    regression_total = len(
        regression_rows
    )

    regression_key_matches = 0
    regression_exact_matches = 0
    regression_mismatches = []

    for reference in regression_rows:

        key = (
            str(
                reference.get(
                    "dataset_name"
                )
                or ""
            ).strip(),

            normalize_source_type(
                reference.get(
                    "telemetry_source_type"
                )
            ),

            str(
                reference.get(
                    "capability_id"
                )
                or ""
            ).strip(),
        )

        derived = output_map.get(
            key
        )

        if derived is None:

            regression_mismatches.append({
                "key": key,
                "reason": (
                    "missing_derived_record"
                ),
            })

            continue

        regression_key_matches += 1

        reference_observed = (
            reference.get(
                "observed"
            )
            is True
        )

        expected_field_count = (
            reference.get(
                "expected_field_count"
            )
        )

        observed_field_count = (
            reference.get(
                "observed_field_count"
            )
        )

        reference_field_coverage = (
            reference.get(
                "field_coverage_ratio"
            )
        )

        reference_weighted = (
            reference.get(
                "availability_weighted_coverage_ratio"
            )
        )

        expected_fields = split_fields(
            reference.get(
                "expected_fields"
            )
        )

        observed_fields = split_fields(
            reference.get(
                "observed_fields"
            )
        )

        checks = {
            "observed": (
                derived[
                    "observed"
                ]
                == reference_observed
            ),

            "expected_field_count": (
                int(
                    derived[
                        "expected_field_count"
                    ]
                )
                == int(
                    expected_field_count
                    or 0
                )
            ),

            "observed_field_count": (
                int(
                    derived[
                        "observed_field_count"
                    ]
                )
                == int(
                    observed_field_count
                    or 0
                )
            ),

            "field_coverage_ratio": (
                almost_equal(
                    derived[
                        "field_coverage_ratio"
                    ],
                    reference_field_coverage,
                )
            ),

            "weighted_coverage_ratio": (
                almost_equal(
                    derived[
                        "availability_weighted_coverage_ratio"
                    ],
                    reference_weighted,
                )
            ),

            "expected_fields": (
                set(
                    derived[
                        "expected_fields"
                    ]
                )
                == set(
                    expected_fields
                )
            ),

            "observed_fields": (
                set(
                    derived[
                        "observed_fields"
                    ]
                )
                == set(
                    observed_fields
                )
            ),
        }

        failed_checks = [
            name
            for name, passed
            in checks.items()
            if not passed
        ]

        if failed_checks:

            regression_mismatches.append({
                "key": key,
                "failed_checks": (
                    failed_checks
                ),
            })

        else:
            regression_exact_matches += 1

    if regression_total:

        if regression_key_matches != (
            regression_total
        ):
            validation_errors.append(
                "Not all regression reference "
                "records have derived counterparts"
            )

        if regression_exact_matches != (
            regression_total
        ):
            validation_errors.append(
                f"Capability regression mismatch: "
                f"{regression_exact_matches}/"
                f"{regression_total} exact matches"
            )

    # -----------------------------------------------------
    # Summaries
    # -----------------------------------------------------

    dataset_source_counter = Counter(
        row[
            "dataset_name"
        ]
        for row
        in source_groups.values()
    )

    observed_capability_rows = [
        row
        for row in output_rows
        if row[
            "observed"
        ]
    ]

    observed_capability_counter = Counter(
        row[
            "capability_id"
        ]
        for row
        in observed_capability_rows
    )

    dataset_capability_counter = Counter(
        row[
            "dataset_name"
        ]
        for row
        in observed_capability_rows
    )

    environment_ids = sorted({
        row.get(
            "environment_id"
        )
        for row in inventory
        if row.get(
            "environment_id"
        )
    })

    if len(environment_ids) != 1:
        validation_errors.append(
            "Expected exactly one "
            "environment_id in inventory"
        )

    validation_status = (
        "PASS"
        if not validation_errors
        else "FAIL"
    )

    # -----------------------------------------------------
    # Write outputs
    # -----------------------------------------------------

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
        "capability_version",
        "environment_id",
        "dataset_name",
        "telemetry_source_type",
        "platform_hints",
        "capability_id",
        "capability_name",
        "capability_status",
        "observed",
        "expected_field_count",
        "observed_field_count",
        "field_coverage_ratio",
        "availability_weighted_coverage_ratio",
        "expected_fields",
        "observed_fields",
        "field_availability",
        "supporting_field_evidence_ids",
        "supporting_field_evidence_count",
        "derivation_confidence",
        "inventory_event_count",
        "derivation_source",
        "uses_regression_reference_for_derivation",
        "interpretation",
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

        for row in output_rows:

            csv_row = dict(
                row
            )

            for field in [
                "platform_hints",
                "expected_fields",
                "observed_fields",
                "supporting_field_evidence_ids",
            ]:

                csv_row[field] = (
                    " | ".join(
                        str(value)
                        for value
                        in row[field]
                    )
                )

            csv_row[
                "field_availability"
            ] = json.dumps(
                row[
                    "field_availability"
                ],
                ensure_ascii=False,
                sort_keys=True,
            )

            writer.writerow(
                csv_row
            )

    report = {
        "component": (
            "generic_capability_resolver"
        ),

        "version": "2.0",

        "generated_at_utc": (
            datetime.now(
                timezone.utc
            ).isoformat()
        ),

        "environment_id": (
            environment_ids[0]
            if len(
                environment_ids
            ) == 1
            else None
        ),

        "capability_registry_count": (
            len(capabilities)
        ),

        "telemetry_source_groups": (
            len(source_groups)
        ),

        "derived_capability_rows": (
            len(output_rows)
        ),

        "operational_field_evidence_rows": (
            len(
                operational_fields
            )
        ),

        "regression_reference_rows": (
            regression_total
        ),

        "regression_key_matches": (
            regression_key_matches
        ),

        "regression_exact_matches": (
            regression_exact_matches
        ),

        "regression_mismatch_count": (
            len(
                regression_mismatches
            )
        ),

        "regression_mismatch_preview": (
            regression_mismatches[
                :20
            ]
        ),

        "telemetry_source_groups_by_dataset": (
            dict(
                sorted(
                    dataset_source_counter.items()
                )
            )
        ),

        "observed_capability_rows": (
            len(
                observed_capability_rows
            )
        ),

        "observed_capability_rows_by_dataset": (
            dict(
                sorted(
                    dataset_capability_counter.items()
                )
            )
        ),

        "observed_source_capabilities": (
            dict(
                sorted(
                    observed_capability_counter.items()
                )
            )
        ),

        "operational_derivation_inputs": [
            "canonical_telemetry_inventory_v1",
            "operational field_observation records"
        ],

        "excluded_from_operational_derivation": [
            "regression_reference capability_observation records",
            "exact_event_observation records"
        ],

        "next_stage_exact_event_usage": (
            "Exact-event evidence is intentionally "
            "reserved for the ATT&CK Data Component "
            "Resolver rather than being collapsed "
            "into generic semantic capabilities."
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

    # -----------------------------------------------------
    # Console output
    # -----------------------------------------------------

    print(
        "Generic Capability Resolver v2.0"
    )

    print(
        "--------------------------------"
    )

    print(
        f"Capability registry      : "
        f"{len(capabilities)}"
    )

    print(
        f"Telemetry source groups  : "
        f"{len(source_groups)}"
    )

    print(
        f"Derived capability rows  : "
        f"{len(output_rows)}"
    )

    print()

    print(
        f"Operational field rows   : "
        f"{len(operational_fields)}"
    )

    print(
        f"Regression references    : "
        f"{regression_total}"
    )

    print()

    print(
        f"Observed capability rows : "
        f"{len(observed_capability_rows)}"
    )

    print()

    print(
        "Telemetry source groups by dataset:"
    )

    for key, value in sorted(
        dataset_source_counter.items()
    ):

        print(
            f"  {key:<20} {value}"
        )

    print()

    print(
        "Observed source capabilities:"
    )

    for key, value in sorted(
        observed_capability_counter.items()
    ):

        print(
            f"  {key:<24} {value}"
        )

    print()

    print(
        "Regression:"
    )

    print(
        f"  Reference rows         : "
        f"{regression_total}"
    )

    print(
        f"  Key matches            : "
        f"{regression_key_matches}"
    )

    print(
        f"  Exact matches          : "
        f"{regression_exact_matches}"
    )

    print(
        f"  Mismatches             : "
        f"{len(regression_mismatches)}"
    )

    print()

    print(
        "Regression used for derivation: NO"
    )

    print(
        "Exact events collapsed into capabilities: NO"
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