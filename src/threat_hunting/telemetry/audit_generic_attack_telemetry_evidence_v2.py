from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]

COMPONENT_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "telemetry"
    / "resolved"
    / "attack_data_component_evidence_v2.jsonl"
)

POLICY_FILE = (
    PROJECT_ROOT
    / "config"
    / "telemetry"
    / "source_identity_policy_v2.json"
)

OUTPUT_DIR = (
    PROJECT_ROOT
    / "reports"
    / "telemetry"
    / "match_audit_v2"
)

EXACT_CSV = (
    OUTPUT_DIR
    / "exact_event_matches_v2.csv"
)

SOURCE_CSV = (
    OUTPUT_DIR
    / "source_requirement_matches_v2.csv"
)

REVIEW_CSV = (
    OUTPUT_DIR
    / "semantic_review_items_v2.csv"
)

SUMMARY_FILE = (
    OUTPUT_DIR
    / "semantic_match_audit_v2_summary.json"
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
                rows.append(
                    json.loads(line)
                )
            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    f"Invalid JSONL at "
                    f"{path}:{line_number}: {exc}"
                ) from exc

    return rows


def read_json(path):
    return json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )


def write_csv(
    path,
    rows,
    fields,
):
    with path.open(
        "w",
        encoding="utf-8-sig",
        newline="",
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=fields,
        )

        writer.writeheader()

        for row in rows:
            writer.writerow({
                field: row.get(field)
                for field in fields
            })


def normalized_event_id(value):
    if value is None:
        return None

    try:
        return str(
            int(float(str(value)))
        )
    except ValueError:
        return str(value).strip()


def main():

    for path in [
        COMPONENT_FILE,
        POLICY_FILE,
    ]:
        if not path.exists():
            raise FileNotFoundError(
                f"Missing required input: {path}"
            )

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    components = read_jsonl(
        COMPONENT_FILE
    )

    policy = read_json(
        POLICY_FILE
    )

    source_threshold = float(
        policy[
            "source_activity_min_score"
        ]
    )

    exact_threshold = float(
        policy[
            "exact_event_source_min_score"
        ]
    )

    validation_errors = []

    if len(components) != 109:
        validation_errors.append(
            f"Expected 109 components, "
            f"found {len(components)}"
        )

    exact_rows = []
    source_rows = []
    review_rows = []

    exact_requirement_ids = set()
    source_requirement_ids = set()

    exact_method_counter = Counter()
    source_method_counter = Counter()

    for component in components:

        component_id = component[
            "component_id"
        ]

        component_name = component[
            "component_name"
        ]

        for result in component.get(
            "requirement_results",
            []
        ):

            requirement_id = result.get(
                "requirement_id"
            )

            requirement_type = result.get(
                "requirement_type"
            )

            status = result.get(
                "evidence_status"
            )

            required_source = result.get(
                "log_source_name"
            )

            required_channel = result.get(
                "channel"
            )

            required_event_ids = [
                normalized_event_id(value)
                for value in (
                    result.get(
                        "exact_event_ids"
                    )
                    or []
                )
            ]

            source_match = result.get(
                "source_match"
            )

            if source_match:

                source_requirement_ids.add(
                    requirement_id
                )

                source_score = float(
                    source_match.get(
                        "match_score"
                    )
                    or 0.0
                )

                source_method = (
                    source_match.get(
                        "match_method"
                    )
                )

                source_method_counter[
                    source_method
                ] += 1

                source_row = {
                    "component_id": (
                        component_id
                    ),

                    "component_name": (
                        component_name
                    ),

                    "requirement_id": (
                        requirement_id
                    ),

                    "requirement_type": (
                        requirement_type
                    ),

                    "evidence_status": (
                        status
                    ),

                    "required_source": (
                        required_source
                    ),

                    "required_channel": (
                        required_channel
                    ),

                    "matched_dataset": (
                        source_match.get(
                            "dataset_name"
                        )
                    ),

                    "matched_identity": (
                        source_match.get(
                            "identity"
                        )
                    ),

                    "matched_identity_kind": (
                        source_match.get(
                            "identity_kind"
                        )
                    ),

                    "match_score": (
                        source_score
                    ),

                    "match_method": (
                        source_method
                    ),

                    "matched_platforms": (
                        " | ".join(
                            source_match.get(
                                "platforms"
                            )
                            or []
                        )
                    ),
                }

                source_rows.append(
                    source_row
                )

                if (
                    source_score
                    < source_threshold
                ):

                    review_rows.append({
                        **source_row,
                        "review_type": (
                            "source_below_operational_threshold"
                        ),
                        "severity": "critical",
                    })

                elif (
                    source_method
                    == "token_overlap"
                    and source_score < 0.80
                ):

                    review_rows.append({
                        **source_row,
                        "review_type": (
                            "low_confidence_token_overlap"
                        ),
                        "severity": "review",
                    })

            exact_matches = result.get(
                "exact_event_matches"
            ) or []

            if exact_matches:

                exact_requirement_ids.add(
                    requirement_id
                )

            for match in exact_matches:

                event_id = normalized_event_id(
                    match.get(
                        "event_id"
                    )
                )

                source_score = float(
                    match.get(
                        "source_match_score"
                    )
                    or 0.0
                )

                source_method = (
                    match.get(
                        "source_match_method"
                    )
                )

                exact_method_counter[
                    source_method
                ] += 1

                exact_row = {
                    "component_id": (
                        component_id
                    ),

                    "component_name": (
                        component_name
                    ),

                    "requirement_id": (
                        requirement_id
                    ),

                    "required_source": (
                        required_source
                    ),

                    "required_channel": (
                        required_channel
                    ),

                    "required_event_ids": (
                        " | ".join(
                            required_event_ids
                        )
                    ),

                    "matched_event_id": (
                        event_id
                    ),

                    "matched_dataset": (
                        match.get(
                            "dataset_name"
                        )
                    ),

                    "matched_provider": (
                        match.get(
                            "provider"
                        )
                    ),

                    "matched_channel": (
                        match.get(
                            "channel"
                        )
                    ),

                    "canonical_category": (
                        match.get(
                            "canonical_category"
                        )
                    ),

                    "canonical_action": (
                        match.get(
                            "canonical_action"
                        )
                    ),

                    "source_match_score": (
                        source_score
                    ),

                    "source_match_method": (
                        source_method
                    ),

                    "matched_platforms": (
                        " | ".join(
                            match.get(
                                "platforms"
                            )
                            or []
                        )
                    ),
                }

                exact_rows.append(
                    exact_row
                )

                if (
                    event_id
                    not in required_event_ids
                ):

                    review_rows.append({
                        **exact_row,

                        "review_type": (
                            "exact_event_id_mismatch"
                        ),

                        "severity": (
                            "critical"
                        ),
                    })

                if (
                    source_score
                    < exact_threshold
                ):

                    review_rows.append({
                        **exact_row,

                        "review_type": (
                            "exact_source_below_threshold"
                        ),

                        "severity": (
                            "critical"
                        ),
                    })

                elif source_score < 0.65:

                    review_rows.append({
                        **exact_row,

                        "review_type": (
                            "weak_exact_event_source_match"
                        ),

                        "severity": (
                            "review"
                        ),
                    })

                if not (
                    match.get(
                        "platforms"
                    )
                    or []
                ):

                    review_rows.append({
                        **exact_row,

                        "review_type": (
                            "exact_event_platform_unscoped"
                        ),

                        "severity": (
                            "review"
                        ),
                    })

    critical_rows = [
        row
        for row in review_rows
        if row.get(
            "severity"
        ) == "critical"
    ]

    manual_review_rows = [
        row
        for row in review_rows
        if row.get(
            "severity"
        ) == "review"
    ]

    if critical_rows:
        validation_errors.append(
            f"{len(critical_rows)} critical "
            f"semantic matching violations"
        )

    exact_fields = [
        "component_id",
        "component_name",
        "requirement_id",
        "required_source",
        "required_channel",
        "required_event_ids",
        "matched_event_id",
        "matched_dataset",
        "matched_provider",
        "matched_channel",
        "canonical_category",
        "canonical_action",
        "source_match_score",
        "source_match_method",
        "matched_platforms",
    ]

    source_fields = [
        "component_id",
        "component_name",
        "requirement_id",
        "requirement_type",
        "evidence_status",
        "required_source",
        "required_channel",
        "matched_dataset",
        "matched_identity",
        "matched_identity_kind",
        "match_score",
        "match_method",
        "matched_platforms",
    ]

    review_fields = sorted({
        key
        for row in review_rows
        for key in row.keys()
    })

    write_csv(
        EXACT_CSV,
        exact_rows,
        exact_fields,
    )

    write_csv(
        SOURCE_CSV,
        source_rows,
        source_fields,
    )

    if review_fields:

        write_csv(
            REVIEW_CSV,
            review_rows,
            review_fields,
        )

    else:

        REVIEW_CSV.write_text(
            "No semantic review items.\n",
            encoding="utf-8",
        )

    status = (
        "PASS"
        if not validation_errors
        else "FAIL"
    )

    summary = {
        "component": (
            "semantic_match_audit"
        ),

        "version": "2.0",

        "data_components": (
            len(components)
        ),

        "exact_requirement_matches": (
            len(
                exact_requirement_ids
            )
        ),

        "exact_evidence_pairs": (
            len(exact_rows)
        ),

        "source_requirement_matches": (
            len(
                source_requirement_ids
            )
        ),

        "source_match_records": (
            len(source_rows)
        ),

        "exact_match_methods": dict(
            sorted(
                exact_method_counter.items()
            )
        ),

        "source_match_methods": dict(
            sorted(
                source_method_counter.items()
            )
        ),

        "critical_semantic_violations": (
            len(critical_rows)
        ),

        "manual_review_items": (
            len(manual_review_rows)
        ),

        "source_activity_threshold": (
            source_threshold
        ),

        "exact_event_source_threshold": (
            exact_threshold
        ),

        "validation_errors": (
            validation_errors
        ),

        "status": status,
    }

    SUMMARY_FILE.write_text(
        json.dumps(
            summary,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    print(
        "Semantic Match Audit v2.0"
    )

    print(
        "-------------------------"
    )

    print(
        f"Data components          : "
        f"{len(components)}"
    )

    print()

    print(
        f"Exact requirements       : "
        f"{len(exact_requirement_ids)}"
    )

    print(
        f"Exact evidence pairs     : "
        f"{len(exact_rows)}"
    )

    print()

    print(
        f"Source requirements      : "
        f"{len(source_requirement_ids)}"
    )

    print(
        f"Source match records     : "
        f"{len(source_rows)}"
    )

    print()

    print(
        "Exact source match methods:"
    )

    for key, value in sorted(
        exact_method_counter.items()
    ):

        print(
            f"  {str(key):<24} {value}"
        )

    print()

    print(
        "Source match methods:"
    )

    for key, value in sorted(
        source_method_counter.items()
    ):

        print(
            f"  {str(key):<24} {value}"
        )

    print()

    print(
        f"Critical violations      : "
        f"{len(critical_rows)}"
    )

    print(
        f"Manual review items      : "
        f"{len(manual_review_rows)}"
    )

    print()

    print(
        f"Validation               : "
        f"{status}"
    )

    if review_rows:

        print()
        print(
            "Review preview:"
        )

        for row in review_rows[:30]:

            component_id = row.get(
                "component_id"
            )

            review_type = row.get(
                "review_type"
            )

            required_source = row.get(
                "required_source"
            )

            matched = (
                row.get(
                    "matched_identity"
                )
                or row.get(
                    "matched_provider"
                )
                or ""
            )

            score = (
                row.get(
                    "match_score"
                )
                if row.get(
                    "match_score"
                )
                is not None
                else row.get(
                    "source_match_score"
                )
            )

            print(
                f"  {component_id:<8} "
                f"{review_type:<40} "
                f"score={score} "
                f"{required_source} -> "
                f"{matched}"
            )

    print()

    print(
        f"Exact CSV  : {EXACT_CSV}"
    )

    print(
        f"Source CSV : {SOURCE_CSV}"
    )

    print(
        f"Review CSV : {REVIEW_CSV}"
    )

    print(
        f"Summary    : {SUMMARY_FILE}"
    )


if __name__ == "__main__":
    main()