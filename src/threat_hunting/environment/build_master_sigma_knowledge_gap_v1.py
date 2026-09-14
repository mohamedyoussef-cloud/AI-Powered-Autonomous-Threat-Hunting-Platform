import csv
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]

OLD_SIGMA_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "environment"
    / "master_sigma_knowledge_gap_v0_1.jsonl"
)

APPLICABILITY_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "environment"
    / "master_technique_applicability_v1.jsonl"
)

OUTPUT_DIR = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "environment"
)

REPORT_DIR = (
    PROJECT_ROOT
    / "reports"
    / "environment"
)

JSONL_OUTPUT = (
    OUTPUT_DIR
    / "master_sigma_knowledge_gap_v1.jsonl"
)

CSV_OUTPUT = (
    OUTPUT_DIR
    / "master_sigma_knowledge_gap_v1.csv"
)

REPORT_OUTPUT = (
    REPORT_DIR
    / "master_sigma_knowledge_gap_v1_summary.json"
)


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
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    f"Invalid JSONL at "
                    f"{path}:{line_number}: {exc}"
                ) from exc

    return rows


def sigma_environment_posture(
    applicability_status
):
    if applicability_status == (
        "observed_environment_applicable"
    ):
        return (
            "current_environment_relevant"
        )

    if applicability_status == (
        "known_present_collection_gap"
    ):
        return (
            "current_environment_collection_gap"
        )

    if applicability_status == (
        "environment_presence_unknown"
    ):
        return (
            "retained_environment_unknown"
        )

    if applicability_status == (
        "pre_attack_scope"
    ):
        return (
            "retained_pre_attack_scope"
        )

    if applicability_status == (
        "confirmed_not_present"
    ):
        return (
            "retained_global_not_current_environment"
        )

    return "retained_unresolved"


def main():
    for path in [
        OLD_SIGMA_FILE,
        APPLICABILITY_FILE,
    ]:
        if not path.exists():
            raise FileNotFoundError(
                f"Missing required input: {path}"
            )

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    sigma_rows = read_jsonl(
        OLD_SIGMA_FILE
    )

    applicability_rows = read_jsonl(
        APPLICABILITY_FILE
    )

    validation_errors = []

    if len(sigma_rows) != 697:
        validation_errors.append(
            f"Expected 697 Sigma master rows, "
            f"found {len(sigma_rows)}"
        )

    if len(applicability_rows) != 697:
        validation_errors.append(
            f"Expected 697 applicability rows, "
            f"found {len(applicability_rows)}"
        )

    sigma_map = {
        row["technique_id"]: row
        for row in sigma_rows
    }

    applicability_map = {
        row["technique_id"]: row
        for row in applicability_rows
    }

    sigma_ids = set(sigma_map)
    applicability_ids = set(
        applicability_map
    )

    missing_sigma = sorted(
        applicability_ids - sigma_ids
    )

    extra_sigma = sorted(
        sigma_ids - applicability_ids
    )

    if missing_sigma:
        validation_errors.append(
            "Missing Sigma rows for: "
            + ", ".join(missing_sigma)
        )

    if extra_sigma:
        validation_errors.append(
            "Unexpected Sigma rows for: "
            + ", ".join(extra_sigma)
        )

    output_rows = []

    for technique_id in sorted(
        applicability_ids
    ):
        app = applicability_map[
            technique_id
        ]

        sigma = sigma_map.get(
            technique_id
        )

        if sigma is None:
            continue

        gap_source = sigma.get(
            "gap_source"
        )

        if gap_source != (
            "prepared_sigma_corpus_proxy"
        ):
            validation_errors.append(
                f"{technique_id}: unexpected "
                f"gap_source={gap_source}"
            )

        is_client_coverage = sigma.get(
            "is_client_detection_coverage"
        )

        if is_client_coverage not in [
            False,
            "False",
            "false",
            0,
        ]:
            validation_errors.append(
                f"{technique_id}: Sigma proxy "
                f"incorrectly marked as client "
                f"detection coverage"
            )

        applicability_status = app[
            "applicability_status"
        ]

        row = {
            "technique_id": technique_id,

            "technique_name": app[
                "technique_name"
            ],

            "product_supported": app[
                "product_supported"
            ],

            "applicability_status": (
                applicability_status
            ),

            "current_environment_applicability": (
                app[
                    "current_environment_applicability"
                ]
            ),

            "prioritization_posture": (
                app[
                    "prioritization_posture"
                ]
            ),

            "sigma_environment_posture": (
                sigma_environment_posture(
                    applicability_status
                )
            ),

            "sigma_rule_count": int(
                sigma.get(
                    "sigma_rule_count",
                    0
                )
            ),

            "sigma_knowledge_coverage_score": (
                float(
                    sigma.get(
                        "sigma_knowledge_coverage_score",
                        0.0
                    )
                )
            ),

            "sigma_detection_knowledge_gap_score": (
                float(
                    sigma.get(
                        "sigma_detection_knowledge_gap_score",
                        0.0
                    )
                )
            ),

            "sigma_detection_knowledge_gap_class": (
                sigma.get(
                    "sigma_detection_knowledge_gap_class"
                )
            ),

            "gap_source": (
                "prepared_sigma_corpus_proxy"
            ),

            "is_client_detection_coverage": (
                False
            ),

            "product_scope": (
                "master_catalog"
            ),

            "interpretation": (
                "Sigma gap is a detection-knowledge "
                "proxy from the prepared Sigma corpus; "
                "it is not deployed client detection "
                "coverage."
            ),
        }

        output_rows.append(row)

    if len(output_rows) != 697:
        validation_errors.append(
            f"Expected 697 output rows, "
            f"found {len(output_rows)}"
        )

    ids = [
        row["technique_id"]
        for row in output_rows
    ]

    if len(set(ids)) != len(ids):
        validation_errors.append(
            "Duplicate technique IDs detected"
        )

    if any(
        not row["product_supported"]
        for row in output_rows
    ):
        validation_errors.append(
            "At least one technique is "
            "incorrectly marked unsupported"
        )

    # Old Windows-era flags must not survive.
    forbidden_fields = {
        "platform_eligible",
        "current_hunt_eligible",
    }

    for row in output_rows:
        overlap = (
            forbidden_fields
            & set(row.keys())
        )

        if overlap:
            validation_errors.append(
                "Legacy eligibility fields "
                "survived into v1 output"
            )
            break

    applicability_counter = Counter(
        row["applicability_status"]
        for row in output_rows
    )

    posture_counter = Counter(
        row["sigma_environment_posture"]
        for row in output_rows
    )

    gap_class_counter = Counter(
        row[
            "sigma_detection_knowledge_gap_class"
        ]
        for row in output_rows
    )

    zero_rule_count = sum(
        1
        for row in output_rows
        if row["sigma_rule_count"] == 0
    )

    rule_count_total = sum(
        row["sigma_rule_count"]
        for row in output_rows
    )

    current_environment_rows = [
        row
        for row in output_rows
        if row["applicability_status"]
        in {
            "observed_environment_applicable",
            "known_present_collection_gap",
        }
    ]

    current_environment_zero_rules = sum(
        1
        for row in current_environment_rows
        if row["sigma_rule_count"] == 0
    )

    validation_status = (
        "PASS"
        if not validation_errors
        else "FAIL"
    )

    with JSONL_OUTPUT.open(
        "w",
        encoding="utf-8",
        newline="\n"
    ) as f:
        for row in output_rows:
            f.write(
                json.dumps(
                    row,
                    ensure_ascii=False
                )
                + "\n"
            )

    fields = [
        "technique_id",
        "technique_name",
        "product_supported",
        "applicability_status",
        "current_environment_applicability",
        "prioritization_posture",
        "sigma_environment_posture",
        "sigma_rule_count",
        "sigma_knowledge_coverage_score",
        "sigma_detection_knowledge_gap_score",
        "sigma_detection_knowledge_gap_class",
        "gap_source",
        "is_client_detection_coverage",
        "product_scope",
        "interpretation",
    ]

    with CSV_OUTPUT.open(
        "w",
        encoding="utf-8-sig",
        newline=""
    ) as f:
        writer = csv.DictWriter(
            f,
            fieldnames=fields
        )

        writer.writeheader()
        writer.writerows(
            output_rows
        )

    report = {
        "component": (
            "master_sigma_knowledge_gap"
        ),

        "version": "1.0",

        "generated_at_utc": (
            datetime.now(
                timezone.utc
            ).isoformat()
        ),

        "master_techniques": (
            len(output_rows)
        ),

        "product_supported": sum(
            1
            for row in output_rows
            if row["product_supported"]
        ),

        "sigma_rule_mapping_total": (
            rule_count_total
        ),

        "zero_rule_techniques": (
            zero_rule_count
        ),

        "applicability_counts": dict(
            sorted(
                applicability_counter.items()
            )
        ),

        "sigma_environment_posture_counts": (
            dict(
                sorted(
                    posture_counter.items()
                )
            )
        ),

        "gap_class_counts": dict(
            sorted(
                gap_class_counter.items()
            )
        ),

        "current_environment_techniques": (
            len(
                current_environment_rows
            )
        ),

        "current_environment_zero_rule_techniques": (
            current_environment_zero_rules
        ),

        "gap_source": (
            "prepared_sigma_corpus_proxy"
        ),

        "is_client_detection_coverage": (
            False
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
        "Master Sigma Knowledge Gap v1.0"
    )
    print(
        "-------------------------------"
    )

    print(
        f"Master techniques        : "
        f"{len(output_rows)}"
    )

    print(
        f"Product supported        : "
        f"{sum(1 for r in output_rows if r['product_supported'])}"
    )

    print(
        f"Sigma rule mappings      : "
        f"{rule_count_total}"
    )

    print(
        f"Zero-rule techniques     : "
        f"{zero_rule_count}"
    )

    print()

    print(
        "Applicability:"
    )

    for key, value in sorted(
        applicability_counter.items()
    ):
        print(
            f"  {key:<38} {value}"
        )

    print()

    print(
        "Sigma environment posture:"
    )

    for key, value in sorted(
        posture_counter.items()
    ):
        print(
            f"  {key:<44} {value}"
        )

    print()

    print(
        "Sigma knowledge-gap classes:"
    )

    for key, value in sorted(
        gap_class_counter.items()
    ):
        print(
            f"  {str(key):<20} {value}"
        )

    print()

    print(
        f"Current-env techniques   : "
        f"{len(current_environment_rows)}"
    )

    print(
        f"Current-env zero rules   : "
        f"{current_environment_zero_rules}"
    )

    print()

    print(
        f"Gap source               : "
        f"prepared_sigma_corpus_proxy"
    )

    print(
        f"Client detection coverage: False"
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
        f"CSV    : {CSV_OUTPUT}"
    )
    print(
        f"JSONL  : {JSONL_OUTPUT}"
    )
    print(
        f"Report : {REPORT_OUTPUT}"
    )


if __name__ == "__main__":
    main()