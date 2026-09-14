from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(r"D:\ThreatHunting\project")

PHASE3 = (
    ROOT / "data" / "processed" / "phase3"
)

HYP_DIR = (
    PHASE3 / "hypothesis_engine"
)

ELIG_DIR = (
    PHASE3 / "detection_eligibility"
)

SCHEMA_PATH = (
    ROOT
    / "schemas"
    / "phase3"
    / "detection_eligibility"
    / "eligibility_output_v1.schema.json"
)

MASTER_PATH = (
    PHASE3
    / "master_hypothesis_context_v2.jsonl"
)

ROUTER_PATH = (
    PHASE3
    / "router"
    / "hypothesis_router_index_v1.jsonl"
)

OUTPUT_PATH = (
    ELIG_DIR
    / "detection_eligibility_outputs_v1.jsonl"
)

INDEX_PATH = (
    ELIG_DIR
    / "detection_eligibility_index_v1.jsonl"
)

ERROR_PATH = (
    ELIG_DIR
    / "detection_eligibility_errors_v1.jsonl"
)

HYPOTHESIS_PATHS = [
    HYP_DIR / "runtime_hunt_outputs_v1.jsonl",
    HYP_DIR / "collection_gap_outputs_v1.jsonl",
    HYP_DIR / "environment_resolution_outputs_v1.jsonl",
    HYP_DIR / "pre_attack_outputs_v1.jsonl",
]


DECISION_ACTION = {
    "ELIGIBLE_FOR_DETECTION":
        "DETECTION_PLAN",

    "COLLECTION_BLOCKED":
        "COLLECTION_GAP_RESOLUTION",

    "ENVIRONMENT_BLOCKED":
        "ENVIRONMENT_RESOLUTION",

    "EXTERNAL_HUNT_ONLY":
        "EXTERNAL_HUNT_WORKFLOW",

    "NOT_ELIGIBLE":
        "NO_DETECTION_GENERATION",
}


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(
        path.read_text(
            encoding="utf-8-sig"
        )
    )


def read_jsonl(
    path: Path,
) -> list[dict[str, Any]]:
    rows = []

    with path.open(
        "r",
        encoding="utf-8-sig",
    ) as handle:

        for line_no, line in enumerate(
            handle,
            start=1,
        ):
            line = line.strip()

            if not line:
                continue

            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    f"Invalid JSONL "
                    f"{path}:{line_no}: {exc}"
                ) from exc

            rows.append(row)

    return rows


def index_unique(
    rows: list[dict[str, Any]],
    label: str,
) -> dict[str, dict[str, Any]]:

    result = {}

    for row in rows:
        tid = row.get("technique_id")

        if not tid:
            raise RuntimeError(
                f"{label}: missing technique_id"
            )

        if tid in result:
            raise RuntimeError(
                f"{label}: duplicate technique_id:{tid}"
            )

        result[tid] = row

    return result


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def recompute_fingerprint(
    master: dict[str, Any],
    router: dict[str, Any],
    hypothesis: dict[str, Any],
) -> str:

    digest = hashlib.sha256()

    digest.update(
        canonical_json(
            {
                "master_context": master,
                "router_record": router,
                "hypothesis_output": hypothesis,
            }
        )
    )

    return (
        "sha256:"
        + digest.hexdigest()
    )


def fail(
    failures: list[str],
    message: str,
) -> None:
    failures.append(message)


def main() -> int:

    required = [
        SCHEMA_PATH,
        MASTER_PATH,
        ROUTER_PATH,
        OUTPUT_PATH,
        INDEX_PATH,
        ERROR_PATH,
        *HYPOTHESIS_PATHS,
    ]

    for path in required:
        if not path.exists():
            raise FileNotFoundError(
                f"Missing required audit artifact: {path}"
            )

    schema = read_json(
        SCHEMA_PATH
    )

    validator = Draft202012Validator(
        schema,
        format_checker=FormatChecker(),
    )

    master_rows = read_jsonl(
        MASTER_PATH
    )

    router_rows = read_jsonl(
        ROUTER_PATH
    )

    hypothesis_rows = []

    for path in HYPOTHESIS_PATHS:
        hypothesis_rows.extend(
            read_jsonl(path)
        )

    eligibility_rows = read_jsonl(
        OUTPUT_PATH
    )

    index_rows = read_jsonl(
        INDEX_PATH
    )

    error_rows = read_jsonl(
        ERROR_PATH
    )

    master = index_unique(
        master_rows,
        "master"
    )

    router = index_unique(
        router_rows,
        "router"
    )

    hypotheses = index_unique(
        hypothesis_rows,
        "hypotheses"
    )

    eligibility = index_unique(
        eligibility_rows,
        "eligibility"
    )

    eligibility_index = index_unique(
        index_rows,
        "eligibility_index"
    )

    failures = []

    # ----------------------------------
    # 1. Dynamic universe coverage
    # ----------------------------------

    authoritative_ids = set(
        hypotheses
    )

    for name, mapping in [
        ("master", master),
        ("router", router),
        ("eligibility", eligibility),
        ("eligibility_index", eligibility_index),
    ]:
        if set(mapping) != authoritative_ids:
            fail(
                failures,
                f"TECHNIQUE_UNIVERSE_MISMATCH:{name}"
            )

    # ----------------------------------
    # 2. Error queue
    # ----------------------------------

    if error_rows:
        fail(
            failures,
            f"ERROR_QUEUE_NOT_EMPTY:{len(error_rows)}"
        )

    # ----------------------------------
    # 3. Schema validation
    # ----------------------------------

    schema_error_count = 0

    for row in eligibility_rows:
        errors = list(
            validator.iter_errors(row)
        )

        if errors:
            schema_error_count += 1

            fail(
                failures,
                "SCHEMA_FAILURE:"
                f"{row.get('technique_id')}:"
                f"{errors[0].message}"
            )

    # ----------------------------------
    # 4. Per-record semantic audit
    # ----------------------------------

    decision_counts = Counter()
    route_counts = Counter()
    fingerprint_failures = 0
    index_failures = 0

    for tid, row in eligibility.items():

        master_row = master[tid]
        router_row = router[tid]
        hypothesis_row = hypotheses[tid]
        idx = eligibility_index[tid]

        decision = row[
            "eligibility_decision"
        ]

        route = row[
            "source_route"
        ]

        decision_counts[
            decision
        ] += 1

        route_counts[
            route
        ] += 1

        # SUCCESS is mandatory in final decision artifact.
        if (
            row.get("processing_status")
            != "SUCCESS"
        ):
            fail(
                failures,
                f"NON_SUCCESS_OUTPUT:{tid}"
            )

        if row.get("error_codes"):
            fail(
                failures,
                f"SUCCESS_WITH_ERROR_CODES:{tid}"
            )

        # Decision -> downstream mapping.
        expected_action = (
            DECISION_ACTION.get(
                decision
            )
        )

        if expected_action is None:
            fail(
                failures,
                f"UNKNOWN_DECISION:{tid}:{decision}"
            )

        elif (
            row.get("downstream_action")
            != expected_action
        ):
            fail(
                failures,
                f"DOWNSTREAM_ACTION_MISMATCH:{tid}"
            )

        # Cross-artifact identity.
        if (
            route
            != hypothesis_row.get("route")
            or route
            != router_row.get("route")
            or route
            != master_row.get("route")
        ):
            fail(
                failures,
                f"ROUTE_MISMATCH:{tid}"
            )

        if (
            row.get("technique_name")
            != hypothesis_row.get("technique_name")
        ):
            fail(
                failures,
                f"TECHNIQUE_NAME_MISMATCH:{tid}"
            )

        # Fingerprint integrity.
        expected_fingerprint = (
            recompute_fingerprint(
                master_row,
                router_row,
                hypothesis_row,
            )
        )

        if (
            row.get("input_fingerprint")
            != expected_fingerprint
        ):
            fingerprint_failures += 1

            fail(
                failures,
                f"INPUT_FINGERPRINT_MISMATCH:{tid}"
            )

        # Eligibility index must be faithful.
        expected_index = {
            "gate_version":
                row["gate_version"],

            "technique_id":
                row["technique_id"],

            "technique_name":
                row["technique_name"],

            "source_route":
                row["source_route"],

            "runtime_hunt_rank":
                row["runtime_hunt_rank"],

            "processing_status":
                row["processing_status"],

            "eligibility_decision":
                row["eligibility_decision"],

            "reason_codes":
                row["reason_codes"],

            "downstream_action":
                row["downstream_action"],

            "input_fingerprint":
                row["input_fingerprint"],
        }

        if idx != expected_index:
            index_failures += 1

            fail(
                failures,
                f"INDEX_RECORD_MISMATCH:{tid}"
            )

        reasons = set(
            row.get(
                "reason_codes",
                []
            )
        )

        assessments = row.get(
            "component_assessments",
            []
        )

        required_components = row.get(
            "required_data_components",
            []
        )

        assessment_ids = [
            item.get("component_id")
            for item in assessments
        ]

        # No duplicate normalized components.
        if (
            len(required_components)
            != len(set(required_components))
        ):
            fail(
                failures,
                f"DUPLICATE_REQUIRED_COMPONENT:{tid}"
            )

        if (
            len(assessment_ids)
            != len(set(assessment_ids))
        ):
            fail(
                failures,
                f"DUPLICATE_COMPONENT_ASSESSMENT:{tid}"
            )

        # ----------------------------------
        # Runtime decision semantics
        # ----------------------------------

        if route == "runtime_hunt":

            if (
                set(required_components)
                != set(assessment_ids)
            ):
                fail(
                    failures,
                    f"RUNTIME_COMPONENT_ASSESSMENT_COVERAGE:{tid}"
                )

            if decision == (
                "ELIGIBLE_FOR_DETECTION"
            ):

                required_reason = (
                    "RUNTIME_REQUIRED_COMPONENTS_"
                    "ENVIRONMENT_GROUNDED"
                )

                if required_reason not in reasons:
                    fail(
                        failures,
                        f"ELIGIBLE_REASON_MISSING:{tid}"
                    )

                for component in assessments:

                    if (
                        component.get(
                            "current_environment_grounded"
                        )
                        is not True
                    ):
                        fail(
                            failures,
                            f"ELIGIBLE_UNGROUNDED_COMPONENT:"
                            f"{tid}:"
                            f"{component.get('component_id')}"
                        )

                    if (
                        component.get(
                            "requirement_unspecified"
                        )
                        is True
                    ):
                        fail(
                            failures,
                            f"ELIGIBLE_UNSPECIFIED_REQUIREMENT:"
                            f"{tid}:"
                            f"{component.get('component_id')}"
                        )

                    if (
                        component.get(
                            "eligibility_effect"
                        )
                        != "SATISFIED"
                    ):
                        fail(
                            failures,
                            f"ELIGIBLE_BAD_COMPONENT_EFFECT:"
                            f"{tid}"
                        )

            elif decision == "COLLECTION_BLOCKED":

                blockers = [
                    c for c in assessments
                    if c.get(
                        "eligibility_effect"
                    )
                    == "COLLECTION_BLOCKER"
                ]

                if not blockers:
                    fail(
                        failures,
                        f"RUNTIME_BLOCKED_WITHOUT_BLOCKER:{tid}"
                    )

                grounded_reason = (
                    "REQUIRED_COMPONENT_NOT_"
                    "ENVIRONMENT_GROUNDED"
                )

                unspecified_reason = (
                    "REQUIRED_COMPONENT_"
                    "REQUIREMENT_UNSPECIFIED"
                )

                actual_grounding_block = any(
                    c.get(
                        "current_environment_grounded"
                    )
                    is not True
                    for c in assessments
                )

                actual_unspecified_block = any(
                    c.get(
                        "requirement_unspecified"
                    )
                    is True
                    for c in assessments
                )

                if (
                    actual_grounding_block
                    != (
                        grounded_reason
                        in reasons
                    )
                ):
                    fail(
                        failures,
                        f"GROUNDING_REASON_MISMATCH:{tid}"
                    )

                if (
                    actual_unspecified_block
                    != (
                        unspecified_reason
                        in reasons
                    )
                ):
                    fail(
                        failures,
                        f"UNSPECIFIED_REASON_MISMATCH:{tid}"
                    )

            else:
                fail(
                    failures,
                    f"INVALID_RUNTIME_DECISION:{tid}:{decision}"
                )

        # ----------------------------------
        # Fixed-route semantics
        # ----------------------------------

        elif route == "collection_gap_resolution":

            if (
                decision != "COLLECTION_BLOCKED"
                or "EXISTING_COLLECTION_GAP"
                not in reasons
            ):
                fail(
                    failures,
                    f"COLLECTION_ROUTE_DECISION_FAILURE:{tid}"
                )

        elif route == "environment_resolution":

            if (
                decision != "ENVIRONMENT_BLOCKED"
                or "ENVIRONMENT_PRESENCE_UNRESOLVED"
                not in reasons
            ):
                fail(
                    failures,
                    f"ENVIRONMENT_ROUTE_DECISION_FAILURE:{tid}"
                )

        elif route == "pre_attack_hunt":

            if (
                decision != "EXTERNAL_HUNT_ONLY"
                or "PRE_ATTACK_EXTERNAL_SCOPE"
                not in reasons
            ):
                fail(
                    failures,
                    f"PRE_ATTACK_ROUTE_DECISION_FAILURE:{tid}"
                )

        else:
            fail(
                failures,
                f"UNKNOWN_ROUTE:{tid}:{route}"
            )

        # Grounding invariants preserved downstream.
        grounding = row.get(
            "grounding_assertions",
            {}
        )

        if (
            grounding.get(
                "telemetry_evidence_proves_occurrence"
            )
            is not False
        ):
            fail(
                failures,
                f"OCCURRENCE_INVARIANT_FAILURE:{tid}"
            )

        if (
            grounding.get(
                "sigma_proxy_is_client_detection_coverage"
            )
            is not False
        ):
            fail(
                failures,
                f"SIGMA_PROXY_INVARIANT_FAILURE:{tid}"
            )

    print(
        "===== DETECTION ELIGIBILITY GATE "
        "FINAL AUDIT v1.0 ====="
    )

    print()
    print("Authoritative inputs :", len(authoritative_ids))
    print("Eligibility outputs :", len(eligibility_rows))
    print("Eligibility index   :", len(index_rows))
    print("Error queue         :", len(error_rows))
    print()

    print("Schema errors       :", schema_error_count)
    print("Fingerprint errors  :", fingerprint_failures)
    print("Index errors        :", index_failures)
    print()

    print("===== DECISIONS =====")

    for decision in [
        "ELIGIBLE_FOR_DETECTION",
        "COLLECTION_BLOCKED",
        "ENVIRONMENT_BLOCKED",
        "EXTERNAL_HUNT_ONLY",
        "NOT_ELIGIBLE",
    ]:
        print(
            f"{decision:<26}: "
            f"{decision_counts.get(decision, 0)}"
        )

    print()
    print("Decision total      :", sum(decision_counts.values()))

    print()
    print("===== ROUTES =====")

    for route in sorted(route_counts):
        print(
            f"{route:<28}: "
            f"{route_counts[route]}"
        )

    print()
    print("===== FINAL RESULT =====")
    print("Audit failures      :", len(failures))

    for failure in failures[:100]:
        print(failure)

    if failures:
        print()
        print(
            "DETECTION ELIGIBILITY GATE "
            "FINAL AUDIT v1.0: FAIL"
        )
        return 1

    print()
    print(
        "DETECTION ELIGIBILITY GATE "
        "FINAL AUDIT v1.0: PASS"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
