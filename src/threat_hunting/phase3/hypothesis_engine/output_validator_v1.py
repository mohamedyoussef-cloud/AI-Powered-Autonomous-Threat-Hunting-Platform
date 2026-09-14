from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator


PROJECT_ROOT = Path(__file__).resolve().parents[4]

CONTRACT_FILE = (
    PROJECT_ROOT
    / "config"
    / "phase3"
    / "hypothesis_engine_task_contracts_v1.json"
)


def read_json(path: Path):
    return json.loads(
        path.read_text(
            encoding="utf-8-sig"
        )
    )


CONTRACTS = read_json(CONTRACT_FILE)["tasks"]


def _all_strings(value: Any):
    if isinstance(value, str):
        yield value

    elif isinstance(value, dict):
        for child in value.values():
            yield from _all_strings(child)

    elif isinstance(value, list):
        for child in value:
            yield from _all_strings(child)


def _allowed_components(record):
    context = record["context"]

    components = (
        context
        .get("telemetry", {})
        .get("component_evaluations", [])
    )

    return {
        component["component_id"]:
            component["component_name"]
        for component in components
        if component.get("component_id")
        and component.get("component_name")
    }


def _validate_component_refs(
    refs,
    allowed_components,
    errors,
    field_name,
):
    for item in refs:
        component_id = item.get(
            "component_id"
        )

        component_name = item.get(
            "component_name"
        )

        if component_id not in allowed_components:
            errors.append(
                f"{field_name}:"
                f"ungrounded_component:"
                f"{component_id}"
            )
            continue

        expected_name = (
            allowed_components[
                component_id
            ]
        )

        if component_name != expected_name:
            errors.append(
                f"{field_name}:"
                f"component_name_mismatch:"
                f"{component_id}:"
                f"expected={expected_name}:"
                f"actual={component_name}"
            )


def validate_schema(
    task_mode: str,
    output: dict,
):
    errors = []

    task = CONTRACTS.get(
        task_mode
    )

    if task is None:
        return [
            f"unsupported_task_mode:{task_mode}"
        ]

    schema_rel = task.get(
        "output_schema"
    )

    if not schema_rel:
        return [
            f"missing_output_schema:{task_mode}"
        ]

    schema_path = (
        PROJECT_ROOT
        / schema_rel
    )

    schema = read_json(
        schema_path
    )

    validator = Draft202012Validator(
        schema
    )

    for error in sorted(
        validator.iter_errors(output),
        key=lambda e: list(e.path),
    ):
        path = ".".join(
            str(x)
            for x in error.path
        )

        errors.append(
            f"schema:"
            f"{path or '<root>'}:"
            f"{error.message}"
        )

    return errors


def validate_grounding(
    record: dict,
    output: dict,
):
    errors = []

    task_mode = record[
        "model_task_mode"
    ]

    context = record[
        "context"
    ]

    allowed_components = (
        _allowed_components(record)
    )

    if task_mode == (
        "generate_runtime_hunt_hypothesis"
    ):
        _validate_component_refs(
            output.get(
                "required_telemetry",
                [],
            ),
            allowed_components,
            errors,
            "required_telemetry",
        )

    elif task_mode == (
        "resolve_collection_gap"
    ):
        _validate_component_refs(
            output.get(
                "affected_data_components",
                [],
            ),
            allowed_components,
            errors,
            "affected_data_components",
        )

        _validate_component_refs(
            output.get(
                "required_collection",
                [],
            ),
            allowed_components,
            errors,
            "required_collection",
        )

    elif task_mode == (
        "generate_pre_attack_hypothesis"
    ):
        _validate_component_refs(
            output.get(
                "required_external_evidence",
                [],
            ),
            allowed_components,
            errors,
            "required_external_evidence",
        )

    elif task_mode == (
        "resolve_environment_presence"
    ):
        allowed_platforms = set(
            context
            .get("environment", {})
            .get(
                "technique_unknown_platform_matches",
                [],
            )
        )

        actual_platforms = set(
            output.get(
                "unresolved_platforms",
                [],
            )
        )

        invalid_platforms = (
            actual_platforms
            - allowed_platforms
        )

        for platform in sorted(
            invalid_platforms
        ):
            errors.append(
                "unresolved_platforms:"
                f"ungrounded_platform:"
                f"{platform}"
            )

    text = "\n".join(
        _all_strings(output)
    )

    lower_text = text.lower()

    sigma_markers = [
        "logsource:",
        "detection:",
        "condition:",
    ]

    sigma_marker_hits = [
        marker
        for marker in sigma_markers
        if marker in lower_text
    ]

    if len(sigma_marker_hits) >= 2:
        errors.append(
            "sigma_generation_violation"
        )

    query_patterns = [
        r"\bselect\s+.+\s+from\b",
        r"\bindex\s*=\s*[a-zA-Z0-9_*.-]+",
        r"\bsearch\s+index\s*=",
    ]

    for pattern in query_patterns:
        if re.search(
            pattern,
            text,
            flags=(
                re.IGNORECASE
                | re.DOTALL
            ),
        ):
            errors.append(
                "siem_query_generation_violation"
            )
            break

    occurrence_patterns = [
        r"\bwas\s+(observed|detected|confirmed|identified)\b",
        r"\bwere\s+(observed|detected|confirmed|identified)\b",
        r"\bhas\s+been\s+(observed|detected|confirmed|identified)\b",
        r"\bhave\s+been\s+(observed|detected|confirmed|identified)\b",
        r"\bwe\s+(observed|detected|confirmed|identified)\b",
        r"\bthe\s+adversary\s+(used|executed|created|modified|accessed|exfiltrated|established|performed)\b",
        r"\bthe\s+attacker\s+(used|executed|created|modified|accessed|exfiltrated|established|performed)\b",
    ]

    for pattern in occurrence_patterns:
        if re.search(
            pattern,
            text,
            flags=re.IGNORECASE,
        ):
            errors.append(
                "occurrence_claim_violation"
            )
            break

    return errors


def validate_output(
    record: dict,
    output: dict,
):
    task_mode = record[
        "model_task_mode"
    ]

    schema_errors = (
        validate_schema(
            task_mode,
            output,
        )
    )

    if schema_errors:
        return {
            "schema_valid": False,
            "grounding_valid": False,
            "errors": schema_errors,
        }

    grounding_errors = (
        validate_grounding(
            record,
            output,
        )
    )

    return {
        "schema_valid": True,
        "grounding_valid":
            not grounding_errors,
        "errors":
            grounding_errors,
    }
