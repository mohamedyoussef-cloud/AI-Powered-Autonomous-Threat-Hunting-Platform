from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator


PROJECT_ROOT = Path(__file__).resolve().parents[4]

CONTRACT_FILE = (
    PROJECT_ROOT
    / "config"
    / "phase3"
    / "hypothesis_engine_task_contracts_v1.json"
)


def main():
    contracts = json.loads(
        CONTRACT_FILE.read_text(
            encoding="utf-8-sig"
        )
    )

    errors = []

    for task_mode, task in contracts["tasks"].items():
        schema_rel = task.get(
            "output_schema"
        )

        if not schema_rel:
            errors.append(
                f"{task_mode}:missing_output_schema"
            )
            continue

        schema_path = (
            PROJECT_ROOT
            / schema_rel
        )

        if not schema_path.exists():
            errors.append(
                f"{task_mode}:schema_not_found:"
                f"{schema_path}"
            )
            continue

        schema = json.loads(
            schema_path.read_text(
                encoding="utf-8-sig"
            )
        )

        try:
            Draft202012Validator.check_schema(
                schema
            )

        except Exception as exc:
            errors.append(
                f"{task_mode}:invalid_schema:{exc}"
            )
            continue

        schema_required = set(
            schema.get(
                "required",
                []
            )
        )

        contract_required = set(
            task.get(
                "required_output_fields",
                []
            )
        )

        if schema_required != contract_required:
            errors.append(
                f"{task_mode}:required_fields_mismatch"
            )

    print(
        "Hypothesis Engine Schema Validation v1"
    )
    print(
        "--------------------------------------"
    )
    print(
        f"Project root   : {PROJECT_ROOT}"
    )
    print(
        f"Task contracts : {len(contracts['tasks'])}"
    )
    print(
        f"Errors         : {len(errors)}"
    )
    print()

    if errors:
        for error in errors:
            print(
                " - " + error
            )

        print()
        print(
            "Validation     : FAIL"
        )

        raise SystemExit(1)

    print(
        "Validation     : PASS"
    )


if __name__ == "__main__":
    main()
