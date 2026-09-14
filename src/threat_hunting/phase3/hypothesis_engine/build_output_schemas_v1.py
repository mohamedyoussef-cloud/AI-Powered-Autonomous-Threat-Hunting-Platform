from __future__ import annotations

import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[4]

SCHEMA_DIR = (
    PROJECT_ROOT
    / "schemas"
    / "phase3"
    / "hypothesis_engine"
)

CONFIG_FILE = (
    PROJECT_ROOT
    / "config"
    / "phase3"
    / "hypothesis_engine_task_contracts_v1.json"
)


CONFIDENCE_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "level",
        "score",
        "explanation",
    ],
    "properties": {
        "level": {
            "type": "string",
            "enum": [
                "low",
                "medium",
                "high",
            ],
        },
        "score": {
            "type": "number",
            "minimum": 0.0,
            "maximum": 1.0,
        },
        "explanation": {
            "type": "string",
            "minLength": 1,
        },
    },
}


DATA_COMPONENT_REF_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "component_id",
        "component_name",
        "reason",
    ],
    "properties": {
        "component_id": {
            "type": "string",
            "pattern": "^DC[0-9]{4}$",
        },
        "component_name": {
            "type": "string",
            "minLength": 1,
        },
        "reason": {
            "type": "string",
            "minLength": 1,
        },
    },
}


COLLECTION_REQUIREMENT_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "component_id",
        "component_name",
        "requirement",
    ],
    "properties": {
        "component_id": {
            "type": "string",
            "pattern": "^DC[0-9]{4}$",
        },
        "component_name": {
            "type": "string",
            "minLength": 1,
        },
        "requirement": {
            "type": "string",
            "minLength": 1,
        },
    },
}


EXTERNAL_EVIDENCE_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "component_id",
        "component_name",
        "evidence_needed",
    ],
    "properties": {
        "component_id": {
            "type": "string",
            "pattern": "^DC[0-9]{4}$",
        },
        "component_name": {
            "type": "string",
            "minLength": 1,
        },
        "evidence_needed": {
            "type": "string",
            "minLength": 1,
        },
    },
}


RUNTIME_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "Runtime Hunt Hypothesis Output v1",
    "type": "object",
    "additionalProperties": False,
    "required": [
        "hypothesis",
        "rationale",
        "investigation_focus",
        "required_telemetry",
        "known_collection_limitations",
        "confidence",
    ],
    "properties": {
        "hypothesis": {
            "type": "string",
            "minLength": 20,
        },
        "rationale": {
            "type": "string",
            "minLength": 20,
        },
        "investigation_focus": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "string",
                "minLength": 1,
            },
        },
        "required_telemetry": {
            "type": "array",
            "minItems": 1,
            "items": DATA_COMPONENT_REF_SCHEMA,
        },
        "known_collection_limitations": {
            "type": "array",
            "items": {
                "type": "string",
                "minLength": 1,
            },
        },
        "confidence": CONFIDENCE_SCHEMA,
    },
}


COLLECTION_GAP_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "Collection Gap Resolution Output v1",
    "type": "object",
    "additionalProperties": False,
    "required": [
        "collection_gap",
        "affected_data_components",
        "required_collection",
        "current_evidence_limitations",
        "next_action",
    ],
    "properties": {
        "collection_gap": {
            "type": "string",
            "minLength": 10,
        },
        "affected_data_components": {
            "type": "array",
            "minItems": 1,
            "items": DATA_COMPONENT_REF_SCHEMA,
        },
        "required_collection": {
            "type": "array",
            "minItems": 1,
            "items": COLLECTION_REQUIREMENT_SCHEMA,
        },
        "current_evidence_limitations": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "string",
                "minLength": 1,
            },
        },
        "next_action": {
            "type": "string",
            "minLength": 10,
        },
    },
}


ENVIRONMENT_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "Environment Presence Resolution Output v1",
    "type": "object",
    "additionalProperties": False,
    "required": [
        "unresolved_platforms",
        "required_environment_evidence",
        "resolution_questions",
        "next_action",
    ],
    "properties": {
        "unresolved_platforms": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "string",
                "minLength": 1,
            },
        },
        "required_environment_evidence": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "string",
                "minLength": 1,
            },
        },
        "resolution_questions": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "string",
                "minLength": 1,
            },
        },
        "next_action": {
            "type": "string",
            "minLength": 10,
        },
    },
}


PRE_ATTACK_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "PRE-Attack Hypothesis Output v1",
    "type": "object",
    "additionalProperties": False,
    "required": [
        "hypothesis",
        "rationale",
        "investigation_focus",
        "required_external_evidence",
        "limitations",
        "confidence",
    ],
    "properties": {
        "hypothesis": {
            "type": "string",
            "minLength": 20,
        },
        "rationale": {
            "type": "string",
            "minLength": 20,
        },
        "investigation_focus": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "string",
                "minLength": 1,
            },
        },
        "required_external_evidence": {
            "type": "array",
            "minItems": 1,
            "items": EXTERNAL_EVIDENCE_SCHEMA,
        },
        "limitations": {
            "type": "array",
            "items": {
                "type": "string",
                "minLength": 1,
            },
        },
        "confidence": CONFIDENCE_SCHEMA,
    },
}


SCHEMAS = {
    "runtime_hunt_output_v1.schema.json":
        RUNTIME_SCHEMA,

    "collection_gap_output_v1.schema.json":
        COLLECTION_GAP_SCHEMA,

    "environment_resolution_output_v1.schema.json":
        ENVIRONMENT_SCHEMA,

    "pre_attack_output_v1.schema.json":
        PRE_ATTACK_SCHEMA,
}


SCHEMA_BY_TASK = {
    "generate_runtime_hunt_hypothesis":
        "schemas/phase3/hypothesis_engine/"
        "runtime_hunt_output_v1.schema.json",

    "resolve_collection_gap":
        "schemas/phase3/hypothesis_engine/"
        "collection_gap_output_v1.schema.json",

    "resolve_environment_presence":
        "schemas/phase3/hypothesis_engine/"
        "environment_resolution_output_v1.schema.json",

    "generate_pre_attack_hypothesis":
        "schemas/phase3/hypothesis_engine/"
        "pre_attack_output_v1.schema.json",
}


def main():
    SCHEMA_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    for filename, schema in SCHEMAS.items():
        output = SCHEMA_DIR / filename

        output.write_text(
            json.dumps(
                schema,
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

    contracts = json.loads(
        CONFIG_FILE.read_text(
            encoding="utf-8-sig"
        )
    )

    for task_mode, schema_path in (
        SCHEMA_BY_TASK.items()
    ):
        contracts[
            "tasks"
        ][
            task_mode
        ][
            "output_schema"
        ] = schema_path

    CONFIG_FILE.write_text(
        json.dumps(
            contracts,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    print(
        "Hypothesis Engine Output Schemas v1"
    )
    print(
        "-----------------------------------"
    )

    for filename in SCHEMAS:
        print(
            f"Created : "
            f"{SCHEMA_DIR / filename}"
        )

    print()
    print(
        f"Updated : {CONFIG_FILE}"
    )

    print()
    print(
        "Schema count : 4"
    )
    print(
        "Status       : PASS"
    )


if __name__ == "__main__":
    main()
