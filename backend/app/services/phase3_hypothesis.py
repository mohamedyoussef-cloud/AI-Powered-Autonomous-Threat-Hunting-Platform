from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.core.config import get_settings


settings = get_settings()


# ============================================================
# JSONL LOADER
# ============================================================

def _jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []

    rows: list[dict[str, Any]] = []

    with path.open("r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, start=1):
            line = line.strip()

            if not line:
                continue

            try:
                value = json.loads(line)

                if isinstance(value, dict):
                    rows.append(value)

            except json.JSONDecodeError:
                # Keep one malformed line from breaking the entire API.
                continue

    return rows


# ============================================================
# ROUTE FILES
# ============================================================

ROUTE_FILES = {
    "runtime_hunt": "runtime_hunt_outputs_v1.jsonl",
    "pre_attack_hunt": "pre_attack_outputs_v1.jsonl",
    "collection_gap_resolution": "collection_gap_outputs_v1.jsonl",
    "environment_resolution": "environment_resolution_outputs_v1.jsonl",
}


# ============================================================
# NORMALIZATION HELPERS
# ============================================================

def _technique_name(row: dict[str, Any]) -> str:
    """
    Resolve technique name from the available Phase 3 structures.
    """

    if row.get("technique_name"):
        return str(row["technique_name"])

    technique = row.get("technique")

    if isinstance(technique, dict):
        if technique.get("technique_name"):
            return str(technique["technique_name"])

        if technique.get("name"):
            return str(technique["name"])

    model_output = row.get("model_output")

    if isinstance(model_output, dict):
        if model_output.get("technique_name"):
            return str(model_output["technique_name"])

    return "Unknown"


def _confidence(model_output: dict[str, Any]) -> dict[str, Any] | None:
    value = model_output.get("confidence")

    if isinstance(value, dict):
        return {
            "level": value.get("level"),
            "score": value.get("score"),
            "explanation": value.get("explanation"),
        }

    return None


def _normalize_output(
    route: str,
    raw: dict[str, Any],
) -> dict[str, Any]:
    """
    Preserve the route-specific model output while exposing a
    normalized shape for the frontend/API.
    """

    model_output = raw.get("model_output")

    if not isinstance(model_output, dict):
        model_output = {}

    normalized: dict[str, Any] = {
        "route": route,
        "status": raw.get("status"),
        "model": raw.get("model"),
        "validation": raw.get("validation", {}),
        "attempts": raw.get("attempts"),
        "latency_seconds": raw.get("latency_seconds"),
        "usage": raw.get("usage"),
        "raw": model_output,
    }

    # --------------------------------------------------------
    # Runtime Hunt / Pre-Attack
    # --------------------------------------------------------

    if route in {"runtime_hunt", "pre_attack_hunt"}:
        normalized.update({
            "hypothesis": model_output.get("hypothesis"),
            "rationale": model_output.get("rationale"),
            "investigation_focus": model_output.get("investigation_focus"),
            "confidence": _confidence(model_output),
        })

    if route == "runtime_hunt":
        normalized["required_telemetry"] = model_output.get(
            "required_telemetry",
            [],
        )

        normalized["known_collection_limitations"] = model_output.get(
            "known_collection_limitations",
            [],
        )

    elif route == "pre_attack_hunt":
        normalized["required_external_evidence"] = model_output.get(
            "required_external_evidence",
            [],
        )

        normalized["limitations"] = model_output.get(
            "limitations",
            [],
        )

    # --------------------------------------------------------
    # Collection Gap Resolution
    # --------------------------------------------------------

    elif route == "collection_gap_resolution":
        normalized.update({
            "collection_gap": model_output.get("collection_gap"),
            "affected_data_components": model_output.get(
                "affected_data_components",
                [],
            ),
            "required_collection": model_output.get(
                "required_collection",
                [],
            ),
            "current_evidence_limitations": model_output.get(
                "current_evidence_limitations",
                [],
            ),
            "next_action": model_output.get("next_action"),
        })

    # --------------------------------------------------------
    # Environment Resolution
    # --------------------------------------------------------

    elif route == "environment_resolution":
        normalized.update({
            "unresolved_platforms": model_output.get(
                "unresolved_platforms",
                [],
            ),
            "required_environment_evidence": model_output.get(
                "required_environment_evidence",
                [],
            ),
            "resolution_questions": model_output.get(
                "resolution_questions",
                [],
            ),
            "next_action": model_output.get("next_action"),
        })

    return normalized


# ============================================================
# PHASE 3 BUNDLE
# ============================================================

@lru_cache(maxsize=1)
def _load_bundle(
    root_str: str,
    signature: tuple[int, ...],
) -> dict[str, Any]:

    root = Path(root_str)

    # Actual Phase 3 structure:
    #
    # data/
    #   processed/
    #     phase3/
    #       master_hypothesis_context_v2.jsonl
    #       hypothesis_engine/
    #         runtime_hunt_outputs_v1.jsonl
    #         pre_attack_outputs_v1.jsonl
    #         collection_gap_outputs_v1.jsonl
    #         environment_resolution_outputs_v1.jsonl
    #
    master_path = root / "master_hypothesis_context_v2.jsonl"

    master_rows = _jsonl(master_path)

    route_rows: dict[str, list[dict[str, Any]]] = {}

    for route, filename in ROUTE_FILES.items():
        route_rows[route] = _jsonl(
            root / "hypothesis_engine" / filename
        )

    # --------------------------------------------------------
    # Index outputs by technique_id
    # --------------------------------------------------------

    outputs_by_route: dict[
        str,
        dict[str, dict[str, Any]]
    ] = {}

    for route, rows in route_rows.items():
        outputs_by_route[route] = {}

        for row in rows:
            technique_id = row.get("technique_id")

            if technique_id:
                outputs_by_route[route][str(technique_id)] = row

    # --------------------------------------------------------
    # Master context index
    # --------------------------------------------------------

    master_by_id: dict[str, dict[str, Any]] = {}

    for row in master_rows:
        technique_id = row.get("technique_id")

        if technique_id:
            master_by_id[str(technique_id)] = row

    # --------------------------------------------------------
    # Build canonical 697 technique records
    # --------------------------------------------------------

    records: list[dict[str, Any]] = []

    for technique_id, context in master_by_id.items():

        route = (
            context.get("route")
            or context.get("task_mode")
            or "unknown"
        )

        route = str(route)

        output = outputs_by_route.get(route, {}).get(technique_id)

        # Some records may have route naming differences.
        if output is None:
            for candidate_route, route_map in outputs_by_route.items():
                if technique_id in route_map:
                    output = route_map[technique_id]
                    route = candidate_route
                    break

        if output is None:
            output = {}

        normalized_output = _normalize_output(
            route=route,
            raw=output,
        )

        technique = context.get("technique", {})
        if not isinstance(technique, dict):
            technique = {}

        records.append({
            "technique_id": technique_id,

            "technique_name": _technique_name({
                **context,
                "technique": technique,
            }),

            "route": route,

            "task_mode": context.get("task_mode"),

            "technique": technique,

            "environment": context.get(
                "environment",
                {},
            ),

            "telemetry": context.get(
                "telemetry",
                {},
            ),

            "sigma_knowledge": context.get(
                "sigma_knowledge",
                {},
            ),

            "prioritization": context.get(
                "prioritization",
                {},
            ),

            "grounding_constraints": context.get(
                "grounding_constraints",
                {},
            ),

            "llm_task": context.get(
                "llm_task",
                {},
            ),

            "engine_output": normalized_output,
        })

    # --------------------------------------------------------
    # Route counts
    # --------------------------------------------------------

    route_counts: dict[str, int] = {}

    for record in records:
        route = record["route"]

        route_counts[route] = (
            route_counts.get(route, 0) + 1
        )

    # --------------------------------------------------------
    # Model
    # --------------------------------------------------------

    model = "Qwen/Qwen3-8B-AWQ"

    for route_rows_list in route_rows.values():
        for row in route_rows_list:

            if row.get("model"):
                model = str(row["model"])
                break

        if model != "Qwen/Qwen3-8B-AWQ":
            break

    return {
        "records": records,
        "route_counts": route_counts,
        "model": model,
        "source": str(root),
    }


# ============================================================
# FILE SIGNATURE
# ============================================================

def _signature(root: Path) -> tuple[int, ...]:

    names = [
        "master_hypothesis_context_v2.jsonl",
        "hypothesis_engine/runtime_hunt_outputs_v1.jsonl",
        "hypothesis_engine/pre_attack_outputs_v1.jsonl",
        "hypothesis_engine/collection_gap_outputs_v1.jsonl",
        "hypothesis_engine/environment_resolution_outputs_v1.jsonl",
    ]

    signature: list[int] = []

    for name in names:
        path = root / name

        if path.exists():
            signature.append(path.stat().st_mtime_ns)
        else:
            signature.append(0)

    return tuple(signature)


# ============================================================
# PUBLIC API
# ============================================================

def load_phase3() -> dict[str, Any]:

    root = Path(settings.TEAM_PHASE3_ROOT)

    return _load_bundle(
        str(root),
        _signature(root),
    )


def list_hypotheses(
    q: str | None = None,
    route: str | None = None,
) -> list[dict[str, Any]]:

    records = load_phase3()["records"]

    ql = q.lower().strip() if q else None

    output: list[dict[str, Any]] = []

    for record in records:

        if route and record["route"] != route:
            continue

        technique = record.get("technique", {})
        if not isinstance(technique, dict):
            technique = {}

        technique_id = record["technique_id"]

        technique_name = (
            record.get("technique_name")
            or technique.get("technique_name")
            or "Unknown"
        )

        description = technique.get(
            "description",
            "",
        )

        if ql:
            haystack = " ".join([
                str(technique_id),
                str(technique_name),
                str(description),
            ]).lower()

            if ql not in haystack:
                continue

        prioritization = record.get(
            "prioritization",
            {},
        )

        telemetry = record.get(
            "telemetry",
            {},
        )

        sigma_knowledge = record.get(
            "sigma_knowledge",
            {},
        )

        engine_output = record.get(
            "engine_output",
            {},
        )

        output.append({
            "technique_id": technique_id,

            "technique_name": technique_name,

            "route": record["route"],

            "task_mode": record.get(
                "task_mode"
            ),

            "tactics": technique.get(
                "tactics",
                [],
            ),

            "platforms": technique.get(
                "platforms",
                [],
            ),

            "runtime_hunt_rank": prioritization.get(
                "runtime_hunt_rank"
            ),

            "priority_score": prioritization.get(
                "priority_score"
            ),

            "telemetry_readiness": telemetry.get(
                "readiness_score"
            ),

            "readiness_band": telemetry.get(
                "readiness_band"
            ),

            "knowledge_gap_score": sigma_knowledge.get(
                "knowledge_gap_score"
            ),

            "model": engine_output.get(
                "model"
            ),

            "status": engine_output.get(
                "status"
            ),

            # Useful frontend metadata
            "hypothesis": engine_output.get(
                "hypothesis"
            ),

            "confidence": engine_output.get(
                "confidence"
            ),
        })

    return sorted(
        output,
        key=lambda item: (
            item["runtime_hunt_rank"] is None,
            item["runtime_hunt_rank"] or 999999,
            item["technique_id"],
        ),
    )


def get_hypothesis(
    technique_id: str,
) -> dict[str, Any] | None:

    target = technique_id.lower()

    for record in load_phase3()["records"]:

        if record["technique_id"].lower() == target:
            return record

    return None
