from __future__ import annotations

import json
from pathlib import Path
from typing import Any


import os

DETECTION_PLAN_FILE = Path(os.environ.get("DETECTION_PLAN_FILE") or (Path(__file__).resolve().parents[3] / "artifacts" / "detection-plans" / "detection_plan_llm_semantic_outputs_v1.jsonl"))

_summary_cache: dict[str, Any] | None = None
_records_cache: list[dict[str, Any]] = []
_cached_mtime: float | None = None


def _load() -> list[dict[str, Any]]:
    global _records_cache, _cached_mtime

    if not DETECTION_PLAN_FILE.exists():
        return []

    mtime = DETECTION_PLAN_FILE.stat().st_mtime

    if _cached_mtime == mtime and _records_cache:
        return _records_cache

    records: list[dict[str, Any]] = []

    with DETECTION_PLAN_FILE.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue

            plan_identity = row.get("plan_identity") or {}
            hypothesis = row.get("hypothesis") or {}
            resolution = row.get("deterministic_resolution") or {}
            eligibility = row.get("eligibility") or {}
            attack_context = row.get("attack_context") or {}

            records.append(
                {
                    "plan_id": plan_identity.get("plan_id"),
                    "plan_input_fingerprint": plan_identity.get(
                        "plan_input_fingerprint"
                    ),
                    "technique_id": row.get("technique_id"),
                    "technique_name": row.get("technique_name"),
                    "environment_id": row.get("environment_id"),
                    "runtime_hunt_rank": row.get("runtime_hunt_rank"),

                    "detection_intent": {
                        "objective": hypothesis.get("text"),
                        "observable_behaviors": hypothesis.get(
                            "investigation_focus", []
                        ),
                    },

                    "known_limitations": hypothesis.get(
                        "known_collection_limitations", []
                    ),

                    "hypothesis": {
                        "text": hypothesis.get("text"),
                        "confidence": hypothesis.get("confidence"),
                        "investigation_focus": hypothesis.get(
                            "investigation_focus", []
                        ),
                        "known_collection_limitations": hypothesis.get(
                            "known_collection_limitations", []
                        ),
                    },

                    "deterministic_resolution": {
                        "plan_status": resolution.get("plan_status"),
                        "downstream_action": resolution.get(
                            "downstream_action"
                        ),
                        "reason_codes": resolution.get(
                            "reason_codes", []
                        ),
                        "grounded_paths": resolution.get(
                            "grounded_paths", []
                        ),
                        "unresolved_paths": resolution.get(
                            "unresolved_paths", []
                        ),
                        "required_components": resolution.get(
                            "required_components", []
                        ),
                    },

                    "eligibility": eligibility,
                    "attack_context": {
                        "analytic_ids": attack_context.get(
                            "analytic_ids", []
                        ),
                        "data_components": attack_context.get(
                            "data_components", []
                        ),
                        "detection_strategy_ids": attack_context.get(
                            "detection_strategy_ids", []
                        ),
                        "platforms": attack_context.get("platforms", []),
                        "current_environment_platforms": attack_context.get(
                            "current_environment_platforms", []
                        ),
                    },

                    "source": "post_task46_handoff",
                    "dispatch_version": row.get("dispatch_version"),
                    "generated_at_utc": row.get("generated_at_utc"),
                }
            )

    _records_cache = records
    _cached_mtime = mtime

    return records

def list_detection_plans(
    q: str | None = None,
    technique_id: str | None = None,
) -> list[dict[str, Any]]:
    rows = _load()

    if q:
        needle = q.strip().lower()
        rows = [
            row
            for row in rows
            if needle in str(row.get("plan_id", "")).lower()
            or needle in str(row.get("technique_id", "")).lower()
            or needle in str(
                row.get("detection_intent", {}).get("objective", "")
            ).lower()
            or any(
                needle in str(item).lower()
                for item in row.get("detection_intent", {}).get(
                    "observable_behaviors", []
                )
            )
        ]

    if technique_id:
        rows = [
            row
            for row in rows
            if row.get("technique_id") == technique_id
        ]

    return rows


def get_detection_plan(technique_id: str) -> dict[str, Any] | None:
    rows = list_detection_plans(technique_id=technique_id)
    return rows[0] if rows else None


def detection_plan_summary() -> dict[str, Any]:
    rows = _load()

    dispatch_versions: dict[str, int] = {}

    for row in rows:
        version = row.get("dispatch_version") or "unknown"
        dispatch_versions[version] = dispatch_versions.get(version, 0) + 1

    return {
        "total": len(rows),
        "source": "post_task46_handoff",
        "file": str(DETECTION_PLAN_FILE),
        "dispatch_versions": dispatch_versions,
        "schema_valid_records": len(rows),
        "processing_errors": 0,
    }
