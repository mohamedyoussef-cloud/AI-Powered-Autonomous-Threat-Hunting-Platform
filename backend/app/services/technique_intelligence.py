from __future__ import annotations

from typing import Any

from app.services.detection_plans import get_detection_plan
from app.services.phase3_hypothesis import get_hypothesis


def get_technique_intelligence(technique_id: str) -> dict[str, Any] | None:
    hypothesis = get_hypothesis(technique_id)
    detection_plan = get_detection_plan(technique_id)

    if hypothesis is None and detection_plan is None:
        return None

    return {
        "technique_id": technique_id,
        "hypothesis": hypothesis,
        "detection_plan": detection_plan,
        "linkage": {
            "hypothesis_available": hypothesis is not None,
            "detection_plan_available": detection_plan is not None,
            "linked_by": "technique_id",
        },
    }
