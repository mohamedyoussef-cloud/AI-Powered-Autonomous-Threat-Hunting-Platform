from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from app.services.detection_plans import (
    detection_plan_summary,
    get_detection_plan,
    list_detection_plans,
)


router = APIRouter(
    prefix="/detection-plans",
    tags=["detection-plans"],
)


@router.get("/summary")
def summary():
    return detection_plan_summary()


@router.get("")
def detection_plans(
    q: str | None = Query(default=None),
    technique_id: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
):
    rows = list_detection_plans(
        q=q,
        technique_id=technique_id,
    )

    total = len(rows)
    start = (page - 1) * page_size

    return {
        "items": rows[start:start + page_size],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/{technique_id}")
def detection_plan_detail(technique_id: str):
    row = get_detection_plan(technique_id)

    if row is None:
        raise HTTPException(
            status_code=404,
            detail=f"Detection Plan for technique {technique_id} not found",
        )

    return row
