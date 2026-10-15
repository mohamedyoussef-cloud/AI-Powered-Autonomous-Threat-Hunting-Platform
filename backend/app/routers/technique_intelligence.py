from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.services.technique_intelligence import get_technique_intelligence


router = APIRouter(
    prefix="/techniques",
    tags=["technique-intelligence"],
)


@router.get("/{technique_id}/intelligence")
def technique_intelligence(technique_id: str):
    result = get_technique_intelligence(technique_id)

    if result is None:
        raise HTTPException(
            status_code=404,
            detail=f"No intelligence found for technique {technique_id}",
        )

    return result
