from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from app.services.phase3_hypothesis import get_hypothesis, list_hypotheses, load_phase3

router = APIRouter(prefix="/hypotheses", tags=["hypothesis-engine"])


@router.get("/summary")
def summary():
    bundle = load_phase3()
    return {
        "total": len(bundle["records"]),
        "route_counts": bundle["route_counts"],
        "model": bundle["model"],
        "source": "team_phase3",
    }


@router.get("")
def hypotheses(
    q: str | None = Query(default=None),
    route: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
):
    rows = list_hypotheses(q=q, route=route)
    total = len(rows)
    start = (page - 1) * page_size
    return {"items": rows[start:start + page_size], "total": total, "page": page, "page_size": page_size}


@router.get("/{technique_id}")
def hypothesis_detail(technique_id: str):
    row = get_hypothesis(technique_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"Technique {technique_id} not found")
    return row
