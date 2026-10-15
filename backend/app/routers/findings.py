"""
routers/findings.py
----------------------
Powers the Hunt Findings / Investigation screen.
"""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.models.finding import HuntFinding
from app.models.execution import AnalystVerdict
from app.core.security import require_analyst, require_user
from app.schemas.api_schemas import PaginatedFindings, FindingListItem, FindingDetail

router = APIRouter(prefix="/findings", tags=["findings"])
settings = get_settings()


def _split(value: str) -> list[str]:
    return [v for v in (value or "").split(",") if v]


def _json_list(value: str) -> list:
    """event_references / processes are stored as JSON by the hunt engine but
    as comma lists by older loaders; accept both instead of corrupting JSON."""
    if not value:
        return []
    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, list) else [parsed]
    except json.JSONDecodeError:
        return _split(value)


VERDICTS = {"true_positive": "confirmed", "false_positive": "dismissed",
            "benign_expected": "dismissed", "needs_review": "unverified"}


@router.get("", response_model=PaginatedFindings)
def list_findings(
    label: str | None = None,
    verification_status: str | None = None,
    source_dataset: str | None = None,
    technique_id: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(settings.DEFAULT_PAGE_SIZE, ge=1, le=settings.MAX_PAGE_SIZE),
    db: Session = Depends(get_db),
    _=Depends(require_user),
):
    q = db.query(HuntFinding)
    if label:
        q = q.filter(HuntFinding.label == label)
    if verification_status:
        q = q.filter(HuntFinding.verification_status == verification_status)
    if source_dataset:
        q = q.filter(HuntFinding.source_dataset == source_dataset)
    if technique_id:
        q = q.filter(HuntFinding.attack_technique_ids.contains(technique_id))

    total = q.count()
    rows = q.order_by(HuntFinding.id.desc()).offset((page - 1) * page_size).limit(page_size).all()

    items = [
        FindingListItem(
            finding_id=r.finding_id, case_id=r.case_id, rule_id=r.rule_id,
            rule_title=r.rule_title, label=r.label, verification_status=r.verification_status,
            risk_score=r.risk_score, source_dataset=r.source_dataset, time_start=r.time_start,
            attack_technique_ids=_split(r.attack_technique_ids),
        )
        for r in rows
    ]

    return PaginatedFindings(total=total, page=page, page_size=page_size, items=items)


def _load(s):
    try:
        return json.loads(s) if s else {}
    except json.JSONDecodeError:
        return {}


@router.post("/{finding_id}/verdict")
def set_verdict(finding_id: str, payload: dict, db: Session = Depends(get_db), user=Depends(require_analyst)):
    """Analyst decision. Stored as an immutable row AND as an ML-ready labelled
    example (feature snapshot + model score at decision time)."""
    verdict = str(payload.get("verdict", "")).strip().lower()
    if verdict not in VERDICTS:
        raise HTTPException(400, f"verdict must be one of {sorted(VERDICTS)}")
    f = db.query(HuntFinding).filter(HuntFinding.finding_id == finding_id).first()
    if not f:
        raise HTTPException(404, "Finding not found")
    tri = _load(f.triage_json)
    db.add(AnalystVerdict(finding_id=finding_id, verdict=verdict, analyst=user["email"],
                          note=str(payload.get("note", ""))[:2000],
                          features_json=json.dumps(tri.get("features", {})), model_score=f.risk_score))
    f.analyst_verdict, f.verification_status = verdict, VERDICTS[verdict]
    db.commit()
    return {"finding_id": finding_id, "verdict": verdict, "verification_status": f.verification_status}


@router.get("/feedback/export")
def export_feedback(db: Session = Depends(get_db), _=Depends(require_analyst)):
    """Labelled training rows (JSONL) for the ML triage retraining pipeline."""
    rows = db.query(AnalystVerdict).filter(AnalystVerdict.verdict.in_(["true_positive", "false_positive", "benign_expected"])).all()
    lines = [json.dumps({"finding_id": r.finding_id, "label": 1 if r.verdict == "true_positive" else 0,
                         "features": json.loads(r.features_json or "{}"), "model_score": r.model_score,
                         "analyst": r.analyst, "at": r.created_at.isoformat()}) for r in rows]
    return PlainTextResponse("\n".join(lines), media_type="application/x-ndjson")


@router.get("/stats/summary")
def findings_summary(db: Session = Depends(get_db), _=Depends(require_user)):
    from sqlalchemy import func
    by_label = dict(db.query(HuntFinding.label, func.count(HuntFinding.id)).group_by(HuntFinding.label).all())
    by_verification = dict(
        db.query(HuntFinding.verification_status, func.count(HuntFinding.id))
        .group_by(HuntFinding.verification_status).all()
    )
    return {"by_label": by_label, "by_verification_status": by_verification}


@router.get("/{finding_id}", response_model=FindingDetail)
def get_finding(finding_id: str, db: Session = Depends(get_db), _=Depends(require_user)):
    r = db.query(HuntFinding).filter(HuntFinding.finding_id == finding_id).first()
    if not r:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found")
    return FindingDetail(
        finding_id=r.finding_id, case_id=r.case_id, rule_id=r.rule_id,
        rule_title=r.rule_title, label=r.label, verification_status=r.verification_status,
        risk_score=r.risk_score, source_dataset=r.source_dataset, time_start=r.time_start,
        time_end=r.time_end, compiled_query=r.compiled_query, narrative=r.narrative,
        threat_probability=r.threat_probability,
        attack_technique_ids=_split(r.attack_technique_ids),
        event_references=_json_list(r.event_references),
        hosts=_split(r.hosts), users=_split(r.users),
        processes=_json_list(r.processes), ips=_split(r.ips),
        triage=_load(r.triage_json), analyst_verdict=r.analyst_verdict,
        verdicts=[{"verdict": v.verdict, "analyst": v.analyst, "note": v.note, "at": v.created_at.isoformat()}
                  for v in db.query(AnalystVerdict).filter_by(finding_id=r.finding_id).order_by(AnalystVerdict.id.desc()).all()],
    )
