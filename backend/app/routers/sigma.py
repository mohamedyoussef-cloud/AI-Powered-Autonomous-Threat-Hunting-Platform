"""
routers/sigma.py
-------------------
Powers the Sigma Rules Browser: searchable, filterable, paginated list
plus a detail view with the full raw YAML and compiled query.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.models.sigma import SigmaRule, SigmaRuleTechnique
from app.models.attack import AttackTechnique
from app.schemas.api_schemas import PaginatedSigmaRules, SigmaRuleListItem, SigmaRuleDetail

router = APIRouter(prefix="/sigma", tags=["sigma"])
settings = get_settings()


def _technique_ids_for(db: Session, rule_pk: int) -> list[str]:
    rows = (
        db.query(AttackTechnique.attack_id)
        .join(SigmaRuleTechnique, SigmaRuleTechnique.attack_technique_id == AttackTechnique.id)
        .filter(SigmaRuleTechnique.sigma_rule_id == rule_pk)
        .all()
    )
    return [r[0] for r in rows]


@router.get("/rules", response_model=PaginatedSigmaRules)
def list_rules(
    search: str | None = Query(None, description="Matches title or description"),
    quarantine_category: str | None = None,
    level: str | None = None,
    logsource_category: str | None = None,
    technique_id: str | None = None,
    training_ready_only: bool = False,
    page: int = Query(1, ge=1),
    page_size: int = Query(settings.DEFAULT_PAGE_SIZE, ge=1, le=settings.MAX_PAGE_SIZE),
    db: Session = Depends(get_db),
):
    q = db.query(SigmaRule)

    if search:
        like = f"%{search}%"
        q = q.filter(or_(SigmaRule.title.ilike(like), SigmaRule.description.ilike(like)))
    if quarantine_category:
        q = q.filter(SigmaRule.quarantine_category == quarantine_category)
    if level:
        q = q.filter(SigmaRule.level == level)
    if logsource_category:
        q = q.filter(SigmaRule.logsource_category == logsource_category)
    if training_ready_only:
        q = q.filter(SigmaRule.is_training_ready == True)  # noqa: E712
    if technique_id:
        q = (
            q.join(SigmaRuleTechnique, SigmaRuleTechnique.sigma_rule_id == SigmaRule.id)
            .join(AttackTechnique, AttackTechnique.id == SigmaRuleTechnique.attack_technique_id)
            .filter(AttackTechnique.attack_id == technique_id)
        )

    total = q.count()
    rules = q.order_by(SigmaRule.title).offset((page - 1) * page_size).limit(page_size).all()

    items = []
    for r in rules:
        item = SigmaRuleListItem.model_validate(r)
        item.technique_ids = _technique_ids_for(db, r.id)
        items.append(item)

    return PaginatedSigmaRules(total=total, page=page, page_size=page_size, items=items)


@router.get("/rules/{rule_id}", response_model=SigmaRuleDetail)
def get_rule(rule_id: str, db: Session = Depends(get_db)):
    r = db.query(SigmaRule).filter(SigmaRule.rule_id == rule_id).first()
    if not r:
        raise HTTPException(status_code=404, detail=f"Sigma rule '{rule_id}' not found")
    detail = SigmaRuleDetail.model_validate(r)
    detail.technique_ids = _technique_ids_for(db, r.id)
    return detail


@router.get("/facets")
def get_facets(db: Session = Depends(get_db)):
    """Distinct filter-dropdown values, so the frontend never has to
    hardcode what quarantine categories / levels / logsource categories
    exist — it asks the API."""
    return {
        "quarantine_categories": [r[0] for r in db.query(SigmaRule.quarantine_category).distinct().all()],
        "levels": [r[0] for r in db.query(SigmaRule.level).distinct().all()],
        "logsource_categories": [
            r[0] for r in db.query(SigmaRule.logsource_category).distinct().all() if r[0]
        ],
    }
