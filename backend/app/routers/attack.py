"""
routers/attack.py
--------------------
Powers the ATT&CK Coverage Matrix screen: which techniques exist, which
tactics they belong to, and how many accepted-core Sigma rules cover
each one — computed as a real SQL aggregation, not recomputed from JSON
on every request.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.attack import AttackTechnique
from app.models.sigma import SigmaRule, SigmaRuleTechnique
from app.schemas.api_schemas import TechniqueOut, CoverageMatrixOut, CoverageCell

router = APIRouter(prefix="/attack", tags=["attack"])


@router.get("/techniques", response_model=list[TechniqueOut])
def list_techniques(
    include_deprecated: bool = False,
    db: Session = Depends(get_db),
):
    rule_counts = dict(
        db.query(SigmaRuleTechnique.attack_technique_id, func.count(SigmaRuleTechnique.id))
        .join(SigmaRule, SigmaRule.id == SigmaRuleTechnique.sigma_rule_id)
        .filter(SigmaRule.quarantine_category == "accepted_core")
        .group_by(SigmaRuleTechnique.attack_technique_id)
        .all()
    )

    q = db.query(AttackTechnique)
    if not include_deprecated:
        q = q.filter(AttackTechnique.is_deprecated == False, AttackTechnique.is_revoked == False)  # noqa: E712

    out = []
    for t in q.order_by(AttackTechnique.attack_id).all():
        out.append(TechniqueOut(
            attack_id=t.attack_id, name=t.name,
            tactics=t.tactics_list, platforms=t.platforms_list,
            is_deprecated=t.is_deprecated, is_revoked=t.is_revoked,
            is_sub_technique=t.is_sub_technique, parent_attack_id=t.parent_attack_id,
            rule_count=rule_counts.get(t.id, 0),
        ))
    return out


@router.get("/coverage", response_model=CoverageMatrixOut)
def coverage_matrix(db: Session = Depends(get_db)):
    """One row per (technique, tactic) pair — a technique with 2 tactics
    appears twice, once per tactic column, which is exactly how the
    Navigator-style matrix wants it laid out."""
    rule_counts = dict(
        db.query(SigmaRuleTechnique.attack_technique_id, func.count(SigmaRuleTechnique.id))
        .join(SigmaRule, SigmaRule.id == SigmaRuleTechnique.sigma_rule_id)
        .filter(SigmaRule.quarantine_category == "accepted_core")
        .group_by(SigmaRuleTechnique.attack_technique_id)
        .all()
    )

    techniques = (
        db.query(AttackTechnique)
        .filter(AttackTechnique.is_deprecated == False, AttackTechnique.is_revoked == False)  # noqa: E712
        .all()
    )

    cells: list[CoverageCell] = []
    tactics_seen: set[str] = set()
    covered_technique_ids: set[str] = set()

    for t in techniques:
        count = rule_counts.get(t.id, 0)
        if count > 0:
            covered_technique_ids.add(t.attack_id)
        for tactic in (t.tactics_list or ["(none)"]):
            tactics_seen.add(tactic)
            cells.append(CoverageCell(
                attack_id=t.attack_id, name=t.name, tactic=tactic,
                rule_count=count, is_sub_technique=t.is_sub_technique,
            ))

    total = len(techniques)
    covered = len(covered_technique_ids)
    return CoverageMatrixOut(
        tactics=sorted(tactics_seen),
        cells=cells,
        total_active_techniques=total,
        total_covered=covered,
        coverage_pct=round(100 * covered / total, 2) if total else 0.0,
    )
