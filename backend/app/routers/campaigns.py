from __future__ import annotations
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException

from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.audit import RuleLifecycleAudit
from app.models.campaign import Campaign, CampaignHypothesis, CampaignRule, CampaignFinding
from app.schemas.campaign import CampaignCreate, CampaignOut, CampaignDetail, CampaignRunRequest
from app.services.campaign_engine import create_campaign_plan, generate_campaign_rules, run_campaign, run_campaign_background
from app.services.post_task46_runtime import get_post_task46_runtime_adapter
from app.core.security import require_analyst, require_user

router = APIRouter(prefix="/campaigns", tags=["campaigns"])

@router.get("", response_model=list[CampaignOut])
def list_campaigns(db: Session = Depends(get_db), _=Depends(require_user)):
    return db.query(Campaign).order_by(Campaign.id.desc()).all()

@router.post("", response_model=CampaignOut)
def create_campaign(payload: CampaignCreate, db: Session = Depends(get_db), _=Depends(require_analyst)):
    if payload.mode.lower() not in {"simulation", "pipeline", "live"}:
        raise HTTPException(400, "mode must be simulation, pipeline or live")
    if payload.rule_source not in {"auto", "corpus", "template", "llm_qwen3"}:
        raise HTTPException(400, "rule_source must be auto, corpus, template or llm_qwen3")
    if payload.rule_source == "llm_qwen3":
        from app.services.detection_providers import get as _prov
        _p = _prov("llm_qwen3")
        if not _p.connected:
            raise HTTPException(409, "LLM detection synthesis is not available: " + _p.reason)
    campaign = Campaign(name=payload.name, description=payload.description, target_platform=payload.target_platform.lower(),
                        mode=payload.mode.lower(), rule_source=payload.rule_source)
    db.add(campaign)
    db.commit()
    db.refresh(campaign)
    if payload.technique_ids:
        create_campaign_plan(db, campaign, payload.technique_ids)
        db.commit()
        db.refresh(campaign)
    return campaign

@router.get("/{campaign_id}", response_model=CampaignDetail)
def get_campaign(campaign_id: int, db: Session = Depends(get_db), _=Depends(require_user)):
    c = db.get(Campaign, campaign_id)
    if not c:
        raise HTTPException(404, "Campaign not found")

    runtime_adapter = get_post_task46_runtime_adapter()
    runtime_summary = runtime_adapter.summary()

    campaign_rules = db.query(CampaignRule).filter_by(campaign_id=c.id).all()

    runtime_rules = []
    for rule in campaign_rules:
        if not rule.source_rule_id:
            continue

        artifact = runtime_adapter.get(rule.source_rule_id)
        if not artifact:
            continue

        runtime_rules.append(
            {
                "source": "post_task46_handoff",
                "source_rule_id": rule.source_rule_id,
                "technique_id": artifact.technique_id,
                "technique_name": artifact.technique_name,
                "analytic_id": artifact.analytic_id,
                "path_id": artifact.path_id,
                "plan_id": artifact.plan_id,
                "classification": artifact.classification,
                "keyword_mode": artifact.keyword_mode,
                "runtime_execution_candidate": artifact.runtime_execution_candidate,
                "queue_present": artifact.queue_present,
                "result_present": artifact.result_present,
                "execution_status": artifact.execution_status,
                "match_count": artifact.match_count,
                "disposition": artifact.disposition,
                "zero_result_interpretation": artifact.zero_result_interpretation,
            }
        )

    return CampaignDetail(
        **{k: getattr(c, k) for k in CampaignOut.model_fields},
        hypotheses=[
            {
                "id": h.id,
                "technique_id": h.technique_id,
                "technique_name": h.technique_name,
                "route": h.route,
                "hypothesis_text": h.hypothesis_text,
                "priority_score": h.priority_score,
                "detection_plan_id": h.detection_plan_id,
                "detection_objective": h.detection_objective,
                "observable_behaviors": (
                    [x.strip() for x in h.observable_behaviors.splitlines() if x.strip()]
                    if h.observable_behaviors else []
                ),
                "known_limitations": (
                    [x.strip() for x in h.known_limitations.splitlines() if x.strip()]
                    if h.known_limitations else []
                ),
                "status": h.status,
            }
            for h in db.query(CampaignHypothesis).filter_by(campaign_id=c.id).all()
        ],
        rules=campaign_rules,
        findings=db.query(CampaignFinding).filter_by(campaign_id=c.id).all(),
        runtime_evidence={
            "summary": runtime_summary,
            "rules": runtime_rules,
        },
    )


@router.post("/{campaign_id}/generate-rules")
def generate_rules(campaign_id: int, db: Session = Depends(get_db), _=Depends(require_analyst)):
    """Generate draft detection rules for analyst review without executing a hunt."""
    c = db.get(Campaign, campaign_id)
    if not c:
        raise HTTPException(404, "Campaign not found")

    hypotheses = db.query(CampaignHypothesis).filter_by(campaign_id=c.id).all()
    if not hypotheses:
        raise HTTPException(400, "Campaign has no hypotheses.")

    existing_rules = db.query(CampaignRule).filter_by(campaign_id=c.id).all()
    if existing_rules:
        return {
            "campaign_id": c.id,
            "status": "already_generated",
            "rules": [
                {
                    "id": r.id,
                    "rule_id": r.rule_id,
                    "title": r.title,
                    "status": r.validation_status or "draft",
                }
                for r in existing_rules
            ],
        }

    generate_campaign_rules(db, c)
    db.commit()

    rules = db.query(CampaignRule).filter_by(campaign_id=c.id).all()

    return {
        "campaign_id": c.id,
        "status": "generated",
        "rules": [
            {
                "id": r.id,
                "rule_id": r.rule_id,
                "title": r.title,
                "status": r.validation_status or "draft",
            }
            for r in rules
        ],
    }


@router.post("/{campaign_id}/run", response_model=CampaignOut)
def run(campaign_id: int, payload: CampaignRunRequest, background: bool = False,
        bg: BackgroundTasks = None, db: Session = Depends(get_db), user=Depends(require_analyst)):
    c = db.get(Campaign, campaign_id)
    if not c:
        raise HTTPException(404, "Campaign not found")
    if c.status in ("running", "hunting", "generating_rules"):
        # a crashed worker must not lock a campaign forever
        started = c.started_at
        stale = started is None or (datetime.now(timezone.utc).replace(tzinfo=None) - started.replace(tzinfo=None)).total_seconds() > 900
        if not stale:
            raise HTTPException(409, "Campaign is already running")
    if payload.technique_ids:
        # rebuild only before a run; keeps the API idempotent for repeated planning
        db.query(CampaignHypothesis).filter_by(campaign_id=c.id).delete()
        db.flush()
        create_campaign_plan(db, c, payload.technique_ids)
    elif c.total_hypotheses == 0:
        raise HTTPException(400, "Campaign has no hypotheses. Supply technique_ids first.")
    if background and bg is not None:
        c.status = "running"
        c.started_at = datetime.now(timezone.utc)
        db.commit()
        bg.add_task(run_campaign_background, c.id)
        db.refresh(c)
        return c
    try:
        return run_campaign(db, c)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(409, str(exc))


@router.get("/{campaign_id}/rules/{rule_id}/audit")
def get_rule_lifecycle_audit(
    campaign_id: int,
    rule_id: int,
    db: Session = Depends(get_db),
    _=Depends(require_user),
):
    """Return immutable lifecycle history for a CampaignRule."""

    rule = (
        db.query(CampaignRule)
        .filter(
            CampaignRule.id == rule_id,
            CampaignRule.campaign_id == campaign_id,
        )
        .first()
    )

    if not rule:
        raise HTTPException(404, "Campaign rule not found")

    rows = (
        db.query(RuleLifecycleAudit)
        .filter(
            RuleLifecycleAudit.rule_id == rule.id,
            RuleLifecycleAudit.campaign_id == campaign_id,
        )
        .order_by(RuleLifecycleAudit.changed_at.asc(), RuleLifecycleAudit.id.asc())
        .all()
    )

    return {
        "campaign_id": campaign_id,
        "rule_id": rule.id,
        "rule_key": rule.rule_id,
        "current_status": rule.validation_status or "draft",
        "count": len(rows),
        "history": [
            {
                "id": row.id,
                "previous_status": row.previous_status,
                "new_status": row.new_status,
                "changed_by": row.changed_by,
                "source": row.source,
                "reason": row.reason,
                "changed_at": row.changed_at.isoformat()
                if row.changed_at
                else None,
            }
            for row in rows
        ],
    }

@router.post("/{campaign_id}/rules/{rule_id}/lifecycle")
def update_rule_lifecycle(
    campaign_id: int,
    rule_id: int,
    payload: dict,
    db: Session = Depends(get_db),
    user=Depends(require_analyst),
):
    """
    Controlled CampaignRule lifecycle transition.

    Allowed lifecycle:
      draft -> validated -> approved -> active -> retired

    This endpoint intentionally does not auto-promote rules.
    """

    allowed = {
        "draft": {"validated"},
        "validated": {"approved"},
        "approved": {"active"},
        "active": {"retired"},
        "retired": set(),
    }

    requested = str(
        payload.get("new_status", payload.get("status", ""))
    ).strip().lower()
    actor = user["email"]  # identity comes from the token, never from the request body
    reason = str(payload.get("reason", "")).strip()

    if requested not in allowed:
        raise HTTPException(
            400,
            "Invalid lifecycle status. Allowed: draft, validated, approved, active, retired",
        )

    rule = (
        db.query(CampaignRule)
        .filter(
            CampaignRule.id == rule_id,
            CampaignRule.campaign_id == campaign_id,
        )
        .first()
    )

    if not rule:
        raise HTTPException(404, "Campaign rule not found")

    current = (rule.validation_status or "draft").lower()

    if requested == current:
        raise HTTPException(409, f"Rule is already '{current}'")

    if requested not in allowed.get(current, set()):
        raise HTTPException(
            409,
            f"Invalid lifecycle transition: {current} -> {requested}",
        )

    # A reason is required for terminal / consequential transitions.
    if requested in {"approved", "active", "retired"} and not reason:
        raise HTTPException(
            400,
            f"A reason is required when transitioning a rule to '{requested}'",
        )

    now = datetime.now(timezone.utc).isoformat()

    rule.validation_status = requested
    rule.lifecycle_updated_at = now
    rule.lifecycle_updated_by = actor
    rule.lifecycle_reason = reason or None

    # Keep the legacy status field meaningful for existing frontend/API users.
    if requested == "draft":
        rule.status = "generated"
    elif requested == "validated":
        rule.status = "validated"
    elif requested == "approved":
        rule.status = "approved"
    elif requested == "active":
        rule.status = "active"
    elif requested == "retired":
        rule.status = "retired"

    # Persist an immutable audit event for every lifecycle transition.
    db.add(
        RuleLifecycleAudit(
            campaign_id=rule.campaign_id,
            rule_id=rule.id,
            previous_status=current,
            new_status=requested,
            changed_by=actor,
            source="analyst",
            reason=reason or "",
        )
    )

    db.commit()
    db.refresh(rule)

    return {
        "id": rule.id,
        "campaign_id": rule.campaign_id,
        "rule_id": rule.rule_id,
        "title": rule.title,
        "previous_status": current,
        "status": rule.validation_status,
        "updated_by": rule.lifecycle_updated_by,
        "updated_at": rule.lifecycle_updated_at,
        "reason": rule.lifecycle_reason,
    }


@router.get("/{campaign_id}/rules/{rule_id}/lifecycle")
def get_rule_lifecycle(
    campaign_id: int,
    rule_id: int,
    db: Session = Depends(get_db),
):
    rule = (
        db.query(CampaignRule)
        .filter(
            CampaignRule.id == rule_id,
            CampaignRule.campaign_id == campaign_id,
        )
        .first()
    )

    if not rule:
        raise HTTPException(404, "Campaign rule not found")

    return {
        "id": rule.id,
        "campaign_id": rule.campaign_id,
        "rule_id": rule.rule_id,
        "title": rule.title,
        "status": rule.validation_status or "draft",
        "updated_by": rule.lifecycle_updated_by,
        "updated_at": rule.lifecycle_updated_at,
        "reason": rule.lifecycle_reason,
        "allowed_next_statuses": {
            "draft": ["validated"],
            "validated": ["approved"],
            "approved": ["active"],
            "active": ["retired"],
            "retired": [],
        }.get(rule.validation_status or "draft", []),
    }


@router.delete("/{campaign_id}")
def delete_campaign(campaign_id: int, db: Session = Depends(get_db), _=Depends(require_analyst)):
    c = db.get(Campaign, campaign_id)
    if not c:
        raise HTTPException(404, "Campaign not found")
    db.delete(c)
    db.commit()
    return {"deleted": True, "campaign_id": campaign_id}
