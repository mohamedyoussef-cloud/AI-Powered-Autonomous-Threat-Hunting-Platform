from __future__ import annotations
import hashlib
import json
import logging
import time
import uuid
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.models.campaign import Campaign, CampaignHypothesis, CampaignRule, CampaignFinding
from app.models.finding import HuntFinding
from app.services.phase3_hypothesis import get_hypothesis
from app.services.detection_plans import get_detection_plan
from app.services.rule_generator import generate_rule_draft
from app.services import telemetry, connectors
from app.services.rule_retrieval import find_candidates
from app.services.sigma_engine import validate_rule, parse_rule, compile_native
from app.services.triage import score_finding, apply_ml
from app.services.ml_triage import ml_triage_for_match
from app.services.post_task46_runtime import get_post_task46_runtime_adapter
from app.models.audit import RuleLifecycleAudit
from app.models.execution import HuntExecution, CampaignEvent


def _hypothesis_text(record: dict) -> str:
    output = record.get("engine_output", {}).get("model_output", {})
    return output.get("hypothesis") or f"Investigate {record.get('technique_id')} - {record.get('technique', {}).get('technique_name', '')}"


def create_campaign_plan(db: Session, campaign: Campaign, technique_ids: list[str]) -> Campaign:
    campaign.status = "planning"
    for tid in technique_ids:
        record = get_hypothesis(tid)
        if not record:
            # Phase-3 engine output unavailable for this technique: fall back to the
            # ATT&CK table so the campaign is never silently empty. Marked clearly.
            from app.models.attack import AttackTechnique
            t = db.query(AttackTechnique).filter(AttackTechnique.attack_id == tid).first()
            if not t:
                emit(db, campaign.id, "hypotheses", f"{tid}: unknown ATT&CK technique, skipped", level="warn")
                continue
            db.add(CampaignHypothesis(
                campaign_id=campaign.id, technique_id=tid, technique_name=t.name, route="attack_fallback",
                hypothesis_text=f"Investigate {tid} - {t.name} on {campaign.target_platform} telemetry "
                                f"(ATT&CK-derived; Hypothesis Engine output not available for this technique).",
            ))
            emit(db, campaign.id, "hypotheses", f"{tid}: Phase-3 hypothesis not found; using ATT&CK-derived fallback", level="warn")
            continue

        detection_plan = get_detection_plan(tid)

        p = record.get("prioritization", {})
        detection_intent = {}
        observable_behaviors = []
        known_limitations = []

        if detection_plan:
            detection_intent = detection_plan.get("detection_intent", {}) or {}
            observable_behaviors = detection_intent.get("observable_behaviors", []) or []
            known_limitations = detection_plan.get("known_limitations", []) or []

        db.add(CampaignHypothesis(
            campaign_id=campaign.id,
            technique_id=record["technique_id"],
            technique_name=record.get("technique", {}).get("technique_name", ""),
            route=record.get("route", ""),
            hypothesis_text=_hypothesis_text(record),
            priority_score=p.get("priority_score"),
            detection_plan_id=(
                detection_plan.get("plan_id")
                if detection_plan
                else None
            ),
            detection_objective=detection_intent.get("objective"),
            observable_behaviors="\n".join(observable_behaviors),
            known_limitations="\n".join(known_limitations),
        ))
    db.flush()
    campaign.total_hypotheses = db.query(CampaignHypothesis).filter_by(campaign_id=campaign.id).count()
    return campaign



log = logging.getLogger("campaign_engine")
RULES_PER_HYPOTHESIS = int(__import__("os").environ.get("RULES_PER_HYPOTHESIS", "5"))


# --------------------------------------------------------------------------
# Timeline helper -- every stage writes here; the UI's live workflow reads it
# --------------------------------------------------------------------------
def emit(db: Session, campaign_id: int, stage: str, message: str, level: str = "info", **detail) -> None:
    db.add(CampaignEvent(campaign_id=campaign_id, stage=stage, level=level, message=message,
                         detail_json=json.dumps(detail, default=str)))
    db.flush()


def _audit(db: Session, rule: CampaignRule, prev: str, new: str, reason: str, actor: str = "campaign-engine") -> None:
    db.add(RuleLifecycleAudit(campaign_id=rule.campaign_id, rule_id=rule.id, previous_status=prev,
                              new_status=new, changed_by=actor, source="engine", reason=reason))


# --------------------------------------------------------------------------
# Detection stage: corpus-grounded rule selection, template only as fallback
# --------------------------------------------------------------------------
def _llm_rule_for_hypothesis(db: Session, campaign: Campaign, h: CampaignHypothesis) -> bool:
    """Ask the Qwen provider for a rule. Returns True when an EXECUTABLE rule was stored.
    A rule that fails the gate is still stored (as blocked) so the analyst can see what the model produced."""
    from app.services import detection_providers as dp
    prov = dp.get("llm_qwen3")
    observable = [x.strip() for x in (h.observable_behaviors or "").splitlines() if x.strip()]
    limits = [x.strip() for x in (h.known_limitations or "").splitlines() if x.strip()]
    try:
        out = prov.generate(db, h.hypothesis_text, h.technique_id, campaign.target_platform,
                            objective=h.detection_objective, behaviors=observable, limits=limits)
    except dp.ProviderUnavailable as exc:
        emit(db, campaign.id, "detection", f"{h.technique_id}: LLM unavailable ({exc})", level="warn", technique=h.technique_id)
        return False
    g = out[0]
    v = validate_rule(g.yaml_text, None, h.technique_id)
    parsed, _ = parse_rule(g.yaml_text)
    title = (parsed.title if parsed and getattr(parsed, "title", None) else h.technique_name or h.technique_id)[:250]
    db.add(CampaignRule(
        campaign_id=campaign.id, hypothesis_id=h.id, rule_id=f"campaign-{campaign.id}-{uuid.uuid4()}-llm",
        title=title, generated_yaml=g.yaml_text, generation_method="llm_qwen3", source_kind="llm",
        validation_status="draft", status="generated", executable=bool(v["executable"]),
    ))
    if v["executable"]:
        emit(db, campaign.id, "detection", f"{h.technique_id}: LLM rule '{title}' generated; passes validation gate",
             technique=h.technique_id, source_rule=None)
    else:
        emit(db, campaign.id, "detection",
             f"{h.technique_id}: LLM rule '{title}' BLOCKED by validation gate: "
             + "; ".join(i.message for i in v["issues"] if i.severity == "error"),
             level="warn", technique=h.technique_id)
    return bool(v["executable"])


def generate_campaign_rules(db: Session, campaign: Campaign) -> None:
    campaign.status = "generating_rules"
    hypotheses = db.query(CampaignHypothesis).filter_by(campaign_id=campaign.id).all()
    for h in hypotheses:
        source = campaign.rule_source or "auto"
        if source == "llm_qwen3":
            if _llm_rule_for_hypothesis(db, campaign, h):
                continue
            emit(db, campaign.id, "detection",
                 f"{h.technique_id}: no usable LLM rule; falling back to corpus retrieval (labelled as corpus)",
                 level="warn", technique=h.technique_id)
            source = "auto"
        cands = [] if source == "template" else find_candidates(db, h.technique_id, campaign.target_platform)
        rule_id = f"campaign-{campaign.id}-{uuid.uuid4()}"
        if cands:
            top = cands[:RULES_PER_HYPOTHESIS]
            for i, best in enumerate(top):
                db.add(CampaignRule(
                    campaign_id=campaign.id, hypothesis_id=h.id, rule_id=f"{rule_id}-{i}",
                    title=best.rule.title[:250], generated_yaml=best.yaml_text,
                    generation_method="corpus_retrieval_v1", source_rule_id=best.corpus_rule_id,
                    source_kind="corpus", validation_status="draft", status="generated", executable=True,
                ))
                emit(db, campaign.id, "detection",
                     f"{h.technique_id}: rule {i + 1}/{len(top)} '{best.rule.title}' (score {best.score:.0f}; {best.reason})",
                     technique=h.technique_id, source_rule=best.corpus_rule_id)
            continue
        if source == "corpus":
            emit(db, campaign.id, "detection",
                 f"{h.technique_id}: no suitable corpus rule and rule source is 'corpus' only; no template fallback used",
                 level="warn", technique=h.technique_id)
            continue
        observable = [x.strip() for x in (h.observable_behaviors or "").splitlines() if x.strip()]
        limits = [x.strip() for x in (h.known_limitations or "").splitlines() if x.strip()]
        draft = generate_rule_draft(h.hypothesis_text, h.technique_id, campaign.target_platform,
                                    detection_objective=h.detection_objective,
                                    observable_behaviors=observable, known_limitations=limits)
        v = validate_rule(draft.yaml_text, None, h.technique_id)
        db.add(CampaignRule(
            campaign_id=campaign.id, hypothesis_id=h.id, rule_id=rule_id,
            title=h.technique_name or h.technique_id, generated_yaml=draft.yaml_text,
            generation_method="template_v0", source_kind="template", validation_status="draft",
            status="generated", executable=bool(v["executable"]),
        ))
        emit(db, campaign.id, "detection",
             f"{h.technique_id}: no corpus rule found; template draft "
             f"{'created' if v['executable'] else 'created but NOT executable (placeholder indicator) - needs analyst authoring'}",
             level="info" if v["executable"] else "warn", technique=h.technique_id)
    db.flush()
    campaign.total_rules = db.query(CampaignRule).filter_by(campaign_id=campaign.id).count()


# --------------------------------------------------------------------------
# Translate stage: validation gate + native query, lifecycle with audit trail
# --------------------------------------------------------------------------
def _gate_rules(db: Session, campaign: Campaign, rules: list[CampaignRule]) -> list[CampaignRule]:
    ready: list[CampaignRule] = []
    now = datetime.now(timezone.utc).isoformat()
    for rule in rules:
        hyp = db.get(CampaignHypothesis, rule.hypothesis_id) if rule.hypothesis_id else None
        parsed_pre, _ = parse_rule(rule.generated_yaml)
        cat = parsed_pre.logsource.get("category") if parsed_pre else None
        svc = parsed_pre.logsource.get("service") if parsed_pre else None
        avail = telemetry.available_fields(db, cat, svc) if telemetry.event_count(db) else None
        v = validate_rule(rule.generated_yaml, avail, hyp.technique_id if hyp else None)
        rule.validation_json = json.dumps({
            "ok": v["ok"], "issues": [i.dict() for i in v["issues"]], "missing_fields": v["missing_fields"],
            "techniques": v["techniques"],
        })
        rule.executable = bool(v["executable"])
        current = (rule.validation_status or "draft").lower()
        if not v["executable"]:
            emit(db, campaign.id, "translate", f"Rule '{rule.title}' blocked by validation gate: "
                 + "; ".join(i.message for i in v["issues"] if i.severity == "error"), level="warn", rule=rule.id)
            continue
        if current == "retired":
            continue
        chain = ["draft", "validated", "approved", "active"]
        if current in chain:
            for nxt in chain[chain.index(current) + 1:]:
                _audit(db, rule, current, nxt, f"Automatically promoted to '{nxt}' by campaign engine after passing validation gate")
                current = nxt
            rule.validation_status = rule.status = "active"
            rule.lifecycle_updated_at, rule.lifecycle_updated_by = now, "campaign-engine"
            rule.lifecycle_reason = "Passed validation gate; activated for campaign execution."
        ready.append(rule)
    db.flush()
    return ready


def _finding_from_match(db: Session, campaign: Campaign, rule: CampaignRule, parsed, hyp, match: dict,
                        query: str, connector: str) -> tuple[HuntFinding, bool]:
    fields, meta = match["fields"], match["meta"]
    technique = (hyp.technique_id if hyp else None) or (parsed.technique_ids[0] if parsed.technique_ids else "")
    digest = hashlib.sha256(f"{campaign.id}|{rule.id}|{connector}|{meta.get('dedupe_key')}".encode()).hexdigest()[:20]
    finding_id = f"F-{digest}"
    existing = db.query(HuntFinding).filter(HuntFinding.finding_id == finding_id).first()
    if existing:
        return existing, False
    triage = score_finding(db, fields, parsed.level, len(parsed.technique_ids), rule.source_rule_id or rule.rule_id)
    triage = apply_ml(triage, ml_triage_for_match(fields, meta, list(getattr(parsed, "tags", []) or []), list(parsed.technique_ids)))
    host = meta.get("host") or str(fields.get("Computer", ""))
    image, cmd = str(fields.get("Image", "")), str(fields.get("CommandLine", ""))
    case_digest = hashlib.sha256(f"{campaign.id}|{host}|{technique}".encode()).hexdigest()[:12]
    parts = [f"Sigma rule '{rule.title}' matched on {host or 'unknown host'}"]
    if image:
        parts.append(f"process {image}")
    if cmd:
        parts.append(f"command line: {cmd[:220]}")
    if triage.get("triage_source") == "ml_model":
        parts.append(f"ML triage ({triage['model']}): {triage['predicted_class'].replace('_', ' ').lower()}, "
                     f"P(true positive) {triage['threat_probability']}; route {triage['route'].replace('_', ' ')}; "
                     "analyst-assisted, not a verdict.")
    else:
        parts.append(f"Triage (heuristic fallback): {triage['route'].replace('_', ' ')} (risk {triage['risk_score']}); top factors: "
                     + ", ".join(f"{f['factor']} ({f['impact']:+})" for f in triage["top_factors"]) + ".")
    parts.append("This is a rule match on telemetry, not proof of technique occurrence; analyst verdict required.")
    finding = HuntFinding(
        finding_id=finding_id, case_id=f"CASE-{case_digest}", rule_id=rule.rule_id, rule_title=rule.title,
        compiled_query=query, time_start=str(meta.get("timestamp", "")), time_end=str(meta.get("timestamp", "")),
        event_references=json.dumps([{"event_id": meta.get("event_id"), "source": meta.get("source"),
                                      "timestamp": meta.get("timestamp"), "connector": connector}]),
        hosts=host, users=str(fields.get("User", "")),
        processes=json.dumps([{"image": image, "command_line": cmd, "process_id": str(fields.get("ProcessId", "")),
                               "parent_image": str(fields.get("ParentImage", "")),
                               "parent_command_line": str(fields.get("ParentCommandLine", ""))}]),
        ips=str(fields.get("DestinationIp", "") or ""), attack_technique_ids=technique,
        narrative=" ".join(parts), risk_score=triage["risk_score"], threat_probability=triage["threat_probability"],
        label=triage["label"], verification_status="unverified",
        source_dataset="evtx" if str(meta.get("source", "")).endswith(".evtx") else connector,
        triage_json=json.dumps(triage),
    )
    db.add(finding)
    db.flush()
    return finding, True


def execute_campaign_hunt(db: Session, campaign: Campaign, rules: list[CampaignRule] | None = None) -> dict:
    campaign.status = "hunting"
    rules = rules if rules is not None else db.query(CampaignRule).filter_by(campaign_id=campaign.id).all()
    conns = connectors.active_connectors()
    if telemetry.event_count(db) == 0 and any(c.name == "local" for c in conns):
        emit(db, campaign.id, "execute", "Local telemetry store is empty; loading default EVTX samples")
        res = telemetry.ingest_default_samples(db)
        for err in res["errors"]:
            emit(db, campaign.id, "execute", f"Could not load sample {err['sample']}: {err['error']}", level="warn")
    db.query(HuntExecution).filter_by(campaign_id=campaign.id).delete()
    db.flush()
    stats = {"executions": 0, "hits": 0, "new_findings": 0, "failed": 0}
    post_task46_runtime = get_post_task46_runtime_adapter()

    for rule in rules:
        parsed, _ = parse_rule(rule.generated_yaml)
        hyp = db.get(CampaignHypothesis, rule.hypothesis_id) if rule.hypothesis_id else None

        # Read-only Post Task 46 runtime provenance.
        # This is evidence/provenance only; it does not create findings
        # and does not replace the active connector hunt.
        if rule.source_rule_id:
            runtime_artifact = post_task46_runtime.get(rule.source_rule_id)
            if runtime_artifact:
                runtime_detail = {
                    "source": "post_task46_handoff",
                    "source_rule_id": rule.source_rule_id,
                    "technique_id": runtime_artifact.technique_id,
                    "technique_name": runtime_artifact.technique_name,
                    "analytic_id": runtime_artifact.analytic_id,
                    "path_id": runtime_artifact.path_id,
                    "plan_id": runtime_artifact.plan_id,
                    "classification": runtime_artifact.classification,
                    "keyword_mode": runtime_artifact.keyword_mode,
                    "runtime_execution_candidate": runtime_artifact.runtime_execution_candidate,
                    "queue_present": runtime_artifact.queue_present,
                    "result_present": runtime_artifact.result_present,
                    "execution_status": runtime_artifact.execution_status,
                    "match_count": runtime_artifact.match_count,
                    "disposition": runtime_artifact.disposition,
                    "zero_result_interpretation": runtime_artifact.zero_result_interpretation,
                }

                evidence_level = "warn" if (
                    runtime_artifact.execution_status == "ZERO_INCONCLUSIVE_RUNTIME_VISIBILITY"
                    or runtime_artifact.execution_status == "EXECUTION_ERROR"
                    or runtime_artifact.disposition
                ) else "info"

                emit(
                    db,
                    campaign.id,
                    "execute",
                    f"Post Task 46 runtime evidence: '{rule.title}' -> "
                    f"{runtime_artifact.execution_status} "
                    f"(matches={runtime_artifact.match_count})",
                    level=evidence_level,
                    rule_id=rule.rule_id,
                    source_rule_id=rule.source_rule_id,
                    runtime_evidence=runtime_detail,
                )
        if parsed is None or not rule.executable:
            db.add(HuntExecution(campaign_id=campaign.id, rule_pk=rule.id, technique_id=hyp.technique_id if hyp else "",
                                 connector="-", status="blocked", status_reason="Rule failed validation gate",
                                 validation_json=rule.validation_json, finished_at=datetime.utcnow()))
            continue
        for conn in conns:
            ex = HuntExecution(campaign_id=campaign.id, rule_pk=rule.id, technique_id=hyp.technique_id if hyp else "",
                               connector=conn.name, status="running", validation_json=rule.validation_json)
            db.add(ex)
            db.flush()
            try:
                res = conn.run(parsed, db)
            except Exception as exc:  # noqa: BLE001 - a bad connector must not sink the campaign
                log.exception("connector %s failed", conn.name)
                ex.status, ex.status_reason = "failed", str(exc)[:500]
                stats["failed"] += 1
                emit(db, campaign.id, "execute", f"{conn.label} failed on '{rule.title}': {exc}", level="error")
                ex.finished_at = datetime.utcnow()
                continue
            ex.status, ex.status_reason = res.status, res.reason
            ex.native_query, ex.events_scanned, ex.hits, ex.duration_ms = res.query, res.events_scanned, len(res.matches), res.duration_ms
            ex.finished_at = datetime.utcnow()
            stats["executions"] += 1
            if res.status == "failed":
                stats["failed"] += 1
                emit(db, campaign.id, "execute", f"{conn.label}: '{rule.title}' failed - {res.reason}", level="error")
                continue
            stats["hits"] += len(res.matches)
            emit(db, campaign.id, "execute",
                 f"{conn.label}: '{rule.title}' scanned {res.events_scanned} events, {len(res.matches)} hit(s) in {res.duration_ms} ms",
                 connector=conn.name, hits=len(res.matches))
            for m in res.matches:
                finding, created = _finding_from_match(db, campaign, rule, parsed, hyp, m, res.query, conn.name)
                stats["new_findings"] += int(created)
                if not db.query(CampaignFinding).filter_by(campaign_id=campaign.id, finding_id=finding.finding_id).first():
                    db.add(CampaignFinding(campaign_id=campaign.id, finding_id=finding.finding_id,
                                           match_type="sigma_rule", confidence=(finding.risk_score or 0) / 100))
    db.flush()
    rows = db.query(CampaignFinding).filter_by(campaign_id=campaign.id).all()
    campaign.total_findings = len(rows)
    campaign.risk_score = round(max((r.confidence for r in rows), default=0.0) * 100, 2)
    emit(db, campaign.id, "score", f"Scored {len(rows)} finding(s); campaign risk {campaign.risk_score}", findings=len(rows))
    return stats


def run_campaign(db: Session, campaign: Campaign) -> Campaign:
    """Run a campaign end-to-end: detection -> validation -> translate -> execute -> score.
    Failures are captured (status=failed + timeline event), never left as 'running'."""
    campaign.status = "running"
    campaign.started_at = datetime.now(timezone.utc)
    campaign.completed_at = None
    db.flush()
    emit(db, campaign.id, "hypotheses", f"Campaign started with {campaign.total_hypotheses} hypothesis(es)")
    try:
        rules = db.query(CampaignRule).filter_by(campaign_id=campaign.id).all()
        if not rules:
            generate_campaign_rules(db, campaign)
            rules = db.query(CampaignRule).filter_by(campaign_id=campaign.id).all()
        if not rules:
            raise ValueError("Campaign has no detection rules.")
        ready = _gate_rules(db, campaign, rules)
        emit(db, campaign.id, "translate", f"{len(ready)}/{len(rules)} rule(s) passed the validation gate and were compiled")
        stats = execute_campaign_hunt(db, campaign, rules)
        campaign.status = "completed"
        emit(db, campaign.id, "review", f"Run finished: {stats['executions']} execution(s), {stats['hits']} hit(s), "
             f"{stats['new_findings']} new finding(s), {stats['failed']} failure(s). Awaiting analyst review.")
    except ValueError:
        db.rollback()
        raise
    except Exception as exc:  # noqa: BLE001
        log.exception("campaign %s failed", campaign.id)
        db.rollback()
        campaign = db.get(Campaign, campaign.id)
        campaign.status = "failed"
        emit(db, campaign.id, "execute", f"Campaign failed: {exc}", level="error")
    campaign.completed_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(campaign)
    return campaign


def run_campaign_background(campaign_id: int) -> None:
    from app.core.database import SessionLocal
    db = SessionLocal()
    try:
        c = db.get(Campaign, campaign_id)
        if c:
            run_campaign(db, c)
    except Exception:  # noqa: BLE001
        log.exception("background run for %s crashed", campaign_id)
    finally:
        db.close()
