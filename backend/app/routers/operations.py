"""
routers/operations.py
---------------------
Everything the UI needs to show a hunt as a connected, observable process:

  GET  /campaigns/{id}/pipeline     live per-stage status (drives the workflow graph)
  GET  /campaigns/{id}/executions   every rule x connector run: query, hits, timing, errors
  GET  /campaigns/{id}/events       ordered timeline / audit log
  GET  /campaigns/{id}/report       Markdown hunt report (also ?format=json)
  GET  /campaigns/{id}/graph        attack graph nodes/edges (host -> technique -> finding)
  GET  /connectors                  registered execution backends and their state
  GET  /telemetry/summary           what the local hunt backend can actually see
  POST /telemetry/ingest            load EVTX / JSONL / public sample into the store
  GET  /health/ready                readiness of every dependency
"""
from __future__ import annotations

import json
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import require_admin, require_user
from app.models.campaign import Campaign, CampaignFinding, CampaignHypothesis, CampaignRule
from app.models.execution import AnalystVerdict, CampaignEvent, HuntExecution
from app.models.finding import HuntFinding
from app.services import connectors, telemetry

router = APIRouter(tags=["operations"])
settings = get_settings()


def _campaign(db: Session, cid: int) -> Campaign:
    c = db.get(Campaign, cid)
    if not c:
        raise HTTPException(404, "Campaign not found")
    return c


def _j(s: str | None, default):
    try:
        return json.loads(s) if s else default
    except json.JSONDecodeError:
        return default


@router.get("/campaigns/{cid}/pipeline")
def campaign_pipeline(cid: int, db: Session = Depends(get_db), _=Depends(require_user)):
    c = _campaign(db, cid)
    hyps = db.query(CampaignHypothesis).filter_by(campaign_id=cid).all()
    rules = db.query(CampaignRule).filter_by(campaign_id=cid).all()
    execs = db.query(HuntExecution).filter_by(campaign_id=cid).all()
    cfs = db.query(CampaignFinding).filter_by(campaign_id=cid).all()
    fids = [x.finding_id for x in cfs]
    findings = db.query(HuntFinding).filter(HuntFinding.finding_id.in_(fids)).all() if fids else []
    last_event = {s: e for s, e in ((e.stage, e) for e in db.query(CampaignEvent).filter_by(campaign_id=cid).order_by(CampaignEvent.id))}
    running = c.status in ("running", "hunting", "generating_rules")
    failed = c.status == "failed"

    def stage_status(has_data: bool, stage: str) -> str:
        ev = last_event.get(stage)
        if ev and ev.level == "error":
            return "failed"
        if has_data:
            return "done"
        return "running" if running else "pending"

    corpus = sum(1 for r in rules if r.source_kind == "corpus")
    blocked = sum(1 for r in rules if not r.executable)
    by_conn: dict[str, dict] = {}
    for e in execs:
        d = by_conn.setdefault(e.connector, {"executions": 0, "hits": 0, "failed": 0, "scanned": 0, "ms": 0})
        d["executions"] += 1
        d["hits"] += e.hits
        d["scanned"] += e.events_scanned
        d["ms"] += e.duration_ms
        d["failed"] += int(e.status == "failed")
    conn_view = []
    for name, conn in connectors.registry().items():
        agg = by_conn.get(name, {})
        conn_view.append({**conn.describe(), **agg,
                          "status": ("failed" if agg.get("failed") else "done" if agg.get("executions") else
                                     "running" if running and conn.configured() else "idle" if conn.configured() else "not_configured")})
    routes = Counter(_j(f.triage_json, {}).get("route", "unscored") for f in findings)
    verdicts = Counter(f.analyst_verdict or "pending" for f in findings)
    return {
        "campaign_id": cid, "status": c.status, "failed": failed,
        "stages": [
            {"id": "hypotheses", "label": "Hypotheses", "status": stage_status(bool(hyps), "hypotheses"),
             "summary": f"{len(hyps)} hypothesis(es)", "count": len(hyps)},
            {"id": "detection", "label": "Sigma rules", "status": stage_status(bool(rules), "detection"),
             "summary": f"{len(rules)} rule(s): {corpus} from corpus, {len(rules) - corpus} template",
             "count": len(rules), "blocked": blocked},
            {"id": "translate", "label": "Validate + compile", "status": stage_status(bool(execs), "translate"),
             "summary": f"{len(rules) - blocked} passed gate, {blocked} blocked", "count": len(rules) - blocked},
            {"id": "execute", "label": "Execute", "status": stage_status(bool(execs), "execute"),
             "summary": f"{sum(e.hits for e in execs)} hit(s) across {len(execs)} run(s)", "count": len(execs),
             "connectors": conn_view},
            {"id": "score", "label": "Triage + risk", "status": stage_status(bool(findings) or (bool(execs) and not running), "score"),
             "summary": f"{len(findings)} finding(s); " + ", ".join(f"{v} {k.replace('_', ' ')}" for k, v in routes.items()) if findings else "0 findings",
             "count": len(findings), "routes": dict(routes)},
            {"id": "review", "label": "Analyst review", "status": "done" if c.status == "completed" and findings and all(f.analyst_verdict for f in findings)
             else "running" if c.status == "completed" and findings else "pending",
             "summary": f"{verdicts.get('pending', 0)} pending, {len(findings) - verdicts.get('pending', 0)} decided", "count": len(findings),
             "verdicts": dict(verdicts)},
        ],
        "connectors": conn_view,
        "telemetry_events": telemetry.event_count(db),
    }


@router.get("/campaigns/{cid}/executions")
def campaign_executions(cid: int, db: Session = Depends(get_db), _=Depends(require_user)):
    _campaign(db, cid)
    rules = {r.id: r for r in db.query(CampaignRule).filter_by(campaign_id=cid)}
    rows = db.query(HuntExecution).filter_by(campaign_id=cid).order_by(HuntExecution.id).all()
    return {"items": [{
        "id": e.id, "rule_pk": e.rule_pk, "rule_title": rules[e.rule_pk].title if e.rule_pk in rules else "",
        "rule_source": rules[e.rule_pk].source_kind if e.rule_pk in rules else "",
        "source_rule_id": rules[e.rule_pk].source_rule_id if e.rule_pk in rules else None,
        "technique_id": e.technique_id, "connector": e.connector, "status": e.status, "reason": e.status_reason,
        "query": e.native_query, "events_scanned": e.events_scanned, "hits": e.hits, "duration_ms": e.duration_ms,
        "validation": _j(e.validation_json, {}),
        "finished_at": e.finished_at.isoformat() if e.finished_at else None,
    } for e in rows]}


@router.get("/campaigns/{cid}/events")
def campaign_events(cid: int, limit: int = Query(200, le=1000), db: Session = Depends(get_db), _=Depends(require_user)):
    _campaign(db, cid)
    rows = db.query(CampaignEvent).filter_by(campaign_id=cid).order_by(CampaignEvent.id.desc()).limit(limit).all()
    return {"items": [{"id": e.id, "stage": e.stage, "level": e.level, "message": e.message,
                       "detail": _j(e.detail_json, {}), "at": e.created_at.isoformat()} for e in reversed(rows)]}


@router.get("/campaigns/{cid}/graph")
def campaign_graph(cid: int, db: Session = Depends(get_db), _=Depends(require_user)):
    """host -> process -> finding -> ATT&CK technique graph for the investigation view."""
    _campaign(db, cid)
    fids = [x.finding_id for x in db.query(CampaignFinding).filter_by(campaign_id=cid)]
    findings = db.query(HuntFinding).filter(HuntFinding.finding_id.in_(fids)).all() if fids else []
    nodes: dict[str, dict] = {}
    edges: list[dict] = []

    def node(nid, kind, label, **extra):
        nodes.setdefault(nid, {"id": nid, "kind": kind, "label": label, **extra})
        return nid

    for f in findings:
        tri = _j(f.triage_json, {})
        fn = node(f.finding_id, "finding", f.rule_title, risk=f.risk_score, verdict=f.analyst_verdict, route=tri.get("route"))
        for h in [x for x in (f.hosts or "").split(",") if x]:
            edges.append({"from": node(f"host:{h}", "host", h), "to": fn, "label": "observed on"})
        for p in _j(f.processes, []):
            img = (p.get("image") or "").split("\\")[-1]
            if img:
                pn = node(f"proc:{img}", "process", img)
                edges.append({"from": pn, "to": fn, "label": "matched"})
                par = (p.get("parent_image") or "").split("\\")[-1]
                if par:
                    edges.append({"from": node(f"proc:{par}", "process", par), "to": pn, "label": "spawned"})
        for t in [x for x in (f.attack_technique_ids or "").split(",") if x]:
            edges.append({"from": fn, "to": node(f"tech:{t}", "technique", t), "label": "maps to"})
    uniq = {(e["from"], e["to"], e["label"]): e for e in edges}
    return {"nodes": list(nodes.values()), "edges": list(uniq.values())}


@router.get("/campaigns/{cid}/report")
def campaign_report(cid: int, format: str = "markdown", db: Session = Depends(get_db), _=Depends(require_user)):
    c = _campaign(db, cid)
    hyps = db.query(CampaignHypothesis).filter_by(campaign_id=cid).all()
    rules = db.query(CampaignRule).filter_by(campaign_id=cid).all()
    execs = db.query(HuntExecution).filter_by(campaign_id=cid).all()
    fids = [x.finding_id for x in db.query(CampaignFinding).filter_by(campaign_id=cid)]
    findings = db.query(HuntFinding).filter(HuntFinding.finding_id.in_(fids)).order_by(HuntFinding.risk_score.desc()).all() if fids else []
    events = db.query(CampaignEvent).filter_by(campaign_id=cid).order_by(CampaignEvent.id).all()
    if format == "json":
        titles = {r.id: r.title for r in rules}
        fl = []
        for f in findings:
            tri = _j(f.triage_json, {})
            fl.append({"finding_id": f.finding_id, "rule_title": f.rule_title, "risk_score": f.risk_score,
                       "label": f.label, "route": tri.get("route"), "techniques": f.attack_technique_ids,
                       "hosts": f.hosts, "case_id": f.case_id, "analyst_verdict": f.analyst_verdict or "pending",
                       "narrative": f.narrative, "top_factors": tri.get("top_factors", [])})
        ex = [{"rule": titles.get(e.rule_pk, "-"), "connector": e.connector, "status": e.status,
               "events_scanned": e.events_scanned, "hits": e.hits, "duration_ms": e.duration_ms,
               "query": e.native_query} for e in execs]
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "campaign": {"id": c.id, "name": c.name, "status": c.status, "risk_score": c.risk_score,
                         "target_platform": getattr(c, "target_platform", None), "mode": getattr(c, "mode", None),
                         "description": getattr(c, "description", None)},
            "summary": {"hypotheses": len(hyps), "rules": len(rules),
                        "executable_rules": sum(1 for r in rules if r.executable), "executions": len(execs),
                        "events_scanned": sum(e.events_scanned or 0 for e in execs),
                        "hits": sum(e.hits or 0 for e in execs), "findings": len(findings),
                        "high_risk": sum(1 for f in findings if f.label == "high"),
                        "pending_review": sum(1 for f in findings if not f.analyst_verdict)},
            "hypotheses": [{"technique_id": h.technique_id, "technique_name": h.technique_name,
                            "hypothesis_text": h.hypothesis_text, "detection_objective": h.detection_objective,
                            "known_limitations": [x.strip() for x in (h.known_limitations or "").splitlines() if x.strip()]}
                           for h in hyps],
            "rules": [{"title": r.title, "source": r.source_kind, "source_rule_id": r.source_rule_id,
                       "lifecycle": r.validation_status, "executable": bool(r.executable)} for r in rules],
            "executions": ex, "findings": fl,
            "timeline": [{"time": f"{e.created_at:%H:%M:%S}", "stage": e.stage, "message": e.message} for e in events],
        }
    L = [f"# Hunt report: {c.name}", "",
         f"- **Campaign ID:** {c.id}  \n- **Status:** {c.status}  \n- **Platform:** {c.target_platform}  \n"
         f"- **Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}  \n- **Campaign risk:** {c.risk_score}", "",
         "## 1. Hypotheses", ""]
    for h in hyps:
        L += [f"### {h.technique_id} - {h.technique_name}", h.hypothesis_text or "_none_", ""]
        if h.detection_objective:
            L += [f"**Detection objective:** {h.detection_objective}", ""]
        if h.known_limitations:
            L += ["**Known limitations:**"] + [f"- {x}" for x in h.known_limitations.splitlines()] + [""]
    L += ["## 2. Detection rules", "", "| Rule | Source | Lifecycle | Executable |", "|---|---|---|---|"]
    for r in rules:
        L.append(f"| {r.title} | {r.source_kind}{' (' + r.source_rule_id + ')' if r.source_rule_id else ''} | {r.validation_status} | {'yes' if r.executable else 'NO'} |")
    L += ["", "## 3. Execution", "", "| Rule | Connector | Status | Scanned | Hits | ms |", "|---|---|---|---|---|---|"]
    titles = {r.id: r.title for r in rules}
    for e in execs:
        L.append(f"| {titles.get(e.rule_pk, '-')} | {e.connector} | {e.status} | {e.events_scanned} | {e.hits} | {e.duration_ms} |")
    for e in execs:
        if e.native_query:
            L += ["", f"**{titles.get(e.rule_pk, '-')} - compiled query ({e.connector})**", "```spl", e.native_query, "```"]
            break
    L += ["", f"## 4. Findings ({len(findings)})", ""]
    if not findings:
        L.append("_No rule matched the available telemetry in this run. This is not evidence of absence; see telemetry coverage._")
    for f in findings:
        tri = _j(f.triage_json, {})
        L += [f"### {f.finding_id} - {f.rule_title}",
              f"- Risk **{f.risk_score}** ({f.label}), route: {tri.get('route', '-')}",
              f"- ATT&CK: {f.attack_technique_ids} | Host: {f.hosts} | Case: {f.case_id}",
              f"- Analyst verdict: **{f.analyst_verdict or 'pending'}**", f"- {f.narrative}", ""]
        if tri.get("top_factors"):
            L.append("- Why this score: " + ", ".join(f"{x['factor']} ({x['impact']:+})" for x in tri["top_factors"]))
            L.append("")
    L += ["## 5. Timeline", ""] + [f"- `{e.created_at:%H:%M:%S}` [{e.stage}] {e.message}" for e in events]
    body = "\n".join(L) + "\n"
    return PlainTextResponse(body, media_type="text/markdown",
                             headers={"Content-Disposition": f'attachment; filename="hunt-report-{cid}.md"'})


@router.post("/connectors/splunk/test")
def test_splunk(_=Depends(require_admin)):
    return connectors.registry()["splunk"].test()


@router.get("/connectors")
def list_connectors(_=Depends(require_user)):
    return {"items": [c.describe() for c in connectors.registry().values()]}


@router.get("/telemetry/summary")
def telemetry_summary(db: Session = Depends(get_db), _=Depends(require_user)):
    return telemetry.summary(db)


@router.post("/telemetry/ingest")
def telemetry_ingest(payload: dict, db: Session = Depends(get_db), _=Depends(require_admin)):
    kind = str(payload.get("kind", "")).lower()
    path = str(payload.get("path", "")).strip()
    try:
        if kind == "default_samples":
            return telemetry.ingest_default_samples(db)
        if kind == "github_sample" and path:
            return telemetry.ingest_github_sample(db, path)
        if kind == "evtx" and path:
            return telemetry.ingest_evtx_path(db, path)
        if kind == "jsonl" and path:
            return telemetry.ingest_jsonl(db, path)
    except FileNotFoundError as exc:
        raise HTTPException(404, str(exc))
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(400, f"Ingestion failed: {exc}")
    raise HTTPException(400, "kind must be default_samples | github_sample | evtx | jsonl (path required except default_samples)")


@router.get("/health/ready")
def ready(db: Session = Depends(get_db)):
    def exists(p: str) -> bool:
        return bool(p) and Path(p).exists()

    from app.services.detection_plans import DETECTION_PLAN_FILE
    checks = {
        "database": True,
        "telemetry_events": telemetry.event_count(db),
        "phase3_hypotheses": exists(settings.TEAM_PHASE3_ROOT),
        "detection_plans": DETECTION_PLAN_FILE.exists(),
        "pipeline_data_root": exists(settings.PIPELINE_DATA_ROOT),
        "splunk_configured": connectors.registry()["splunk"].configured(),
        "auth_secret_changed": os.environ.get("THREATHUNT_AUTH_SECRET", "") not in ("", "CHANGE_THIS_THREATHUNT_SECRET_IN_PRODUCTION"),
    }
    return {"status": "ok" if checks["database"] else "degraded", "checks": checks}
