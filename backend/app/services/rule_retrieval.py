"""
services/rule_retrieval.py
--------------------------
Corpus-grounded rule selection. Instead of a keyword template producing a
rule with a placeholder indicator, look up real, curated Sigma rules
(3k+ in the platform DB) that are tagged with the campaign's technique,
score them, and adopt the best executable one -- with provenance.

Ranking (higher is better):
  + exact technique tag match (sub-technique > parent)
  + logsource product matches campaign platform
  + logsource category is one the local telemetry can serve
  + fewer techniques tagged (more specific rule)
  + severity level
  - rule cannot be parsed / uses unsupported features (filtered out)
"""
from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.orm import Session

from app.models.attack import AttackTechnique
from app.models.sigma import SigmaRule, SigmaRuleTechnique
from app.services.sigma_engine import parse_rule

LEVEL_SCORE = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
LOCAL_CATEGORIES = {
    "process_creation", "network_connection", "file_event", "registry_set", "registry_add",
    "registry_event", "image_load", "dns_query", "process_access", "create_remote_thread",
    "pipe_created", "wmi_event", "file_delete",
}


@dataclass
class Candidate:
    rule: SigmaRule
    pk: int
    corpus_rule_id: str
    yaml_text: str
    score: float
    reason: str


def _technique_pks(db: Session, technique_id: str) -> list[int]:
    ids = [technique_id]
    if "." in technique_id:
        ids.append(technique_id.split(".")[0])  # fall back to parent technique
    rows = db.query(AttackTechnique.id, AttackTechnique.attack_id).filter(AttackTechnique.attack_id.in_(ids)).all()
    exact = [pk for pk, aid in rows if aid == technique_id]
    parent = [pk for pk, aid in rows if aid != technique_id]
    return exact + parent


def find_candidates(db: Session, technique_id: str, platform: str = "windows", limit: int = 5) -> list[Candidate]:
    from sqlalchemy import func
    from app.models.execution import TelemetryEvent
    loaded = {c for (c,) in db.query(TelemetryEvent.category).distinct().all() if c}
    loaded_svc = {c for (c,) in db.query(TelemetryEvent.service).distinct().all() if c}
    pks = _technique_pks(db, technique_id)
    if not pks:
        return []
    exact_pk = pks[0] if db.get(AttackTechnique, pks[0]).attack_id == technique_id else None
    rows = (
        db.query(SigmaRule, SigmaRuleTechnique.attack_technique_id)
        .join(SigmaRuleTechnique, SigmaRuleTechnique.sigma_rule_id == SigmaRule.id)
        .filter(SigmaRuleTechnique.attack_technique_id.in_(pks))
        .all()
    )
    # Dry-run sample: cheap evidence that a rule can actually fire on what we hold.
    import json as _json
    sample: dict[str, list[dict]] = {}
    for cat, blob in db.query(TelemetryEvent.category, TelemetryEvent.fields_json).limit(5000).all():
        try:
            sample.setdefault(cat or "", []).append(_json.loads(blob))
        except ValueError:
            pass
    seen: set[int] = set()
    out: list[Candidate] = []
    for r, tech_pk in rows:
        if r.id in seen or not r.raw_yaml:
            continue
        seen.add(r.id)
        parsed, issues = parse_rule(r.raw_yaml)
        if parsed is None or parsed.has_placeholder():
            continue
        score, why = 0.0, []
        if tech_pk == exact_pk:
            score += 40; why.append("exact technique tag")
        else:
            score += 15; why.append("parent technique tag")
        if (parsed.logsource.get("product") or "").lower() == platform.lower():
            score += 25; why.append(f"product={platform}")
        cat = parsed.logsource.get("category")
        svc = parsed.logsource.get("service")
        if cat in loaded:
            score += 45; why.append(f"telemetry loaded for {cat}")
        elif svc and svc in loaded_svc:
            score += 45; why.append(f"telemetry loaded for service {svc}")
        elif cat in LOCAL_CATEGORIES:
            score += 12; why.append(f"supported category {cat} (no telemetry loaded yet)")
        elif (parsed.logsource.get("service") or "") in ("sysmon", "powershell", "security"):
            score += 10; why.append("service log source")
        prod = (parsed.logsource.get("product") or "").lower()
        if prod and prod != platform.lower():
            continue  # never run a macOS/linux/cloud rule against a windows campaign
        pool = sample.get(cat or "", [])
        dry = sum(1 for e in pool[:2000] if parsed.match(e)) if pool else 0
        if dry:
            score += 60; why.append(f"dry-run: matches {dry} loaded event(s)")
        score += max(0, 10 - 2 * len(parsed.technique_ids))
        score += LEVEL_SCORE.get(parsed.level.lower(), 2) * 2
        out.append(Candidate(parsed, r.id, r.rule_id, r.raw_yaml, score, ", ".join(why)))
    out.sort(key=lambda c: c.score, reverse=True)
    return out[:limit]
