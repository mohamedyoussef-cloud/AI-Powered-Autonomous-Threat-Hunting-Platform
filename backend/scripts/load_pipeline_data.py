#!/usr/bin/env python3
"""
scripts/load_pipeline_data.py
--------------------------------
The bridge between the data-preparation pipeline (a separate project —
see PIPELINE_DATA_ROOT in app/core/config.py) and this platform's
PostgreSQL database. Reads the pipeline's JSON/JSONL canonical + derived
outputs and upserts them into the relational schema the API serves from.

This is intentionally a separate, explicit step (not something the API
does on every request) — the pipeline and the platform are different
projects with different release cadences; re-run this whenever you have
fresh pipeline output to publish.

Usage:
    python scripts/load_pipeline_data.py
    python scripts/load_pipeline_data.py --data-root /path/to/pipeline/data
"""
from __future__ import annotations

import datetime as dt
import json
import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_ROOT))

from sqlalchemy.orm import Session  # noqa: E402

from app.core.config import get_settings  # noqa: E402
from app.core.database import SessionLocal  # noqa: E402
from app.models.attack import AttackTechnique, Mitigation  # noqa: E402
from app.models.sigma import SigmaRule, SigmaRuleTechnique  # noqa: E402
from app.models.finding import HuntFinding  # noqa: E402
from app.models.pipeline import (  # noqa: E402
    PipelineRun, PipelineStageResult, QualityGateResult, SourceSummary,
)


def _load_json(path: Path, default):
    if not path.exists():
        return default
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _load_jsonl(path: Path, default):
    if not path.exists():
        return default
    records = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def load_attack(db: Session, data_root: Path) -> int:
    kb = _load_json(data_root / "canonical" / "attack_knowledge.json", {})
    techniques = kb.get("techniques", [])
    links = kb.get("sub_technique_links", [])
    parent_by_child = {link["child_attack_id"]: link["parent_attack_id"] for link in links}

    db.query(AttackTechnique).delete()
    for t in techniques:
        db.add(AttackTechnique(
            stix_id=t["stix_id"],
            attack_id=t["attack_id"],
            name=t["name"],
            description=t.get("description", ""),
            tactics=",".join(t.get("tactics", [])),
            platforms=",".join(t.get("platforms", [])),
            version=t.get("version", ""),
            is_deprecated=t.get("is_deprecated", False),
            is_revoked=t.get("is_revoked", False),
            is_sub_technique=t.get("is_sub_technique", False),
            parent_attack_id=parent_by_child.get(t["attack_id"]),
        ))

    db.query(Mitigation).delete()
    for m in kb.get("mitigations", []):
        db.add(Mitigation(
            mitigation_id=m["mitigation_id"],
            name=m["name"],
            description=m.get("description", ""),
            technique_relationship=",".join(m.get("technique_relationship", [])),
        ))

    db.commit()
    return len(techniques)


def load_sigma(db: Session, data_root: Path) -> int:
    rules = _load_json(data_root / "canonical" / "sigma_rules.json", [])

    db.query(SigmaRuleTechnique).delete()
    db.query(SigmaRule).delete()
    db.flush()

    technique_id_by_attack_id = {
        row.attack_id: row.id for row in db.query(AttackTechnique).all()
    }

    count = 0
    for r in rules:
        identity = r["identity"]
        logsource = r["logsource"]
        detection = r["detection"]
        validation = r["validation"]
        attack_mapping = r["attack_mapping"]
        training = r.get("training", {})
        rule_id = identity.get("rule_id") or identity["title"]

        row = SigmaRule(
            rule_id=rule_id,
            title=identity["title"],
            status=identity.get("status", "experimental"),
            description=identity.get("description", ""),
            author=identity.get("author", ""),
            level=identity.get("level", "medium"),
            logsource_product=logsource.get("product"),
            logsource_category=logsource.get("category"),
            logsource_service=logsource.get("service"),
            condition_expression=detection.get("condition_expression", ""),
            raw_yaml=r.get("raw_yaml", ""),
            tag_validation_result=attack_mapping.get("tag_validation_result", "unvalidated"),
            yaml_valid=validation.get("yaml_valid", False),
            sigma_schema_valid=validation.get("sigma_schema_valid", False),
            compilation_backend=validation.get("compilation_backend"),
            compiled_query=validation.get("compiled_query"),
            quarantine_category=r.get("_quarantine_category", "accepted_core"),
            is_training_ready=bool(training.get("target_sigma_yaml")),
            split_id=training.get("split_id"),
            leakage_group=training.get("leakage_group"),
        )
        db.add(row)
        db.flush()  # need row.id for the join rows below

        for tid in attack_mapping.get("technique_ids", []):
            tech_pk = technique_id_by_attack_id.get(tid)
            if tech_pk:
                db.add(SigmaRuleTechnique(sigma_rule_id=row.id, attack_technique_id=tech_pk))
        count += 1

    db.commit()
    return count


def load_findings(db: Session, data_root: Path) -> int:
    findings = _load_json(data_root / "derived" / "hunt_findings.json", [])

    db.query(HuntFinding).delete()
    rule_title_by_id = {r.rule_id: r.title for r in db.query(SigmaRule).all()}

    for f in findings:
        source_dataset = "unknown"
        refs = f.get("event_references", [])
        if refs and ":" in refs[0]:
            source_dataset = refs[0].split(":")[0]

        db.add(HuntFinding(
            finding_id=f["finding_id"],
            case_id=f["case_id"],
            rule_id=f["rule_id"],
            rule_title=rule_title_by_id.get(f["rule_id"], ""),
            compiled_query=f.get("compiled_query", ""),
            event_references=",".join(refs),
            time_start=f.get("time_start", ""),
            time_end=f.get("time_end", ""),
            hosts=",".join(f.get("entities", {}).get("hosts", [])),
            users=",".join(f.get("entities", {}).get("users", [])),
            processes=",".join(f.get("entities", {}).get("processes", [])),
            ips=",".join(f.get("entities", {}).get("ips", [])),
            attack_technique_ids=",".join(t["attack_id"] for t in f.get("attack_techniques", [])),
            narrative=f.get("evidence", {}).get("narrative", ""),
            risk_score=f.get("risk_score"),
            threat_probability=f.get("threat_probability"),
            label=f.get("label", "unknown"),
            verification_status=f.get("verification_status", "unverified"),
            source_dataset=source_dataset,
        ))

    db.commit()
    return len(findings)


def load_pipeline_status(db: Session, data_root: Path) -> int:
    report = _load_json(data_root / "manifests" / "pipeline_run_report.json", None)
    if not report:
        return 0

    run = PipelineRun(
        run_timestamp=dt.datetime.fromisoformat(report["run_timestamp_utc"].replace("Z", "+00:00")),
        mode=report.get("mode", "unknown"),
        overall_status=report.get("overall_status", "UNKNOWN"),
        total_duration_seconds=report.get("total_duration_seconds", 0.0),
    )
    db.add(run)
    db.flush()

    for stage in report.get("stages", []):
        db.add(PipelineStageResult(
            pipeline_run_id=run.id,
            stage_name=stage["name"],
            status=stage["status"],
            returncode=stage.get("returncode", 0),
            duration_seconds=stage.get("duration_seconds", 0.0),
        ))

    quality = _load_json(data_root / "manifests" / "phase7_quality_report.json", {})
    for gate in quality.get("gates", []):
        db.add(QualityGateResult(
            pipeline_run_id=run.id,
            gate_name=gate["name"],
            passed=gate["passed"],
            measured=gate["measured"],
            threshold=gate["threshold"],
            message=gate["message"],
        ))

    db.commit()
    return 1


def refresh_source_summaries(db: Session, counts: dict) -> None:
    db.query(SourceSummary).delete()
    now = dt.datetime.now(dt.UTC)
    for source_id, record_count in counts.items():
        db.add(SourceSummary(
            source_id=source_id, record_count=record_count,
            last_loaded_at=now, extra_json="{}",
        ))
    db.commit()


def main() -> int:
    args = sys.argv[1:]
    settings = get_settings()
    data_root = Path(settings.PIPELINE_DATA_ROOT)
    if "--data-root" in args:
        data_root = Path(args[args.index("--data-root") + 1])

    if not data_root.exists():
        print(f"[FATAL] Pipeline data root not found: {data_root}")
        return 1

    print(f"Loading pipeline data from: {data_root}\n")
    db = SessionLocal()
    try:
        n_attack = load_attack(db, data_root)
        print(f"  ATT&CK techniques loaded: {n_attack}")

        n_sigma = load_sigma(db, data_root)
        print(f"  Sigma rules loaded: {n_sigma}")

        n_findings = load_findings(db, data_root)
        print(f"  Hunt findings loaded: {n_findings}")

        n_runs = load_pipeline_status(db, data_root)
        print(f"  Pipeline run report loaded: {'yes' if n_runs else 'no report found'}")

        refresh_source_summaries(db, {
            "attack": n_attack, "sigma": n_sigma, "findings": n_findings,
        })
        print("\nSource summaries refreshed.")
        print("\nDone.")
    finally:
        db.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
