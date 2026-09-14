#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

PIPELINE_VERSION = "0.2.0"
SCHEMA_VERSION = "1.0.0"


def external_id(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return str(ref["external_id"])
    return None


def json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [json_safe(v) for v in value]
    return value


def write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(json_safe(record), ensure_ascii=False, separators=(",", ":")) + "\n")


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--project-root", type=Path, required=True)
    args = p.parse_args()
    root = args.project_root
    src = root / "data/raw/mitre_attack/enterprise-attack-19.1.json"
    out = root / "data/processed/knowledge"
    out.mkdir(parents=True, exist_ok=True)
    bundle = json.loads(src.read_text(encoding="utf-8"))
    objects = bundle.get("objects", [])
    by_id = {o["id"]: o for o in objects if isinstance(o, dict) and o.get("id")}
    collection = next((o for o in objects if o.get("type") == "x-mitre-collection"), {})
    attack_version = str(collection.get("x_mitre_version") or "19.1")
    ingested_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    parent_by_child: dict[str, str] = {}
    strategies_by_technique: dict[str, list[str]] = defaultdict(list)
    for rel in (o for o in objects if o.get("type") == "relationship"):
        if rel.get("relationship_type") == "subtechnique-of":
            parent_by_child[rel.get("source_ref")] = rel.get("target_ref")
        elif rel.get("relationship_type") == "detects":
            source = by_id.get(rel.get("source_ref"), {})
            target = by_id.get(rel.get("target_ref"), {})
            if source.get("type") == "x-mitre-detection-strategy" and target.get("type") == "attack-pattern":
                sid = external_id(source)
                if sid:
                    strategies_by_technique[target["id"]].append(sid)

    strategy_analytics: dict[str, list[str]] = {}
    analytic_components: dict[str, list[str]] = {}
    for obj in objects:
        if obj.get("type") == "x-mitre-detection-strategy":
            sid = external_id(obj)
            if sid:
                strategy_analytics[sid] = [external_id(by_id.get(ref, {})) or ref for ref in obj.get("x_mitre_analytic_refs", [])]
        elif obj.get("type") == "x-mitre-analytic":
            aid = external_id(obj)
            if aid:
                components = []
                for ls in obj.get("x_mitre_log_source_references", []) or []:
                    comp = by_id.get(ls.get("x_mitre_data_component_ref"), {})
                    cid = external_id(comp)
                    if cid:
                        components.append(cid)
                analytic_components[aid] = sorted(set(components))

    schema = json.loads((root / "schemas/attack_technique.schema.json").read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    active: list[dict[str, Any]] = []
    inactive: list[dict[str, Any]] = []
    validation_errors: list[dict[str, Any]] = []

    for obj in (o for o in objects if o.get("type") == "attack-pattern"):
        tid = external_id(obj)
        if not tid or not tid.startswith("T"):
            continue
        strategy_ids = sorted(set(strategies_by_technique.get(obj["id"], [])))
        analytic_ids = sorted({a for s in strategy_ids for a in strategy_analytics.get(s, []) if a.startswith("AN")})
        component_ids = sorted({c for a in analytic_ids for c in analytic_components.get(a, [])})
        parent_obj = by_id.get(parent_by_child.get(obj["id"], ""), {})
        record = {
            "technique_id": tid,
            "name": obj.get("name") or "Unnamed Technique",
            "description": obj.get("description"),
            "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
            "parent_technique_id": external_id(parent_obj),
            "platforms": sorted(set(obj.get("x_mitre_platforms", []) or [])),
            "tactics": sorted({p.get("phase_name") for p in obj.get("kill_chain_phases", []) or [] if p.get("phase_name")}),
            "data_components": component_ids,
            "detection_strategy_ids": strategy_ids,
            "analytic_ids": analytic_ids,
            "revoked": bool(obj.get("revoked")),
            "deprecated": bool(obj.get("x_mitre_deprecated")),
            "attack_version": attack_version,
            "lineage": {
                "source_dataset": "mitre_attack_enterprise",
                "source_record_id": obj["id"],
                "schema_version": SCHEMA_VERSION,
                "pipeline_version": PIPELINE_VERSION,
                "source_file": str(src.relative_to(root)),
                "ingested_at": ingested_at,
            },
        }
        errors = sorted(validator.iter_errors(record), key=lambda e: list(e.path))
        if errors:
            validation_errors.append({"technique_id": tid, "errors": [e.message for e in errors]})
        if record["revoked"] or record["deprecated"]:
            inactive.append(record)
        else:
            active.append(record)

    active.sort(key=lambda x: x["technique_id"])
    inactive.sort(key=lambda x: x["technique_id"])
    write_jsonl(out / "attack_techniques_active.jsonl", active)
    write_jsonl(out / "attack_techniques_inactive.jsonl", inactive)
    write_jsonl(out / "attack_techniques_all.jsonl", active + inactive)

    generic_types = {
        "x-mitre-data-component": "attack_data_components.jsonl",
        "x-mitre-detection-strategy": "attack_detection_strategies.jsonl",
        "x-mitre-analytic": "attack_analytics.jsonl",
        "x-mitre-tactic": "attack_tactics.jsonl",
        "x-mitre-data-source": "attack_data_sources.jsonl",
    }
    for typ, filename in generic_types.items():
        records = []
        for obj in objects:
            if obj.get("type") != typ:
                continue
            records.append({
                "external_id": external_id(obj),
                "stix_id": obj.get("id"),
                "name": obj.get("name"),
                "description": obj.get("description"),
                "platforms": obj.get("x_mitre_platforms", []),
                "deprecated": bool(obj.get("x_mitre_deprecated")),
                "revoked": bool(obj.get("revoked")),
                "raw": obj,
            })
        write_jsonl(out / filename, records)

    with (out / "attack_relationships.csv").open("w", newline="", encoding="utf-8") as f:
        fields = ["relationship_stix_id", "relationship_type", "source_stix_id", "source_type", "source_external_id", "target_stix_id", "target_type", "target_external_id", "revoked"]
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for rel in (o for o in objects if o.get("type") == "relationship"):
            so = by_id.get(rel.get("source_ref"), {})
            to = by_id.get(rel.get("target_ref"), {})
            writer.writerow({
                "relationship_stix_id": rel.get("id"),
                "relationship_type": rel.get("relationship_type"),
                "source_stix_id": rel.get("source_ref"),
                "source_type": so.get("type"),
                "source_external_id": external_id(so),
                "target_stix_id": rel.get("target_ref"),
                "target_type": to.get("type"),
                "target_external_id": external_id(to),
                "revoked": bool(rel.get("revoked")),
            })

    object_counts = Counter(o.get("type", "unknown") for o in objects)
    summary = {
        "source_file": str(src.relative_to(root)),
        "attack_version": attack_version,
        "attack_spec_version": collection.get("x_mitre_attack_spec_version"),
        "object_count": len(objects),
        "object_counts_by_type": dict(sorted(object_counts.items())),
        "techniques_total": len(active) + len(inactive),
        "techniques_active": len(active),
        "techniques_inactive": len(inactive),
        "subtechniques_active": sum(r["is_subtechnique"] for r in active),
        "techniques_with_detection_strategies": sum(bool(r["detection_strategy_ids"]) for r in active),
        "techniques_with_data_components": sum(bool(r["data_components"]) for r in active),
        "validation_error_count": len(validation_errors),
        "validation_errors": validation_errors[:100],
        "generated_at": ingested_at,
    }
    (out / "attack_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
