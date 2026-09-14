#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path


def read_jsonl(path: Path):
    with path.open(encoding="utf-8") as f:
        for line in f:
            if line.strip():
                yield json.loads(line)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--project-root", type=Path, required=True)
    args = p.parse_args()
    root = args.project_root
    knowledge = root / "data/processed/knowledge"
    detections = root / "data/processed/detections"
    reports = root / "reports"
    reports.mkdir(parents=True, exist_ok=True)

    techniques = {r["technique_id"]: r for r in read_jsonl(knowledge / "attack_techniques_active.jsonl")}
    rules = list(read_jsonl(detections / "sigma_rules_valid.jsonl"))
    rules_by_technique = defaultdict(list)
    for rule in rules:
        for tid in rule.get("attack_techniques", []):
            if tid in techniques:
                rules_by_technique[tid].append(rule)

    rows = []
    for tid, technique in sorted(techniques.items()):
        mapped = rules_by_technique.get(tid, [])
        products = sorted({str(r.get("logsource", {}).get("product")) for r in mapped if r.get("logsource", {}).get("product")})
        categories = sorted({str(r.get("logsource", {}).get("category")) for r in mapped if r.get("logsource", {}).get("category")})
        fields = sorted({f for r in mapped for f in r.get("required_fields", [])})
        rows.append({
            "technique_id": tid,
            "technique_name": technique["name"],
            "is_subtechnique": technique["is_subtechnique"],
            "platforms": ";".join(technique["platforms"]),
            "tactics": ";".join(technique["tactics"]),
            "attack_detection_strategy_count": len(technique.get("detection_strategy_ids", [])),
            "attack_analytic_count": len(technique.get("analytic_ids", [])),
            "attack_data_component_count": len(technique.get("data_components", [])),
            "sigma_rule_count": len(mapped),
            "sigma_products": ";".join(products),
            "sigma_categories": ";".join(categories),
            "sigma_required_field_count": len(fields),
            "sigma_coverage_status": "covered" if mapped else "uncovered",
        })

    out_csv = reports / "attack_sigma_coverage.csv"
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    covered = [r for r in rows if r["sigma_rule_count"] > 0]
    by_tactic_total = Counter()
    by_tactic_covered = Counter()
    for row in rows:
        tactics = [x for x in row["tactics"].split(";") if x]
        for tactic in tactics:
            by_tactic_total[tactic] += 1
            if row["sigma_rule_count"] > 0:
                by_tactic_covered[tactic] += 1
    tactic_rows = []
    for tactic in sorted(by_tactic_total):
        total = by_tactic_total[tactic]
        cov = by_tactic_covered[tactic]
        tactic_rows.append({
            "tactic": tactic,
            "active_technique_count": total,
            "covered_technique_count": cov,
            "coverage_percent": round((cov / total * 100) if total else 0.0, 2),
        })
    with (reports / "attack_sigma_coverage_by_tactic.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(tactic_rows[0].keys()))
        writer.writeheader()
        writer.writerows(tactic_rows)

    summary = {
        "active_attack_techniques": len(rows),
        "active_attack_techniques_with_sigma_rules": len(covered),
        "active_attack_techniques_without_sigma_rules": len(rows) - len(covered),
        "technique_coverage_percent": round(len(covered) / len(rows) * 100, 2) if rows else 0,
        "accepted_sigma_rules": len(rules),
        "coverage_by_tactic": tactic_rows,
    }
    (reports / "attack_sigma_coverage_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
