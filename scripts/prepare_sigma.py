#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

import yaml
from jsonschema import Draft202012Validator

PIPELINE_VERSION = "0.2.0"
SCHEMA_VERSION = "1.0.0"
ACTIVE_ROOTS = {
    "rules",
    "rules-emerging-threats",
    "rules-threat-hunting",
    "rules-compliance",
    "rules-dfir",
    "rules-placeholder",
}
TACTIC_PREFIX = "attack."
TECHNIQUE_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)


class DuplicateKeySafeLoader(yaml.SafeLoader):
    pass


def construct_mapping(loader: DuplicateKeySafeLoader, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    duplicates: list[str] = []
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        value = loader.construct_object(value_node, deep=deep)
        if key in mapping:
            duplicates.append(str(key))
        mapping[key] = value
    if duplicates:
        existing = getattr(loader, "duplicate_keys", [])
        existing.extend(duplicates)
        loader.duplicate_keys = existing
    return mapping


DuplicateKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    construct_mapping,
)


def json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [json_safe(v) for v in value]
    if isinstance(value, (dt.date, dt.datetime)):
        return value.isoformat()
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def parse_yaml_documents(path: Path) -> tuple[list[Any], list[str]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    docs: list[Any] = []
    duplicate_keys: list[str] = []
    for segment in yaml.compose_all(text, Loader=DuplicateKeySafeLoader):
        if segment is None:
            continue
        loader = DuplicateKeySafeLoader(text)
        try:
            doc = loader.construct_document(segment)
            docs.append(doc)
            duplicate_keys.extend(getattr(loader, "duplicate_keys", []))
        finally:
            loader.dispose()
    return docs, sorted(set(duplicate_keys))


def load_attack_context(project_root: Path) -> tuple[set[str], set[str], set[str]]:
    active: set[str] = set()
    inactive: set[str] = set()
    tactic_names: set[str] = set()
    for target, filename in [
        (active, "attack_techniques_active.jsonl"),
        (inactive, "attack_techniques_inactive.jsonl"),
    ]:
        path = project_root / "data/processed/knowledge" / filename
        if not path.exists():
            continue
        with path.open(encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    record = json.loads(line)
                    target.add(record["technique_id"].upper())
                    tactic_names.update(record.get("tactics", []))
    return active, inactive, tactic_names


def walk_field_keys(value: Any, inside_selection: bool = False) -> Iterable[str]:
    if isinstance(value, dict):
        for key, child in value.items():
            key_s = str(key)
            if key_s in {"condition", "timeframe"}:
                continue
            if inside_selection:
                if not isinstance(child, dict):
                    yield key_s
                else:
                    # Nested field structures in newer Sigma rules.
                    yield key_s
                    yield from walk_field_keys(child, inside_selection=True)
            else:
                yield from walk_field_keys(child, inside_selection=True)
    elif isinstance(value, list):
        for child in value:
            yield from walk_field_keys(child, inside_selection=inside_selection)


def extract_fields_and_modifiers(detection: dict[str, Any]) -> tuple[list[str], list[str]]:
    fields: set[str] = set()
    modifiers: set[str] = set()
    for raw_key in walk_field_keys(detection, inside_selection=False):
        if raw_key.startswith("_"):
            continue
        parts = raw_key.split("|")
        field = parts[0].strip()
        if field and field.lower() not in {"condition", "timeframe"}:
            fields.add(field)
        for modifier in parts[1:]:
            if modifier.strip():
                modifiers.add(modifier.strip())
    return sorted(fields), sorted(modifiers)


def normalized_logic_hash(logsource: dict[str, Any], detection: dict[str, Any]) -> str:
    payload = json.dumps(
        json_safe({"logsource": logsource, "detection": detection}),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def canonical_rule_record(
    doc: dict[str, Any],
    source_file: str,
    doc_index: int,
    repository_commit: str | None,
    active_attack_ids: set[str],
    inactive_attack_ids: set[str],
    tactic_names: set[str],
    duplicate_keys: list[str],
    ingested_at: str,
) -> tuple[dict[str, Any], list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    title = doc.get("title")
    if not isinstance(title, str) or not title.strip():
        errors.append("missing_or_invalid_title")
        title = f"Untitled rule from {source_file}#{doc_index}"

    logsource = doc.get("logsource")
    if not isinstance(logsource, dict):
        errors.append("missing_or_invalid_logsource")
        logsource = {}

    detection = doc.get("detection")
    if not isinstance(detection, dict) or not detection:
        errors.append("missing_or_invalid_detection")
        detection = {}

    condition = detection.get("condition") if isinstance(detection, dict) else None
    if isinstance(condition, list):
        condition = " | ".join(str(x) for x in condition)
        warnings.append("condition_was_list_and_was_serialized")
    if not isinstance(condition, str) or not condition.strip():
        errors.append("missing_or_invalid_condition")
        condition = "__INVALID_MISSING_CONDITION__"

    tags = [str(t) for t in (doc.get("tags") or []) if t is not None]
    technique_ids: set[str] = set()
    tactics: set[str] = set()
    for tag in tags:
        low = tag.lower()
        match = TECHNIQUE_RE.fullmatch(low)
        if match:
            technique_ids.add(match.group(1).upper())
        elif low.startswith(TACTIC_PREFIX) and not low.startswith("attack.t"):
            candidate_tactic = low.split(".", 1)[1]
            if candidate_tactic in tactic_names:
                tactics.add(candidate_tactic)

    for tid in sorted(technique_ids):
        if tid in inactive_attack_ids:
            warnings.append(f"attack_tag_resolves_to_inactive_technique:{tid}")
        elif tid not in active_attack_ids:
            warnings.append(f"attack_tag_not_found_in_enterprise_v19_1:{tid}")

    if duplicate_keys:
        warnings.append("duplicate_yaml_keys:" + ",".join(duplicate_keys))

    fields, modifiers = extract_fields_and_modifiers(detection)
    raw_id = doc.get("id")
    if raw_id is None:
        raw_id = "generated-" + hashlib.sha256(f"{source_file}#{doc_index}".encode()).hexdigest()[:24]
        warnings.append("missing_rule_id_generated_from_source_path")

    falsepositives = doc.get("falsepositives") or []
    if isinstance(falsepositives, str):
        falsepositives = [falsepositives]
    elif not isinstance(falsepositives, list):
        falsepositives = [str(falsepositives)]

    record = {
        "rule_id": str(raw_id),
        "title": title.strip(),
        "status": str(doc.get("status")) if doc.get("status") is not None else None,
        "description": str(doc.get("description")) if doc.get("description") is not None else None,
        "author": str(doc.get("author")) if doc.get("author") is not None else None,
        "logsource": json_safe(logsource),
        "detection": json_safe({k: v for k, v in detection.items() if k != "condition"}),
        "condition": condition.strip(),
        "required_fields": fields,
        "modifiers": modifiers,
        "falsepositives": [str(x) for x in falsepositives],
        "level": str(doc.get("level")) if doc.get("level") is not None else None,
        "tags": tags,
        "attack_techniques": sorted(technique_ids),
        "attack_tactics": sorted(tactics),
        "validation": {
            "yaml_valid": True,
            "sigma_valid": not errors,
            "status": "valid" if not errors else "invalid_sigma",
            "errors": errors,
            "warnings": sorted(set(warnings)),
        },
        "duplicate_group_id": None,
        "split_group_id": None,
        "lineage": {
            "source_dataset": "sigma_rules_repository",
            "source_record_id": f"{source_file}#{doc_index}",
            "schema_version": SCHEMA_VERSION,
            "pipeline_version": PIPELINE_VERSION,
            "source_file": source_file,
            "ingested_at": ingested_at,
        },
    }
    if repository_commit:
        record["lineage"]["source_record_id"] += f"@{repository_commit}"
    return record, errors, warnings


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
    repo = root / "data/raw/sigma/repository"
    out = root / "data/processed/detections"
    out.mkdir(parents=True, exist_ok=True)
    intake = json.loads((root / "reports/source_intake_manifest.json").read_text(encoding="utf-8"))
    sigma_manifest = next(x for x in intake["sources"] if x["source"] == "sigma_rules_repository")
    commit = sigma_manifest.get("commit")
    active_attack_ids, inactive_attack_ids, tactic_names = load_attack_context(root)
    schema = json.loads((root / "schemas/sigma_rule_record.schema.json").read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    ingested_at = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")

    accepted: list[dict[str, Any]] = []
    quarantined: list[dict[str, Any]] = []
    all_records: list[dict[str, Any]] = []
    file_parse_errors: list[dict[str, str]] = []
    root_counts: Counter[str] = Counter()
    status_counts: Counter[str] = Counter()
    product_counts: Counter[str] = Counter()
    category_counts: Counter[str] = Counter()
    warning_counts: Counter[str] = Counter()
    structural_error_counts: Counter[str] = Counter()
    logic_groups: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)

    yaml_paths = sorted([*repo.rglob("*.yml"), *repo.rglob("*.yaml")])
    for path in yaml_paths:
        relative = path.relative_to(repo).as_posix()
        source_root = relative.split("/", 1)[0]
        root_counts[source_root] += 1
        try:
            docs, duplicate_keys = parse_yaml_documents(path)
        except Exception as exc:
            file_parse_errors.append({"source_file": relative, "error": repr(exc)})
            continue
        for doc_index, doc in enumerate(docs):
            if not isinstance(doc, dict):
                file_parse_errors.append({"source_file": relative, "error": f"document_{doc_index}_not_mapping"})
                continue
            record, errors, warnings = canonical_rule_record(
                doc=doc,
                source_file=relative,
                doc_index=doc_index,
                repository_commit=commit,
                active_attack_ids=active_attack_ids,
                inactive_attack_ids=inactive_attack_ids,
                tactic_names=tactic_names,
                duplicate_keys=duplicate_keys,
                ingested_at=ingested_at,
            )
            record["split_group_id"] = "source-root:" + source_root
            schema_errors = sorted(validator.iter_errors(record), key=lambda e: list(e.path))
            if schema_errors:
                record["validation"]["sigma_valid"] = False
                record["validation"]["status"] = "invalid_sigma"
                record["validation"]["errors"].extend([f"canonical_schema:{e.message}" for e in schema_errors])
            for e in record["validation"]["errors"]:
                structural_error_counts[e.split(":", 1)[0]] += 1
            for w in record["validation"]["warnings"]:
                warning_counts[w.split(":", 1)[0]] += 1

            status_counts[str(record.get("status"))] += 1
            product_counts[str(record["logsource"].get("product"))] += 1
            category_counts[str(record["logsource"].get("category"))] += 1

            active_source = source_root in ACTIVE_ROOTS
            active_status = str(record.get("status") or "").lower() not in {"deprecated", "unsupported"}
            if active_source and active_status and record["validation"]["sigma_valid"]:
                accepted.append(record)
                logic_hash = normalized_logic_hash(record["logsource"], {**record["detection"], "condition": record["condition"]})
                logic_groups[logic_hash].append(record)
            else:
                if not active_source and record["validation"]["status"] == "valid":
                    record["validation"]["status"] = "quarantined"
                    record["validation"]["warnings"].append(f"non_core_source_root:{source_root}")
                elif not active_status and record["validation"]["status"] == "valid":
                    record["validation"]["status"] = "quarantined"
                    record["validation"]["warnings"].append(f"inactive_rule_status:{record.get('status')}")
                quarantined.append(record)
            all_records.append(record)

    duplicate_rows: list[dict[str, Any]] = []
    duplicate_group_count = 0
    duplicate_member_count = 0
    for logic_hash, members in logic_groups.items():
        if len(members) < 2:
            continue
        duplicate_group_count += 1
        duplicate_member_count += len(members)
        group_id = "logic-sha256:" + logic_hash[:24]
        for member in members:
            member["duplicate_group_id"] = group_id
            member["split_group_id"] = group_id
            duplicate_rows.append({
                "duplicate_group_id": group_id,
                "rule_id": member["rule_id"],
                "title": member["title"],
                "source_file": member["lineage"]["source_file"],
            })

    write_jsonl(out / "sigma_rules_valid.jsonl", accepted)
    write_jsonl(out / "sigma_rules_quarantined.jsonl", quarantined)
    write_jsonl(out / "sigma_rules_all.jsonl", all_records)

    with (out / "sigma_rule_attack_mapping.csv").open("w", newline="", encoding="utf-8") as f:
        fields = ["rule_id", "title", "technique_id", "resolution_status", "source_file"]
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for record in accepted:
            for tid in record["attack_techniques"]:
                resolution = "active" if tid in active_attack_ids else "inactive" if tid in inactive_attack_ids else "unknown"
                writer.writerow({
                    "rule_id": record["rule_id"],
                    "title": record["title"],
                    "technique_id": tid,
                    "resolution_status": resolution,
                    "source_file": record["lineage"]["source_file"],
                })

    with (out / "sigma_rule_field_inventory.csv").open("w", newline="", encoding="utf-8") as f:
        fields = ["rule_id", "title", "product", "category", "field", "source_file"]
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for record in accepted:
            for field in record["required_fields"]:
                writer.writerow({
                    "rule_id": record["rule_id"],
                    "title": record["title"],
                    "product": record["logsource"].get("product"),
                    "category": record["logsource"].get("category"),
                    "field": field,
                    "source_file": record["lineage"]["source_file"],
                })

    with (out / "sigma_rule_modifier_inventory.csv").open("w", newline="", encoding="utf-8") as f:
        fields = ["rule_id", "modifier", "source_file"]
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for record in accepted:
            for modifier in record["modifiers"]:
                writer.writerow({"rule_id": record["rule_id"], "modifier": modifier, "source_file": record["lineage"]["source_file"]})

    with (out / "sigma_duplicate_groups.csv").open("w", newline="", encoding="utf-8") as f:
        fields = ["duplicate_group_id", "rule_id", "title", "source_file"]
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(duplicate_rows)

    attack_mapped = sum(bool(r["attack_techniques"]) for r in accepted)
    unknown_tag_occurrences = sum(
        1 for r in accepted for tid in r["attack_techniques"] if tid not in active_attack_ids and tid not in inactive_attack_ids
    )
    summary = {
        "repository_origin": sigma_manifest.get("origin"),
        "repository_commit": commit,
        "yaml_files_discovered": len(yaml_paths),
        "documents_parsed": len(all_records),
        "accepted_core_rules": len(accepted),
        "quarantined_records": len(quarantined),
        "file_parse_error_count": len(file_parse_errors),
        "file_parse_errors": file_parse_errors[:100],
        "rules_with_attack_mapping": attack_mapped,
        "rules_without_attack_mapping": len(accepted) - attack_mapped,
        "unique_active_attack_techniques_mapped": len({tid for r in accepted for tid in r["attack_techniques"] if tid in active_attack_ids}),
        "unknown_attack_tag_occurrences": unknown_tag_occurrences,
        "duplicate_logic_groups": duplicate_group_count,
        "duplicate_logic_members": duplicate_member_count,
        "source_root_file_counts": dict(sorted(root_counts.items())),
        "status_counts": dict(status_counts.most_common()),
        "product_counts": dict(product_counts.most_common()),
        "category_counts": dict(category_counts.most_common()),
        "structural_error_counts": dict(structural_error_counts.most_common()),
        "warning_counts": dict(warning_counts.most_common()),
        "validation_scope": "YAML parsing, canonical structural checks, ATT&CK tag resolution, and JSON Schema validation. pySigma semantic validation and backend compilation are not yet included.",
        "generated_at": ingested_at,
    }
    (out / "sigma_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
