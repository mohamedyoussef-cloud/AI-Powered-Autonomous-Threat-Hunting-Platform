#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import yaml
from sigma.rule import SigmaRule
from sigma.validation import SigmaValidator
from sigma.validators.core import validators


SOURCE_ID = "sigmahq_rules"
LICENSE = "DRL-1.1"
ALLOWED_STATUSES = {"stable", "test"}
BLOCKING_SEVERITIES = {"critical", "high", "medium", "error"}
NEAR_DUP_THRESHOLD = 0.92
NEAR_DUP_MIN_TOKENS = 8
SPLIT_SALT = "llm-dataset-selection-v1"
EXPECTED_RATIOS = {"train": 0.80, "validation": 0.10, "test": 0.10}


def json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [json_safe(v) for v in value]
    if hasattr(value, "isoformat"):
        try:
            return value.isoformat()
        except Exception:
            pass
    return value


def canonical_json(value: Any) -> str:
    return json.dumps(
        json_safe(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def read_one_yaml(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        raw = path.read_text(encoding="utf-8")
        docs = [d for d in yaml.safe_load_all(raw) if d is not None]
    except Exception as exc:
        return None, f"yaml_load_failed:{type(exc).__name__}:{exc}"

    if len(docs) != 1:
        return None, f"expected_one_yaml_document_found:{len(docs)}"
    if not isinstance(docs[0], dict):
        return None, "yaml_root_not_mapping"
    return docs[0], None


def issue_severity(issue: Any) -> str:
    severity = getattr(issue, "severity", None)
    if severity is None:
        return ""
    name = getattr(severity, "name", None)
    return str(name or severity).lower()


def issue_type(issue: Any) -> str:
    return type(issue).__name__


def issue_message(issue: Any) -> str:
    try:
        return str(issue)
    except Exception:
        return repr(issue)


def rule_key(doc: dict[str, Any], rel_path: str) -> str:
    rid = doc.get("id")
    return str(rid).strip() if rid else f"path:{rel_path.lower()}"


def semantic_fingerprint(doc: dict[str, Any]) -> str:
    semantic = {
        "logsource": doc.get("logsource") or {},
        "detection": doc.get("detection") or {},
    }
    return sha256_text(canonical_json(semantic))


def logsource_block(doc: dict[str, Any]) -> str:
    ls = doc.get("logsource") or {}
    if not isinstance(ls, dict):
        return "<invalid-logsource>"
    return "|".join(
        str(ls.get(k) or "").strip().lower()
        for k in ("product", "category", "service")
    )


TOKEN_RE = re.compile(r"[A-Za-z0-9_./\\:@$%+-]+")


def semantic_tokens(doc: dict[str, Any]) -> set[str]:
    text = canonical_json(
        {
            "logsource": doc.get("logsource") or {},
            "detection": doc.get("detection") or {},
        }
    ).lower()
    return set(TOKEN_RE.findall(text))


def attack_tags(doc: dict[str, Any]) -> list[str]:
    tags = doc.get("tags") or []
    if not isinstance(tags, list):
        return []
    return sorted(
        {
            str(t)
            for t in tags
            if str(t).lower().startswith("attack.")
        }
    )


class UnionFind:
    def __init__(self, keys: list[str]):
        self.parent = {k: k for k in keys}
        self.rank = {k: 0 for k in keys}

    def find(self, x: str) -> str:
        p = self.parent[x]
        if p != x:
            self.parent[x] = self.find(p)
        return self.parent[x]

    def union(self, a: str, b: str) -> None:
        ra = self.find(a)
        rb = self.find(b)
        if ra == rb:
            return
        if self.rank[ra] < self.rank[rb]:
            ra, rb = rb, ra
        self.parent[rb] = ra
        if self.rank[ra] == self.rank[rb]:
            self.rank[ra] += 1


def split_for_group(group_anchor: str) -> str:
    h = hashlib.sha256(f"{SPLIT_SALT}:{group_anchor}".encode("utf-8")).digest()
    x = int.from_bytes(h[:8], "big") / float(2**64)
    if x < EXPECTED_RATIOS["test"]:
        return "test"
    if x < EXPECTED_RATIOS["test"] + EXPECTED_RATIOS["validation"]:
        return "validation"
    return "train"


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(json_safe(value), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(canonical_json(row) + "\n")


def main() -> None:
    ap = argparse.ArgumentParser(
        description="LLM dataset selection: build leakage-resistant SigmaHQ train/validation/test selection manifests."
    )
    ap.add_argument("--sigma-root", type=Path, required=True)
    ap.add_argument("--output-dir", type=Path, required=True)
    ap.add_argument("--source-commit", required=True)
    args = ap.parse_args()

    sigma_root = args.sigma_root.resolve()
    rules_root = sigma_root / "rules"
    out = args.output_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)

    files = sorted(
        list(rules_root.rglob("*.yml")) + list(rules_root.rglob("*.yaml"))
    )
    if not files:
        raise RuntimeError(f"No Sigma rules found under {rules_root}")

    validator = SigmaValidator(validators.values())

    inventory: list[dict[str, Any]] = []
    docs_by_key: dict[str, dict[str, Any]] = {}
    relpath_by_key: dict[str, str] = {}
    filehash_by_key: dict[str, str] = {}
    issues_by_key: dict[str, list[dict[str, str]]] = {}
    excluded_reasons: dict[str, list[str]] = defaultdict(list)

    status_counts = Counter()
    parse_status_counts = Counter()
    issue_severity_counts = Counter()
    issue_type_counts = Counter()

    for path in files:
        rel = path.relative_to(sigma_root).as_posix()
        raw = path.read_text(encoding="utf-8", errors="replace")
        raw_sha = sha256_text(raw)

        doc, yaml_error = read_one_yaml(path)
        if yaml_error:
            key = f"path:{rel.lower()}"
            inventory.append(
                {
                    "source_id": SOURCE_ID,
                    "source_commit": args.source_commit,
                    "license": LICENSE,
                    "source_path": rel,
                    "rule_key": key,
                    "rule_sha256": raw_sha,
                    "status": None,
                    "parse_status": "yaml_failed",
                    "parse_errors": [yaml_error],
                    "validation_issues": [],
                    "selected_for_gold": False,
                    "exclusion_reasons": ["yaml_failed"],
                }
            )
            parse_status_counts["yaml_failed"] += 1
            continue

        key = rule_key(doc, rel)
        if key in docs_by_key:
            key = f"{key}#path:{rel.lower()}"

        docs_by_key[key] = doc
        relpath_by_key[key] = rel
        filehash_by_key[key] = raw_sha

        status = str(doc.get("status") or "<MISSING>").strip().lower()
        status_counts[status] += 1

        parse_status = "parsed_clean"
        parse_errors: list[str] = []
        parsed_rule = None

        try:
            parsed_rule = SigmaRule.from_dict(doc)
            object_errors = list(getattr(parsed_rule, "errors", []) or [])
            parse_errors = [issue_message(e) for e in object_errors]
            if parse_errors:
                parse_status = "parsed_with_parse_errors"
        except Exception as exc:
            parse_status = "parse_failed"
            parse_errors = [f"{type(exc).__name__}:{exc}"]

        parse_status_counts[parse_status] += 1

        rule_issues: list[dict[str, str]] = []
        if parsed_rule is not None:
            try:
                for issue in validator.validate_rule(parsed_rule) or []:
                    sev = issue_severity(issue)
                    typ = issue_type(issue)
                    msg = issue_message(issue)
                    rule_issues.append(
                        {"severity": sev, "type": typ, "message": msg}
                    )
                    issue_severity_counts[sev or "<none>"] += 1
                    issue_type_counts[typ] += 1
            except Exception as exc:
                rule_issues.append(
                    {
                        "severity": "error",
                        "type": "validator_exception",
                        "message": f"{type(exc).__name__}:{exc}",
                    }
                )
                issue_severity_counts["error"] += 1
                issue_type_counts["validator_exception"] += 1

        issues_by_key[key] = rule_issues

        if status not in ALLOWED_STATUSES:
            excluded_reasons[key].append(f"status_not_gold:{status}")
        if parse_status != "parsed_clean":
            excluded_reasons[key].append(parse_status)

        blocking = sorted(
            {
                x["severity"]
                for x in rule_issues
                if x["severity"] in BLOCKING_SEVERITIES
            }
        )
        if blocking:
            excluded_reasons[key].append(
                "blocking_validation_severity:" + ",".join(blocking)
            )

    try:
        final_issues = list(validator.finalize() or [])
    except Exception as exc:
        final_issues = [f"validator_finalize_failed:{type(exc).__name__}:{exc}"]

    selected_keys = sorted(
        k for k in docs_by_key if not excluded_reasons.get(k)
    )

    # Family construction:
    # 1) explicit Sigma `related` links
    # 2) exact logsource+detection semantic fingerprints
    # 3) high-similarity near duplicates within same logsource block
    uf = UnionFind(selected_keys)
    selected_set = set(selected_keys)

    id_to_key: dict[str, str] = {}
    for k in selected_keys:
        rid = docs_by_key[k].get("id")
        if rid:
            id_to_key[str(rid).strip()] = k

    related_edges = 0
    for k in selected_keys:
        related = docs_by_key[k].get("related") or []
        if not isinstance(related, list):
            continue
        for item in related:
            if not isinstance(item, dict):
                continue
            rid = item.get("id")
            if rid is None:
                continue
            other = id_to_key.get(str(rid).strip())
            if other and other in selected_set:
                uf.union(k, other)
                related_edges += 1

    fp_to_first: dict[str, str] = {}
    exact_semantic_edges = 0
    semantic_fp_by_key: dict[str, str] = {}
    for k in selected_keys:
        fp = semantic_fingerprint(docs_by_key[k])
        semantic_fp_by_key[k] = fp
        if fp in fp_to_first:
            uf.union(k, fp_to_first[fp])
            exact_semantic_edges += 1
        else:
            fp_to_first[fp] = k

    block_to_keys: dict[str, list[str]] = defaultdict(list)
    tokens_by_key: dict[str, set[str]] = {}
    for k in selected_keys:
        block_to_keys[logsource_block(docs_by_key[k])].append(k)
        tokens_by_key[k] = semantic_tokens(docs_by_key[k])

    near_duplicate_edges = 0
    near_duplicate_pairs: list[dict[str, Any]] = []
    for block, keys in sorted(block_to_keys.items()):
        keys = sorted(keys)
        for i in range(len(keys)):
            a = keys[i]
            ta = tokens_by_key[a]
            if len(ta) < NEAR_DUP_MIN_TOKENS:
                continue
            for j in range(i + 1, len(keys)):
                b = keys[j]
                if semantic_fp_by_key[a] == semantic_fp_by_key[b]:
                    continue
                tb = tokens_by_key[b]
                if len(tb) < NEAR_DUP_MIN_TOKENS:
                    continue
                size_ratio = min(len(ta), len(tb)) / max(len(ta), len(tb))
                if size_ratio < NEAR_DUP_THRESHOLD:
                    continue
                union = ta | tb
                if not union:
                    continue
                score = len(ta & tb) / len(union)
                if score >= NEAR_DUP_THRESHOLD:
                    uf.union(a, b)
                    near_duplicate_edges += 1
                    near_duplicate_pairs.append(
                        {
                            "rule_a": a,
                            "rule_b": b,
                            "logsource_block": block,
                            "jaccard": round(score, 6),
                        }
                    )

    groups: dict[str, list[str]] = defaultdict(list)
    for k in selected_keys:
        groups[uf.find(k)].append(k)

    family_id_by_key: dict[str, str] = {}
    split_by_key: dict[str, str] = {}
    family_rows: list[dict[str, Any]] = []

    for members in sorted((sorted(v) for v in groups.values()), key=lambda x: x[0]):
        anchor = members[0]
        family_id = "fam_" + sha256_text("\n".join(members))[:16]
        split = split_for_group(anchor)
        for k in members:
            family_id_by_key[k] = family_id
            split_by_key[k] = split
        family_rows.append(
            {
                "family_id": family_id,
                "family_anchor": anchor,
                "split": split,
                "member_count": len(members),
                "members": members,
            }
        )

    # Build full inventory.
    inventory_by_key = {row["rule_key"]: row for row in inventory}
    for k, doc in docs_by_key.items():
        status = str(doc.get("status") or "<MISSING>").strip().lower()
        issues = issues_by_key.get(k, [])
        selected = k in selected_set
        row = {
            "source_id": SOURCE_ID,
            "source_commit": args.source_commit,
            "license": LICENSE,
            "source_path": relpath_by_key[k],
            "rule_key": k,
            "rule_id": doc.get("id"),
            "rule_sha256": filehash_by_key[k],
            "title": doc.get("title"),
            "status": status,
            "author": doc.get("author"),
            "attack_tags": attack_tags(doc),
            "logsource": doc.get("logsource") or {},
            "semantic_fingerprint": semantic_fp_by_key.get(k),
            "parse_status": (
                "parsed_clean"
                if not any(
                    r in {"parse_failed", "parsed_with_parse_errors"}
                    for r in excluded_reasons.get(k, [])
                )
                else next(
                    (
                        r
                        for r in excluded_reasons.get(k, [])
                        if r in {"parse_failed", "parsed_with_parse_errors"}
                    ),
                    "parsed_clean",
                )
            ),
            "validation_issues": issues,
            "selected_for_gold": selected,
            "exclusion_reasons": excluded_reasons.get(k, []),
            "family_id": family_id_by_key.get(k),
            "split": split_by_key.get(k),
        }
        inventory_by_key[k] = row

    inventory_rows = sorted(
        inventory_by_key.values(),
        key=lambda r: str(r.get("source_path") or ""),
    )

    selected_rows = [
        r for r in inventory_rows if r.get("selected_for_gold")
    ]
    selected_rows.sort(key=lambda r: (r["split"], r["source_path"]))

    split_rows = {
        name: [r for r in selected_rows if r["split"] == name]
        for name in ("train", "validation", "test")
    }

    # Leakage assertions.
    family_split_map: dict[str, set[str]] = defaultdict(set)
    fp_split_map: dict[str, set[str]] = defaultdict(set)
    id_split_map: dict[str, set[str]] = defaultdict(set)

    for r in selected_rows:
        family_split_map[r["family_id"]].add(r["split"])
        fp_split_map[r["semantic_fingerprint"]].add(r["split"])
        if r.get("rule_id"):
            id_split_map[str(r["rule_id"])].add(r["split"])

    cross_family = [k for k, v in family_split_map.items() if len(v) > 1]
    cross_fp = [k for k, v in fp_split_map.items() if len(v) > 1]
    cross_id = [k for k, v in id_split_map.items() if len(v) > 1]

    near_cross = []
    for pair in near_duplicate_pairs:
        a = pair["rule_a"]
        b = pair["rule_b"]
        if split_by_key[a] != split_by_key[b]:
            near_cross.append(pair)

    if cross_family or cross_fp or cross_id or near_cross:
        raise RuntimeError(
            "Leakage invariant failed: "
            f"family={len(cross_family)}, semantic={len(cross_fp)}, "
            f"rule_id={len(cross_id)}, near_duplicate={len(near_cross)}"
        )

    exclusion_counts = Counter(
        reason
        for reasons in excluded_reasons.values()
        for reason in reasons
    )

    split_counts = {k: len(v) for k, v in split_rows.items()}
    split_family_counts = Counter(row["split"] for row in family_rows)

    policy = {
        "task": "LLM Train / Validation / Test Dataset Selection",
        "version": "1.0",
        "source": {
            "source_id": SOURCE_ID,
            "repository": "SigmaHQ/sigma",
            "source_commit": args.source_commit,
            "license": LICENSE,
            "rules_root": "rules/",
        },
        "gold_selection": {
            "allowed_statuses": sorted(ALLOWED_STATUSES),
            "excluded_statuses": ["experimental"],
            "require_pysigma_parsed_clean": True,
            "blocking_validation_severities": sorted(BLOCKING_SEVERITIES),
            "internal_project_baseline_sigma_is_gold": False,
        },
        "split_policy": {
            "ratios": EXPECTED_RATIOS,
            "deterministic_salt": SPLIT_SALT,
            "unit_of_split": "rule_family",
            "family_links": [
                "Sigma related IDs",
                "exact logsource+detection semantic fingerprint",
                f"near-duplicate Jaccard >= {NEAR_DUP_THRESHOLD} within same logsource block",
            ],
            "test_set_policy": "Freeze after LLM dataset selection for all subsequent tuning/evaluation.",
        },
        "target_materialization": {
            "raw_rule_bodies_copied_into_dataset_selection_manifests": False,
            "outputs_are_selection_provenance_manifests": True,
            "training_examples_materialized_in_next dataset-preparation stage": True,
        },
    }

    summary = {
        "task": policy["task"],
        "version": "1.0",
        "status": "PASS",
        "source_commit": args.source_commit,
        "total_rule_files": len(files),
        "status_counts": dict(status_counts),
        "parse_status_counts": dict(parse_status_counts),
        "validation_issue_severity_counts": dict(issue_severity_counts),
        "top_validation_issue_types": issue_type_counts.most_common(20),
        "validator_finalize_issue_count": len(final_issues),
        "selected_gold_rules": len(selected_rows),
        "excluded_rules": len(files) - len(selected_rows),
        "exclusion_reason_counts": dict(exclusion_counts),
        "family_count": len(family_rows),
        "related_edges": related_edges,
        "exact_semantic_duplicate_edges": exact_semantic_edges,
        "near_duplicate_edges": near_duplicate_edges,
        "split_rule_counts": split_counts,
        "split_family_counts": dict(split_family_counts),
        "split_ratios_actual": {
            k: (v / len(selected_rows) if selected_rows else 0.0)
            for k, v in split_counts.items()
        },
        "leakage_audit": {
            "cross_split_family_overlap": len(cross_family),
            "cross_split_semantic_fingerprint_overlap": len(cross_fp),
            "cross_split_rule_id_overlap": len(cross_id),
            "cross_split_near_duplicate_overlap": len(near_cross),
        },
        "invariants": {
            "internal_baseline_sigma_used_as_gold": False,
            "experimental_sigmahq_used_as_gold": False,
            "test_split_frozen": True,
            "all_selected_rules_have_provenance": True,
        },
    }

    write_json(out / "dataset_policy_v1.json", policy)
    write_json(out / "dataset_selection_summary_v1.json", summary)
    write_jsonl(out / "sigmahq_inventory_v1.jsonl", inventory_rows)
    write_jsonl(out / "sigmahq_family_index_v1.jsonl", family_rows)
    write_jsonl(out / "sigmahq_near_duplicate_pairs_v1.jsonl", near_duplicate_pairs)
    write_jsonl(out / "train_manifest_v1.jsonl", split_rows["train"])
    write_jsonl(out / "validation_manifest_v1.jsonl", split_rows["validation"])
    write_jsonl(out / "test_manifest_v1.jsonl", split_rows["test"])

    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
