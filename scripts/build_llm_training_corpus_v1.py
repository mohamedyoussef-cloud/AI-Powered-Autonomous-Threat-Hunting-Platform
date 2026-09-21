#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

import yaml
from sigma.rule import SigmaRule


SYSTEM_PROMPT = (
    "You are a detection-engineering model that generates exactly one Sigma rule. "
    "Use the supplied detection intent, ATT&CK grounding, and Sigma logsource constraints. "
    "Return YAML only. Do not return SIEM-specific query syntax or explanatory prose."
)

TECHNIQUE_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            row["_line_number"] = line_number
            rows.append(row)
    return rows


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as f:
        for row in rows:
            f.write(canonical_json(row) + "\n")


def split_attack_tags(tags: list[str]) -> tuple[list[str], list[str]]:
    techniques: list[str] = []
    tactics: list[str] = []
    for tag in tags:
        tag_s = str(tag).strip()
        match = TECHNIQUE_RE.match(tag_s)
        if match:
            techniques.append(match.group(1).upper())
        elif tag_s.lower().startswith("attack."):
            tactics.append(tag_s.split(".", 1)[1])
    return sorted(set(techniques)), sorted(set(tactics))


def build_user_prompt(doc: dict[str, Any]) -> str:
    title = str(doc.get("title") or "").strip()
    description = str(doc.get("description") or "").strip()
    logsource = doc.get("logsource") or {}
    level = doc.get("level")
    falsepositives = doc.get("falsepositives") or []
    tags = [str(x) for x in (doc.get("tags") or [])]
    techniques, tactics = split_attack_tags(tags)

    context = {
        "detection_intent": {
            "title": title,
            "description": description,
        },
        "attack_grounding": {
            "technique_ids": techniques,
            "tactics": tactics,
        },
        "logsource": logsource,
        "severity": level,
        "known_false_positives": falsepositives,
    }

    return (
        "Generate one Sigma rule for the following grounded detection context.\n\n"
        + json.dumps(context, ensure_ascii=False, indent=2)
        + "\n\nRequirements:\n"
        "- Preserve the supplied detection intent and ATT&CK grounding.\n"
        "- Preserve the supplied Sigma logsource constraints.\n"
        "- Produce a complete Sigma rule in YAML.\n"
        "- Return YAML only."
    )


def load_source_rule(
    sigma_root: Path,
    manifest_row: dict[str, Any],
) -> tuple[dict[str, Any], str, str]:
    source_path = sigma_root / str(manifest_row["source_path"])
    if not source_path.exists():
        raise RuntimeError(f"Missing source rule: {source_path}")

    raw_bytes = source_path.read_bytes()
    raw_sha = sha256_bytes(raw_bytes)
    expected_sha = str(manifest_row["rule_sha256"])
    if raw_sha != expected_sha:
        raise RuntimeError(
            f"Source hash mismatch for {manifest_row['source_path']}: "
            f"expected={expected_sha} actual={raw_sha}"
        )

    raw_text = raw_bytes.decode("utf-8")
    docs = [d for d in yaml.safe_load_all(raw_text) if d is not None]
    if len(docs) != 1 or not isinstance(docs[0], dict):
        raise RuntimeError(
            f"Expected one mapping document: {manifest_row['source_path']}"
        )

    doc = docs[0]
    parsed = SigmaRule.from_dict(doc)
    parse_errors = list(getattr(parsed, "errors", []) or [])
    if parse_errors:
        raise RuntimeError(
            f"pySigma parse errors in selected rule {manifest_row['source_path']}: "
            + "; ".join(str(x) for x in parse_errors)
        )

    return doc, raw_text.rstrip() + "\n", raw_sha


def build_example(
    split: str,
    row: dict[str, Any],
    sigma_root: Path,
) -> dict[str, Any]:
    doc, target_yaml, raw_sha = load_source_rule(sigma_root, row)

    user_prompt = build_user_prompt(doc)
    example_id = "sigma_" + sha256_text(
        f"{row['source_commit']}:{row['rule_key']}"
    )[:20]

    attack_tags = [str(x) for x in (doc.get("tags") or []) if str(x).lower().startswith("attack.")]
    technique_ids, tactics = split_attack_tags(attack_tags)

    return {
        "example_id": example_id,
        "split": split,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
            {"role": "assistant", "content": target_yaml},
        ],
        "conditioning": {
            "title": doc.get("title"),
            "description": doc.get("description"),
            "attack_technique_ids": technique_ids,
            "attack_tactics": tactics,
            "logsource": doc.get("logsource") or {},
            "level": doc.get("level"),
            "falsepositives": doc.get("falsepositives") or [],
        },
        "provenance": {
            "source_id": row["source_id"],
            "source_commit": row["source_commit"],
            "source_path": row["source_path"],
            "source_rule_id": row.get("rule_id"),
            "source_rule_sha256": raw_sha,
            "license": row["license"],
            "author": row.get("author"),
            "status": row.get("status"),
            "family_id": row["family_id"],
            "semantic_fingerprint": row["semantic_fingerprint"],
        },
    }


def validate_cross_split(
    examples_by_split: dict[str, list[dict[str, Any]]]
) -> dict[str, int]:
    dimensions = {
        "example_id": lambda x: x["example_id"],
        "source_rule_id": lambda x: x["provenance"].get("source_rule_id"),
        "source_rule_sha256": lambda x: x["provenance"]["source_rule_sha256"],
        "family_id": lambda x: x["provenance"]["family_id"],
        "semantic_fingerprint": lambda x: x["provenance"]["semantic_fingerprint"],
    }

    result: dict[str, int] = {}

    for name, getter in dimensions.items():
        sets: dict[str, set[str]] = {}
        for split, examples in examples_by_split.items():
            values = {
                str(v)
                for e in examples
                if (v := getter(e)) not in (None, "")
            }
            sets[split] = values

        overlaps = (
            (sets["train"] & sets["validation"])
            | (sets["train"] & sets["test"])
            | (sets["validation"] & sets["test"])
        )
        result[f"cross_split_{name}_overlap"] = len(overlaps)

    return result


def schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "llm_sigma_training_example_v1",
        "title": "LLM Sigma Training Example",
        "type": "object",
        "required": [
            "example_id",
            "split",
            "messages",
            "conditioning",
            "provenance",
        ],
        "properties": {
            "example_id": {"type": "string", "minLength": 1},
            "split": {
                "type": "string",
                "enum": ["train", "validation", "test"],
            },
            "messages": {
                "type": "array",
                "minItems": 3,
                "maxItems": 3,
                "prefixItems": [
                    {
                        "type": "object",
                        "required": ["role", "content"],
                        "properties": {
                            "role": {"const": "system"},
                            "content": {"type": "string", "minLength": 1},
                        },
                    },
                    {
                        "type": "object",
                        "required": ["role", "content"],
                        "properties": {
                            "role": {"const": "user"},
                            "content": {"type": "string", "minLength": 1},
                        },
                    },
                    {
                        "type": "object",
                        "required": ["role", "content"],
                        "properties": {
                            "role": {"const": "assistant"},
                            "content": {"type": "string", "minLength": 1},
                        },
                    },
                ],
            },
            "conditioning": {"type": "object"},
            "provenance": {
                "type": "object",
                "required": [
                    "source_id",
                    "source_commit",
                    "source_path",
                    "source_rule_sha256",
                    "license",
                    "family_id",
                    "semantic_fingerprint",
                ],
            },
        },
        "additionalProperties": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build reproducible chat-format LLM Sigma training corpus."
    )
    parser.add_argument("--selection-dir", type=Path, required=True)
    parser.add_argument("--sigma-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    selection_dir = args.selection_dir.resolve()
    sigma_root = args.sigma_root.resolve()
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    manifest_paths = {
        "train": selection_dir / "train_manifest_v1.jsonl",
        "validation": selection_dir / "validation_manifest_v1.jsonl",
        "test": selection_dir / "test_manifest_v1.jsonl",
    }

    examples_by_split: dict[str, list[dict[str, Any]]] = {}
    source_commit_values: set[str] = set()
    source_license_values: set[str] = set()
    status_counts = Counter()
    technique_tagged_counts = Counter()

    for split, manifest_path in manifest_paths.items():
        rows = read_jsonl(manifest_path)
        examples: list[dict[str, Any]] = []

        for row in rows:
            if row.get("split") != split:
                raise RuntimeError(
                    f"Manifest split mismatch in {manifest_path}: "
                    f"line {row['_line_number']}"
                )
            if row.get("selected_for_gold") is not True:
                raise RuntimeError(
                    f"Non-gold record found in {manifest_path}: "
                    f"line {row['_line_number']}"
                )

            source_commit_values.add(str(row["source_commit"]))
            source_license_values.add(str(row["license"]))
            status_counts[str(row.get("status"))] += 1

            example = build_example(split, row, sigma_root)
            if example["conditioning"]["attack_technique_ids"]:
                technique_tagged_counts[split] += 1
            examples.append(example)

        examples_by_split[split] = examples

    leakage = validate_cross_split(examples_by_split)
    if any(leakage.values()):
        raise RuntimeError(f"Cross-split leakage detected: {leakage}")

    expected_counts = {"train": 2347, "validation": 274, "test": 290}
    actual_counts = {
        split: len(examples)
        for split, examples in examples_by_split.items()
    }
    if actual_counts != expected_counts:
        raise RuntimeError(
            f"Selected population changed: expected={expected_counts} actual={actual_counts}"
        )

    for split, examples in examples_by_split.items():
        write_jsonl(output_dir / f"{split}.jsonl", examples)

    write_json(output_dir / "training_example_schema_v1.json", schema())

    file_hashes = {}
    for name in ("train.jsonl", "validation.jsonl", "test.jsonl"):
        path = output_dir / name
        file_hashes[name] = sha256_bytes(path.read_bytes())

    summary = {
        "dataset": "LLM Sigma Supervised Training Corpus",
        "version": "1.0",
        "status": "PASS",
        "format": "chat_messages",
        "source_commits": sorted(source_commit_values),
        "licenses": sorted(source_license_values),
        "example_counts": actual_counts,
        "total_examples": sum(actual_counts.values()),
        "source_status_counts": dict(status_counts),
        "examples_with_attack_technique_tags": dict(technique_tagged_counts),
        "conditioning_policy": {
            "included": [
                "title",
                "description",
                "ATT&CK tags",
                "logsource",
                "level",
                "falsepositives",
            ],
            "excluded_from_prompt": [
                "detection",
                "condition",
                "fields",
                "Sigma source identifiers",
                "author",
                "license metadata",
                "project internal baseline Sigma",
            ],
            "production_note": (
                "This corpus trains semantic-context-to-Sigma generation. "
                "Project Detection Plans remain the governed production input contract "
                "and are not fabricated from SigmaHQ metadata."
            ),
        },
        "target_policy": {
            "assistant_target": "exact SigmaHQ YAML source rule",
            "target_normalization": "none",
            "pysigma_parse_required": True,
        },
        "leakage_audit": leakage,
        "split_policy": {
            "test_split_frozen": True,
            "family_grouping_inherited_from": "../supervised_sigma_v1",
        },
        "file_sha256": file_hashes,
    }

    write_json(output_dir / "dataset_build_summary_v1.json", summary)

    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
