#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import time
from collections import Counter
from pathlib import Path

import torch
import yaml
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from sigma.rule import SigmaRule
from sigma.validators.core import validators


ATTACK_TECHNIQUE_RE = re.compile(r"^attack\.t\d{4}(?:\.\d{3})?$", re.IGNORECASE)


def read_jsonl(path):
    return [
        json.loads(line)
        for line in Path(path).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def append_jsonl(path, row):
    with Path(path).open("a", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
        f.flush()
        os.fsync(f.fileno())


def sha256_file(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_yaml_mapping(text):
    try:
        obj = yaml.safe_load(text)
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"
    if not isinstance(obj, dict):
        return None, "top_level_not_mapping"
    return obj, None


def normalize_tags(obj):
    if not isinstance(obj, dict):
        return set()
    tags = obj.get("tags", [])
    if not isinstance(tags, list):
        return set()
    return {str(tag).strip().lower() for tag in tags}


def attack_techniques(obj):
    return {
        tag for tag in normalize_tags(obj)
        if ATTACK_TECHNIQUE_RE.fullmatch(tag)
    }


def attack_tactics(obj):
    return {
        tag for tag in normalize_tags(obj)
        if tag.startswith("attack.") and not ATTACK_TECHNIQUE_RE.fullmatch(tag)
    }


def severity_name(issue):
    sev = getattr(issue, "severity", None)
    if sev is None:
        return "unknown"
    name = getattr(sev, "name", None)
    if name is not None:
        return str(name).lower()
    return str(sev).split(".")[-1].lower()


def normalize_issues(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    try:
        return list(value)
    except TypeError:
        return [value]


def pysigma_validate(raw_output):
    result = {
        "parse_valid": False,
        "parse_error": None,
        "validator_error_count": 0,
        "validator_errors": {},
        "issue_severity_counts": {},
        "issue_type_counts": {},
        "blocking_issue_count": 0,
        "pass_no_blocking_issues": False,
    }

    try:
        rule = SigmaRule.from_yaml(raw_output)
        result["parse_valid"] = True
    except Exception as exc:
        result["parse_error"] = f"{type(exc).__name__}: {exc}"
        return result

    severity_counts = Counter()
    type_counts = Counter()
    validator_errors = {}

    for validator_name, validator_entry in validators.items():
        try:
            validator = validator_entry() if isinstance(validator_entry, type) else validator_entry
            issues = normalize_issues(validator.validate(rule))
            for issue in issues:
                severity_counts[severity_name(issue)] += 1
                type_counts[type(issue).__name__] += 1
        except Exception as exc:
            validator_errors[validator_name] = f"{type(exc).__name__}: {exc}"

    blockers = sum(
        severity_counts.get(level, 0)
        for level in ("medium", "high", "error", "critical")
    )

    result["validator_error_count"] = len(validator_errors)
    result["validator_errors"] = validator_errors
    result["issue_severity_counts"] = dict(severity_counts)
    result["issue_type_counts"] = dict(type_counts)
    result["blocking_issue_count"] = blockers
    result["pass_no_blocking_issues"] = (
        result["parse_valid"]
        and len(validator_errors) == 0
        and blockers == 0
    )
    return result


def build_record(row, raw_output, new_tokens, elapsed, max_new_tokens):
    target_obj, target_error = safe_yaml_mapping(row["messages"][2]["content"])
    if target_obj is None:
        raise RuntimeError(
            f"{row['example_id']}: invalid gold target YAML: {target_error}"
        )

    generated_obj, yaml_error = safe_yaml_mapping(raw_output)
    py_result = pysigma_validate(raw_output)

    expected_techniques = attack_techniques(target_obj)
    generated_techniques = attack_techniques(generated_obj)
    expected_tactics = attack_tactics(target_obj)
    generated_tactics = attack_tactics(generated_obj)

    strict_yaml_only = (
        generated_obj is not None
        and "```" not in raw_output
        and "<think>" not in raw_output.lower()
        and "</think>" not in raw_output.lower()
    )

    return {
        "example_id": row["example_id"],
        "provenance": {
            "source_rule_id": row.get("provenance", {}).get("source_rule_id"),
            "source_path": row.get("provenance", {}).get("source_path"),
            "family_id": row.get("provenance", {}).get("family_id"),
        },
        "generation": {
            "new_tokens": int(new_tokens),
            "max_new_tokens_reached": int(new_tokens) >= max_new_tokens,
            "seconds": float(elapsed),
        },
        "format": {
            "strict_yaml_only": strict_yaml_only,
            "yaml_mapping_valid": generated_obj is not None,
            "yaml_error": yaml_error,
        },
        "pysigma": py_result,
        "semantic_alignment": {
            "expected_attack_techniques": sorted(expected_techniques),
            "generated_attack_techniques": sorted(generated_techniques),
            "attack_technique_exact": (
                generated_obj is not None
                and generated_techniques == expected_techniques
            ),
            "attack_technique_recall_complete": (
                generated_obj is not None
                and expected_techniques.issubset(generated_techniques)
            ),
            "expected_attack_tactics": sorted(expected_tactics),
            "generated_attack_tactics": sorted(generated_tactics),
            "attack_tactic_exact": (
                generated_obj is not None
                and generated_tactics == expected_tactics
            ),
            "logsource_exact": (
                generated_obj is not None
                and generated_obj.get("logsource") == target_obj.get("logsource")
            ),
            "level_exact": (
                generated_obj is not None
                and generated_obj.get("level") == target_obj.get("level")
            ),
        },
        "raw_output": raw_output,
    }


def metric(records, path):
    count = 0
    for record in records:
        value = record
        for key in path:
            value = value[key]
        count += int(bool(value))
    total = len(records)
    return {"count": count, "rate": count / total if total else 0.0}


def summarize(records, requested_population):
    severity_counts = Counter()
    issue_types = Counter()
    validator_error_total = 0
    total_seconds = 0.0
    max_token_hits = 0

    for record in records:
        severity_counts.update(record["pysigma"]["issue_severity_counts"])
        issue_types.update(record["pysigma"]["issue_type_counts"])
        validator_error_total += record["pysigma"]["validator_error_count"]
        total_seconds += float(record["generation"]["seconds"])
        max_token_hits += int(record["generation"]["max_new_tokens_reached"])

    total = len(records)
    return {
        "status": "PASS" if total == requested_population else "PARTIAL",
        "requested_population": requested_population,
        "evaluated_population": total,
        "metrics": {
            "strict_yaml_only": metric(records, ["format", "strict_yaml_only"]),
            "yaml_mapping_valid": metric(records, ["format", "yaml_mapping_valid"]),
            "pysigma_parse_valid": metric(records, ["pysigma", "parse_valid"]),
            "pysigma_pass_no_blocking_issues": metric(
                records, ["pysigma", "pass_no_blocking_issues"]
            ),
            "attack_technique_exact": metric(
                records, ["semantic_alignment", "attack_technique_exact"]
            ),
            "attack_technique_recall_complete": metric(
                records, ["semantic_alignment", "attack_technique_recall_complete"]
            ),
            "attack_tactic_exact": metric(
                records, ["semantic_alignment", "attack_tactic_exact"]
            ),
            "logsource_exact": metric(
                records, ["semantic_alignment", "logsource_exact"]
            ),
            "level_exact": metric(
                records, ["semantic_alignment", "level_exact"]
            ),
        },
        "validator_error_total": validator_error_total,
        "validator_issue_severity_counts": dict(severity_counts),
        "top_validator_issue_types": issue_types.most_common(20),
        "generation": {
            "total_seconds": total_seconds,
            "mean_seconds": total_seconds / total if total else 0.0,
            "max_new_tokens_reached_count": max_token_hits,
        },
    }


def main():
    ap = argparse.ArgumentParser(
        description="Deterministic resumable Sigma generation evaluation."
    )
    ap.add_argument("--model", required=True)
    ap.add_argument("--dataset", type=Path, required=True)
    ap.add_argument("--output-dir", type=Path, required=True)
    ap.add_argument("--adapter", type=Path)
    ap.add_argument("--max-new-tokens", type=int, default=2048)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--allow-test", action="store_true")
    args = ap.parse_args()

    if args.dataset.name.lower() == "test.jsonl" and not args.allow_test:
        raise RuntimeError(
            "Refusing frozen test evaluation without explicit --allow-test."
        )

    if not torch.cuda.is_available():
        raise RuntimeError("CUDA is required.")

    rows_all = read_jsonl(args.dataset)
    rows = rows_all[:args.limit] if args.limit is not None else rows_all
    if not rows:
        raise RuntimeError("Evaluation dataset is empty.")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    predictions_path = args.output_dir / "predictions.jsonl"
    summary_path = args.output_dir / "summary.json"

    existing = {}
    if predictions_path.exists():
        existing = {
            row["example_id"]: row
            for row in read_jsonl(predictions_path)
        }

    tokenizer = AutoTokenizer.from_pretrained(
        args.model,
        local_files_only=True,
    )
    if tokenizer.pad_token_id is None:
        tokenizer.pad_token = tokenizer.eos_token

    quant_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_use_double_quant=True,
        bnb_4bit_compute_dtype=torch.bfloat16,
    )

    model = AutoModelForCausalLM.from_pretrained(
        args.model,
        quantization_config=quant_config,
        device_map={"": 0},
        dtype=torch.bfloat16,
        local_files_only=True,
        low_cpu_mem_usage=True,
    )

    if args.adapter is not None:
        model = PeftModel.from_pretrained(
            model,
            str(args.adapter),
            is_trainable=False,
        )

    model.eval()
    model.config.use_cache = True

    print("PYSIGMA_VALIDATORS", len(validators))
    print("FULL_SPLIT_POPULATION", len(rows_all))
    print("REQUESTED_POPULATION", len(rows))
    print("ALREADY_COMPLETED", sum(r["example_id"] in existing for r in rows))
    print("ADAPTER", str(args.adapter) if args.adapter else "NONE_BASE_MODEL")
    print("MAX_NEW_TOKENS", args.max_new_tokens)
    print("SAMPLING", False)
    print("THINKING", False)
    print("OUTPUT_REPAIR", False)

    for position, row in enumerate(rows, start=1):
        example_id = row["example_id"]
        if example_id in existing:
            continue

        prompt = tokenizer.apply_chat_template(
            row["messages"][:2],
            tokenize=True,
            add_generation_prompt=True,
            enable_thinking=False,
        )

        input_ids = torch.tensor(
            [prompt["input_ids"]],
            dtype=torch.long,
            device="cuda:0",
        )
        attention_mask = torch.ones_like(input_ids)

        started = time.time()
        with torch.inference_mode():
            generated = model.generate(
                input_ids=input_ids,
                attention_mask=attention_mask,
                max_new_tokens=args.max_new_tokens,
                do_sample=False,
                use_cache=True,
                eos_token_id=tokenizer.eos_token_id,
                pad_token_id=tokenizer.pad_token_id,
            )
        elapsed = time.time() - started

        new_ids = generated[0, input_ids.shape[1]:]
        raw_output = tokenizer.decode(
            new_ids,
            skip_special_tokens=True,
        ).strip()

        record = build_record(
            row,
            raw_output,
            int(new_ids.numel()),
            elapsed,
            args.max_new_tokens,
        )
        append_jsonl(predictions_path, record)
        existing[example_id] = record

        if position == 1 or position % 1 == 0 or position == len(rows):
            completed = sum(r["example_id"] in existing for r in rows)
            print(
                "PROGRESS",
                f"{completed}/{len(rows)}",
                "LAST",
                example_id,
                "TOKENS",
                record["generation"]["new_tokens"],
                "PYSIGMA",
                record["pysigma"]["parse_valid"],
                "VALIDATOR_ERRORS",
                record["pysigma"]["validator_error_count"],
                "SECONDS",
                round(elapsed, 2),
            )

    ordered = [
        existing[row["example_id"]]
        for row in rows
        if row["example_id"] in existing
    ]

    summary = summarize(ordered, len(rows))
    summary.update(
        {
            "full_split_population": len(rows_all),
            "dataset": str(args.dataset.resolve()),
            "dataset_sha256": sha256_file(args.dataset),
            "base_model_snapshot": str(Path(args.model).resolve()),
            "adapter": (
                str(args.adapter.resolve())
                if args.adapter is not None
                else None
            ),
            "adapter_used": args.adapter is not None,
            "test_split_used": args.dataset.name.lower() == "test.jsonl",
            "sampling_enabled": False,
            "thinking_enabled": False,
            "output_repair_used": False,
            "max_new_tokens": args.max_new_tokens,
            "limit": args.limit,
        }
    )

    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print("EVALUATION_STATUS", summary["status"])
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
