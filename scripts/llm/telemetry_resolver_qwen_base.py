#!/usr/bin/env python3
import argparse
import hashlib
import json
import time
from pathlib import Path

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

SYSTEM_PROMPT = '''You are the telemetry-resolution component of an AI-powered autonomous threat-hunting platform.

Your task is semantic resolution only.

Rules:
1. The logical_source is authoritative.
2. You may select ONLY a sourcetype that appears in allowed_live_candidates.
3. Never invent, normalize, rewrite, or synthesize a sourcetype.
4. Live source examples and event counts are evidence, not proof of attack occurrence.
5. grounded_event_ids and technique_ids are context only.
6. If one live candidate is clearly semantically equivalent to the logical source, return MATCH.
7. If multiple candidates remain plausible, return AMBIGUOUS.
8. If no live candidate is semantically equivalent, return NO_MATCH.
9. Return exactly one JSON object and no prose, markdown, or code fences.

Required JSON schema:
{
  "decision": "MATCH|AMBIGUOUS|NO_MATCH",
  "selected_sourcetype": "exact allowed candidate string or null",
  "confidence": 0.0,
  "reason": "concise evidence-grounded explanation"
}
'''

def read_jsonl(path: Path):
    rows = []
    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception as e:
                raise RuntimeError(f"{path}:{line_no}: invalid JSON: {e}") from e
    return rows

def extract_json_object(text: str):
    s = text.strip()
    if s.startswith("```"):
        s = s.replace("```json", "").replace("```", "").strip()
    try:
        return json.loads(s)
    except Exception:
        pass
    start = s.find("{")
    if start < 0:
        return None
    depth = 0
    in_string = False
    escape = False
    for i in range(start, len(s)):
        ch = s[i]
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(s[start:i+1])
                except Exception:
                    return None
    return None

def validate_result(task, parsed):
    allowed = {x["sourcetype"] for x in task["allowed_live_candidates"]}
    errors = []

    if not isinstance(parsed, dict):
        return "INVALID_OUTPUT", ["NOT_JSON_OBJECT"]

    decision = parsed.get("decision")
    selected = parsed.get("selected_sourcetype")
    confidence = parsed.get("confidence")
    reason = parsed.get("reason")

    if decision not in {"MATCH", "AMBIGUOUS", "NO_MATCH"}:
        errors.append("INVALID_DECISION")

    if decision == "MATCH":
        if selected not in allowed:
            errors.append("SELECTED_SOURCETYPE_NOT_ALLOWED")
    else:
        if selected is not None:
            errors.append("NON_MATCH_SELECTED_SOURCETYPE_MUST_BE_NULL")

    if not isinstance(confidence, (int, float)) or isinstance(confidence, bool):
        errors.append("INVALID_CONFIDENCE_TYPE")
    elif not (0.0 <= float(confidence) <= 1.0):
        errors.append("CONFIDENCE_OUT_OF_RANGE")

    if not isinstance(reason, str) or not reason.strip():
        errors.append("MISSING_REASON")

    return ("PASS" if not errors else "INVALID_OUTPUT"), errors

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--adapter", type=Path)
    ap.add_argument("--input", type=Path, required=True)
    ap.add_argument("--output-dir", type=Path, required=True)
    ap.add_argument("--max-new-tokens", type=int, default=1536)
    ap.add_argument("--repetition-penalty", type=float, default=1.08)
    ap.add_argument("--no-repeat-ngram-size", type=int, default=12)
    args = ap.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    predictions_path = args.output_dir / "predictions.jsonl"
    summary_path = args.output_dir / "summary.json"

    tasks = read_jsonl(args.input)
    if len(tasks) != 20:
        raise RuntimeError(f"Expected exactly 20 AI resolution tasks, got {len(tasks)}")

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

    existing = {}
    if predictions_path.exists():
        for row in read_jsonl(predictions_path):
            existing[row["logical_source"]] = row

    print("TASKS", len(tasks))
    print("ALREADY_COMPLETED", len(existing))
    print("MODEL", args.model)
    print("ADAPTER", args.adapter)
    print("MAX_NEW_TOKENS", args.max_new_tokens)
    print("SAMPLING", False)
    print("THINKING", False)

    for i, task in enumerate(tasks, 1):
        logical_source = task["logical_source"]
        if logical_source in existing:
            print(f"[{i}/{len(tasks)}] SKIP {logical_source}")
            continue

        task_payload = {
            "logical_source": task["logical_source"],
            "usage_paths": task.get("usage_paths"),
            "grounded_event_ids": task.get("grounded_event_ids", []),
            "technique_ids": task.get("technique_ids", []),
            "allowed_live_candidates": task["allowed_live_candidates"],
        }

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": "Resolve this telemetry source using only the supplied live Splunk evidence:\n"
                + json.dumps(task_payload, ensure_ascii=False, separators=(",", ":")),
            },
        ]

        prompt = tokenizer.apply_chat_template(
            messages,
            tokenize=True,
            add_generation_prompt=True,
            enable_thinking=False,
        )

        prompt_ids = prompt["input_ids"]

        input_ids = torch.tensor(
            [prompt_ids],
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
                repetition_penalty=args.repetition_penalty,
                no_repeat_ngram_size=args.no_repeat_ngram_size,
                use_cache=True,
                eos_token_id=tokenizer.eos_token_id,
                pad_token_id=tokenizer.pad_token_id,
            )
        elapsed = time.time() - started

        new_ids = generated[0, input_ids.shape[1]:]
        raw_output = tokenizer.decode(new_ids, skip_special_tokens=True).strip()
        parsed = extract_json_object(raw_output)
        validation_status, validation_errors = validate_result(task, parsed)

        record = {
            "resolver_version": "1.0",
            "logical_source": logical_source,
            "task_sha256": hashlib.sha256(
                json.dumps(task, sort_keys=True, ensure_ascii=False).encode("utf-8")
            ).hexdigest(),
            "raw_output": raw_output,
            "parsed_output": parsed,
            "validation_status": validation_status,
            "validation_errors": validation_errors,
            "elapsed_seconds": round(elapsed, 3),
        }

        with predictions_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

        print(
            f"[{i}/{len(tasks)}] {logical_source} "
            f"=> {validation_status} "
            f"{parsed.get('decision') if isinstance(parsed, dict) else 'NO_JSON'} "
            f"{parsed.get('selected_sourcetype') if isinstance(parsed, dict) else ''} "
            f"({elapsed:.1f}s)"
        )

    results = read_jsonl(predictions_path)
    counts = {}
    valid = 0
    for r in results:
        if r["validation_status"] == "PASS":
            valid += 1
            decision = r["parsed_output"]["decision"]
            counts[decision] = counts.get(decision, 0) + 1

    summary = {
        "resolver_version": "1.0",
        "expected_tasks": 20,
        "completed_tasks": len(results),
        "contract_valid_outputs": valid,
        "contract_invalid_outputs": len(results) - valid,
        "decision_counts": counts,
        "model": args.model,
        "adapter": str(args.adapter),
        "max_new_tokens": args.max_new_tokens,
        "repetition_penalty": args.repetition_penalty,
        "no_repeat_ngram_size": args.no_repeat_ngram_size,
        "sampling": False,
        "thinking": False,
    }
    summary_path.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print("COMPLETED", len(results))
    print("CONTRACT_VALID", valid)
    print("DECISIONS", json.dumps(counts, sort_keys=True))
    print("OUTPUT", predictions_path)
    print("SUMMARY", summary_path)

if __name__ == "__main__":
    main()
