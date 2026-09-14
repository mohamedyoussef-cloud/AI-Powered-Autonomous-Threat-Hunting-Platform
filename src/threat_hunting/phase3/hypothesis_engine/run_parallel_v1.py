from __future__ import annotations

import argparse
from copy import deepcopy
import json
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from .output_validator_v1 import validate_output
from .run_hypothesis_engine_v1 import (
    PROJECT_ROOT,
    PROVIDER_FILE,
    MANIFEST_FILE,
    OUTPUT_FILES,
    INDEX_OUTPUT,
    ERROR_OUTPUT,
    REPORT_OUTPUT,
    read_json,
    read_jsonl,
    append_jsonl,
    parse_json_output,
    post_json,
    load_router_records,
    load_completed,
    reset_outputs,
)


CONTRACT_FILE = (
    PROJECT_ROOT
    / "config"
    / "phase3"
    / "hypothesis_engine_task_contracts_v1.json"
)


def load_task_schemas():
    contracts = read_json(CONTRACT_FILE)["tasks"]

    result = {}

    for task_mode, task in contracts.items():
        schema_path = PROJECT_ROOT / task["output_schema"]

        result[task_mode] = read_json(schema_path)

    return result


def call_model(
    provider,
    messages,
    schema,
    task_mode,
    timeout,
):
    base_url = provider["base_url"].rstrip("/")
    url = base_url + "/chat/completions"

    generation = provider["generation"]

    payload = {
        "model": provider["inference_model"],
        "messages": messages,
        "temperature": 0.0,
        "top_p": generation.get("top_p", 0.9),
        "max_tokens": max(2200, int(generation.get("max_tokens", 1400))),
        "stream": False,

        "chat_template_kwargs": {
            "enable_thinking": bool(
                generation.get(
                    "thinking_mode",
                    False,
                )
            )
        },

        "structured_outputs": {
            "json": schema,
        },
    }

    response, latency = post_json(
        url,
        payload,
        timeout,
    )

    choices = response.get("choices", [])

    if not choices:
        raise RuntimeError(
            "Model response contains no choices"
        )

    content = (
        choices[0]
        .get("message", {})
        .get("content")
    )

    if not content:
        raise RuntimeError(
            "Model response contains no content"
        )

    return (
        content,
        latency,
        response.get("usage", {}),
    )


def process_record(
    position,
    item,
    provider,
    schemas,
    router_records,
    timeout,
    max_retries,
):
    technique_id = item["technique_id"]
    route = item["route"]
    task_mode = item["task_mode"]

    record = router_records[technique_id]
    schema = deepcopy(schemas[task_mode])

    component_rows = (
        record.get("context", {})
        .get("telemetry", {})
        .get("component_evaluations", [])
    )

    allowed_ids = [
        row["component_id"]
        for row in component_rows
        if row.get("component_id")
    ]

    allowed_names = [
        row["component_name"]
        for row in component_rows
        if row.get("component_name")
    ]

    allowed_pairs = [
        f"{row['component_id']}={row['component_name']}"
        for row in component_rows
        if (
            row.get("component_id")
            and row.get("component_name")
        )
    ]

    component_array = None

    if task_mode == "generate_runtime_hunt_hypothesis":
        component_array = (
            schema["properties"]
            ["required_telemetry"]
        )

    elif task_mode == "generate_pre_attack_hypothesis":
        component_array = (
            schema["properties"]
            ["required_external_evidence"]
        )

        # The LLM generates the narrative only.
        # Grounded external evidence is injected deterministically
        # after generation from ATT&CK component_evaluations.
        component_array.pop("minItems", None)
        component_array["minItems"] = 0
        component_array["maxItems"] = 0

    if component_array is not None:
        if allowed_ids:
            component_array["maxItems"] = len(allowed_ids)

            item_properties = (
                component_array
                .get("items", {})
                .get("properties", {})
            )

            if "component_id" in item_properties:
                item_properties[
                    "component_id"
                ]["enum"] = allowed_ids

            if "component_name" in item_properties:
                item_properties[
                    "component_name"
                ]["enum"] = allowed_names

        else:
            component_array.pop(
                "minItems",
                None,
            )
            component_array["maxItems"] = 0

    # PRE deterministic generation policy:
    # Generate only narrative fields with the LLM.
    # Grounded evidence and confidence are added deterministically
    # after successful JSON generation.
    if task_mode == "generate_pre_attack_hypothesis":
        schema["properties"].pop(
            "required_external_evidence",
            None,
        )
        schema["properties"].pop(
            "confidence",
            None,
        )

        schema["required"] = [
            x
            for x in schema.get("required", [])
            if x not in {
                "required_external_evidence",
                "confidence",
            }
        ]

    base_messages = list(item["messages"])

    base_messages.append({
        "role": "user",
        "content": (
            "GROUNDING LOCK: Use ONLY the exact ATT&CK "
            "Data Component ID/name pairs listed below. "
            "Never introduce another Data Component and "
            "never change a component name. "
            "If the list is empty, return an empty component "
            "array. Allowed pairs: "
            + (
                "; ".join(allowed_pairs)
                if allowed_pairs
                else "NONE"
            )
        ),
    })

    base_messages.append({
        "role": "user",
        "content": (
            "STRICT BREVITY: Return one complete JSON object only. "
            "Use exactly 2 investigation_focus items. "
            "Keep every narrative field very short. "
            "Do not repeat technique descriptions, examples, commands, "
            "procedures, or background information. "
            "Each explanation or evidence description should be one short sentence."
        ),
    })

    total_latency = 0.0
    final_raw = None
    final_usage = {}
    last_errors = []

    for attempt in range(
        1,
        max_retries + 2,
    ):
        messages = list(base_messages)

        if attempt > 1 and last_errors:
            messages.append({
                "role": "user",
                "content": (
                    "The previous answer failed grounding "
                    "validation. Correct all issues below and "
                    "return the complete JSON object only.\n"
                    + "\n".join(
                        f"- {e}"
                        for e in last_errors
                    )
                ),
            })

        try:
            raw, latency, usage = call_model(
                provider,
                messages,
                schema,
                task_mode,
                timeout,
            )

            total_latency += latency
            final_raw = raw
            final_usage = usage

            parsed = parse_json_output(raw)

            if task_mode == "generate_pre_attack_hypothesis":
                parsed["required_external_evidence"] = [
                    {
                        "component_id": row["component_id"],
                        "component_name": row["component_name"],
                        "evidence_needed": (
                            "Collect external evidence corresponding to "
                            + row["component_name"]
                            + "."
                        ),
                    }
                    for row in component_rows
                    if (
                        row.get("component_id")
                        and row.get("component_name")
                    )
                ]

                parsed["confidence"] = {
                    "level": "low",
                    "score": 0.3,
                    "explanation": (
                        "Confidence is conservative because this "
                        "PRE hypothesis requires external evidence "
                        "for validation."
                    ),
                }

            validation = validate_output(
                record,
                parsed,
            )

            if (
                validation["schema_valid"]
                and validation["grounding_valid"]
            ):
                envelope = {
                    "engine_version": "1.0",
                    "generated_at_utc":
                        datetime.now(
                            timezone.utc
                        ).isoformat(),

                    "technique_id": technique_id,
                    "technique_name":
                        item.get("technique_name"),

                    "route": route,
                    "task_mode": task_mode,

                    "router_queue_position":
                        item.get(
                            "router_queue_position"
                        ),

                    "runtime_hunt_rank":
                        item.get(
                            "runtime_hunt_rank"
                        ),

                    "requires_detection_eligibility_after_task":
                        item.get(
                            "requires_detection_eligibility_after_task"
                        ),

                    "model":
                        provider["inference_model"],

                    "model_output": parsed,

                    "validation": validation,

                    "attempts": attempt,

                    "latency_seconds":
                        round(total_latency, 3),

                    "usage": final_usage,

                    "status": "PASS",
                }

                index = {
                    "technique_id": technique_id,
                    "route": route,
                    "task_mode": task_mode,

                    "router_queue_position":
                        item.get(
                            "router_queue_position"
                        ),

                    "runtime_hunt_rank":
                        item.get(
                            "runtime_hunt_rank"
                        ),

                    "attempts": attempt,

                    "latency_seconds":
                        round(total_latency, 3),

                    "status": "PASS",
                }

                return {
                    "position": position,
                    "status": "PASS",
                    "route": route,
                    "technique_id": technique_id,
                    "attempts": attempt,
                    "latency": total_latency,
                    "envelope": envelope,
                    "index": index,
                }

            last_errors = validation["errors"]

        except Exception as exc:
            last_errors = [
                f"{type(exc).__name__}:{exc}"
            ]

    error = {
        "engine_version": "1.0",

        "generated_at_utc":
            datetime.now(
                timezone.utc
            ).isoformat(),

        "technique_id": technique_id,

        "technique_name":
            item.get("technique_name"),

        "route": route,
        "task_mode": task_mode,

        "attempts":
            max_retries + 1,

        "errors":
            last_errors,

        "raw_response":
            final_raw,

        "status": "FAIL",
    }

    index = {
        "technique_id": technique_id,
        "route": route,
        "task_mode": task_mode,

        "router_queue_position":
            item.get(
                "router_queue_position"
            ),

        "runtime_hunt_rank":
            item.get(
                "runtime_hunt_rank"
            ),

        "attempts":
            max_retries + 1,

        "status": "FAIL",
    }

    return {
        "position": position,
        "status": "FAIL",
        "route": route,
        "technique_id": technique_id,
        "attempts": max_retries + 1,
        "latency": total_latency,
        "error": error,
        "index": index,
    }


def api_ready(provider, timeout):
    url = (
        provider["base_url"]
        .rstrip("/")
        .removesuffix("/v1")
        + "/v1/models"
    )

    try:
        response, _ = post_json
    except Exception:
        pass

    import urllib.request

    with urllib.request.urlopen(
        url,
        timeout=timeout,
    ) as response:
        if response.status != 200:
            raise RuntimeError(
                f"API readiness returned "
                f"{response.status}"
            )


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--workers",
        type=int,
        default=4,
    )

    parser.add_argument(
        "--max-retries",
        type=int,
        default=2,
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=None,
    )

    parser.add_argument(
        "--reset",
        action="store_true",
    )

    args = parser.parse_args()

    if args.workers < 1 or args.workers > 6:
        raise RuntimeError(
            "--workers must be between 1 and 6"
        )

    provider = read_json(PROVIDER_FILE)

    timeout = (
        args.timeout
        or provider.get(
            "request_timeout_seconds",
            180,
        )
    )

    api_ready(
        provider,
        timeout,
    )

    if args.reset:
        reset_outputs()

    manifest = read_jsonl(
        MANIFEST_FILE
    )

    if len(manifest) != 697:
        raise RuntimeError(
            f"Expected 697 inputs, "
            f"found {len(manifest)}"
        )

    schemas = load_task_schemas()
    router_records = load_router_records()
    completed = load_completed()

    pending = [
        (position, item)
        for position, item
        in enumerate(
            manifest,
            start=1,
        )
        if item["technique_id"]
        not in completed
    ]

    print(
        "Hypothesis Engine v1.0 - PARALLEL"
    )
    print(
        "---------------------------------"
    )
    print(
        f"Model       : "
        f"{provider['inference_model']}"
    )
    print(
        f"Inputs      : {len(manifest)}"
    )
    print(
        f"Resume PASS : {len(completed)}"
    )
    print(
        f"Pending     : {len(pending)}"
    )
    print(
        f"Workers     : {args.workers}"
    )
    print(
        "Structured  : JSON Schema"
    )
    print()

    start = time.perf_counter()

    completed_now = 0

    with ThreadPoolExecutor(
        max_workers=args.workers
    ) as executor:

        futures = {
            executor.submit(
                process_record,
                position,
                item,
                provider,
                schemas,
                router_records,
                timeout,
                args.max_retries,
            ): (
                position,
                item["technique_id"],
            )
            for position, item
            in pending
        }

        for future in as_completed(
            futures
        ):
            result = future.result()

            completed_now += 1

            if result["status"] == "PASS":
                append_jsonl(
                    OUTPUT_FILES[
                        result["route"]
                    ],
                    result["envelope"],
                )

            else:
                append_jsonl(
                    ERROR_OUTPUT,
                    result["error"],
                )

            append_jsonl(
                INDEX_OUTPUT,
                result["index"],
            )

            print(
                f"[{completed_now:03d}/"
                f"{len(pending):03d}] "
                f"{result['status']} "
                f"{result['technique_id']} "
                f"{result['route']} "
                f"attempt={result['attempts']} "
                f"{result['latency']:.1f}s",
                flush=True,
            )

    rows = read_jsonl(
        INDEX_OUTPUT
    )

    latest = {}

    for row in rows:
        latest[
            row["technique_id"]
        ] = row

    pass_rows = [
        row
        for row in latest.values()
        if row["status"] == "PASS"
    ]

    fail_rows = [
        row
        for row in latest.values()
        if row["status"] == "FAIL"
    ]

    route_pass = Counter(
        row["route"]
        for row in pass_rows
    )

    route_fail = Counter(
        row["route"]
        for row in fail_rows
    )

    status = (
        "PASS"
        if len(pass_rows) == 697
        else "FAIL"
    )

    elapsed = (
        time.perf_counter()
        - start
    )

    report = {
        "component":
            "hypothesis_engine",

        "version":
            "1.0",

        "execution_mode":
            "parallel_structured",

        "workers":
            args.workers,

        "model":
            provider["inference_model"],

        "input_records":
            697,

        "successful_records":
            len(pass_rows),

        "failed_records":
            len(fail_rows),

        "route_pass_counts":
            dict(
                sorted(
                    route_pass.items()
                )
            ),

        "route_fail_counts":
            dict(
                sorted(
                    route_fail.items()
                )
            ),

        "elapsed_seconds":
            round(elapsed, 3),

        "sigma_generation_allowed":
            False,

        "occurrence_claim_allowed":
            False,

        "status":
            status,
    }

    REPORT_OUTPUT.write_text(
        json.dumps(
            report,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    print()
    print(
        "Hypothesis Engine v1.0 Summary"
    )
    print(
        "------------------------------"
    )
    print(
        f"Successful : {len(pass_rows)}"
    )
    print(
        f"Failed     : {len(fail_rows)}"
    )
    print(
        f"Elapsed    : {elapsed:.1f}s"
    )
    print(
        f"Validation : {status}"
    )


if __name__ == "__main__":
    main()

