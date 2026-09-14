from __future__ import annotations

import argparse
import json
import re
import time
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from .output_validator_v1 import (
    validate_output,
)


PROJECT_ROOT = Path(__file__).resolve().parents[4]

PHASE3_DIR = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "phase3"
)

ROUTER_DIR = (
    PHASE3_DIR
    / "router"
)

ENGINE_DIR = (
    PHASE3_DIR
    / "hypothesis_engine"
)

REPORT_DIR = (
    PROJECT_ROOT
    / "reports"
    / "phase3"
)

PROVIDER_FILE = (
    PROJECT_ROOT
    / "config"
    / "phase3"
    / "llm_provider.local_qwen3_8b.json"
)

MANIFEST_FILE = (
    ENGINE_DIR
    / "hypothesis_engine_dispatch_manifest_v1.jsonl"
)

INDEX_OUTPUT = (
    ENGINE_DIR
    / "hypothesis_engine_results_index_v1.jsonl"
)

ERROR_OUTPUT = (
    ENGINE_DIR
    / "hypothesis_engine_errors_v1.jsonl"
)

REPORT_OUTPUT = (
    REPORT_DIR
    / "hypothesis_engine_v1_summary.json"
)


QUEUE_FILES = {
    "runtime_hunt":
        ROUTER_DIR
        / "runtime_hunt_queue_v1.jsonl",

    "collection_gap_resolution":
        ROUTER_DIR
        / "collection_gap_queue_v1.jsonl",

    "environment_resolution":
        ROUTER_DIR
        / "environment_resolution_queue_v1.jsonl",

    "pre_attack_hunt":
        ROUTER_DIR
        / "pre_attack_queue_v1.jsonl",
}


OUTPUT_FILES = {
    "runtime_hunt":
        ENGINE_DIR
        / "runtime_hunt_outputs_v1.jsonl",

    "collection_gap_resolution":
        ENGINE_DIR
        / "collection_gap_outputs_v1.jsonl",

    "environment_resolution":
        ENGINE_DIR
        / "environment_resolution_outputs_v1.jsonl",

    "pre_attack_hunt":
        ENGINE_DIR
        / "pre_attack_outputs_v1.jsonl",
}


def read_json(path):
    return json.loads(
        path.read_text(
            encoding="utf-8-sig"
        )
    )


def read_jsonl(path):
    rows = []

    with path.open(
        "r",
        encoding="utf-8-sig",
    ) as f:

        for line_number, line in enumerate(
            f,
            start=1,
        ):
            line = line.strip()

            if not line:
                continue

            try:
                row = json.loads(line)

            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    f"Invalid JSONL:"
                    f"{path}:{line_number}:"
                    f"{exc}"
                ) from exc

            rows.append(row)

    return rows


def append_jsonl(path, row):
    with path.open(
        "a",
        encoding="utf-8",
        newline="\n",
    ) as f:
        f.write(
            json.dumps(
                row,
                ensure_ascii=False,
            )
            + "\n"
        )


def strip_thinking(text):
    return re.sub(
        r"<think>.*?</think>",
        "",
        text,
        flags=(
            re.IGNORECASE
            | re.DOTALL
        ),
    ).strip()


def parse_json_output(text):
    text = strip_thinking(
        text
    )

    text = text.strip()

    if text.startswith("```"):
        text = re.sub(
            r"^```(?:json)?\s*",
            "",
            text,
            flags=re.IGNORECASE,
        )

        text = re.sub(
            r"\s*```$",
            "",
            text,
        )

    try:
        value = json.loads(
            text
        )

        if isinstance(
            value,
            dict,
        ):
            return value

    except json.JSONDecodeError:
        pass

    start = text.find(
        "{"
    )

    end = text.rfind(
        "}"
    )

    if (
        start == -1
        or end == -1
        or end <= start
    ):
        raise ValueError(
            "No JSON object found"
        )

    value = json.loads(
        text[
            start:end + 1
        ]
    )

    if not isinstance(
        value,
        dict,
    ):
        raise ValueError(
            "Model output is not a JSON object"
        )

    return value


def post_json(
    url,
    payload,
    timeout,
):
    body = json.dumps(
        payload,
        ensure_ascii=False,
    ).encode(
        "utf-8"
    )

    request = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type":
                "application/json",
        },
        method="POST",
    )

    started = time.perf_counter()

    try:
        with urllib.request.urlopen(
            request,
            timeout=timeout,
        ) as response:

            raw = response.read()

    except urllib.error.HTTPError as exc:
        error_body = (
            exc.read()
            .decode(
                "utf-8",
                errors="replace",
            )
        )

        raise RuntimeError(
            f"HTTP {exc.code}: "
            f"{error_body}"
        ) from exc

    latency = (
        time.perf_counter()
        - started
    )

    result = json.loads(
        raw.decode("utf-8")
    )

    return result, latency


def call_model(
    provider,
    messages,
    timeout,
):
    base_url = (
        provider[
            "base_url"
        ].rstrip("/")
    )

    url = (
        base_url
        + "/chat/completions"
    )

    generation = provider[
        "generation"
    ]

    payload = {
        "model":
            provider[
                "inference_model"
            ],

        "messages":
            messages,

        "temperature":
            generation.get(
                "temperature",
                0.2,
            ),

        "top_p":
            generation.get(
                "top_p",
                0.9,
            ),

        "max_tokens":
            generation.get(
                "max_tokens",
                1400,
            ),

        "stream":
            False,

        "chat_template_kwargs": {
            "enable_thinking":
                bool(
                    generation.get(
                        "thinking_mode",
                        False,
                    )
                ),
        },
    }

    response, latency = post_json(
        url,
        payload,
        timeout,
    )

    choices = response.get(
        "choices",
        []
    )

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

    usage = response.get(
        "usage",
        {}
    )

    return (
        content,
        latency,
        usage,
    )


def load_router_records():
    records = {}

    for route, path in (
        QUEUE_FILES.items()
    ):
        for row in read_jsonl(
            path
        ):
            technique_id = row[
                "technique_id"
            ]

            if technique_id in records:
                raise RuntimeError(
                    "Duplicate technique ID: "
                    f"{technique_id}"
                )

            records[
                technique_id
            ] = row

    if len(records) != 697:
        raise RuntimeError(
            "Expected 697 router records, "
            f"found {len(records)}"
        )

    return records


def load_completed():
    if not INDEX_OUTPUT.exists():
        return set()

    completed = set()

    for row in read_jsonl(
        INDEX_OUTPUT
    ):
        if row.get(
            "status"
        ) == "PASS":
            completed.add(
                row[
                    "technique_id"
                ]
            )

    return completed


def reset_outputs():
    paths = [
        INDEX_OUTPUT,
        ERROR_OUTPUT,
        REPORT_OUTPUT,
        *OUTPUT_FILES.values(),
    ]

    for path in paths:
        if path.exists():
            path.unlink()


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--reset",
        action="store_true",
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

    args = parser.parse_args()

    required_files = [
        PROVIDER_FILE,
        MANIFEST_FILE,
        *QUEUE_FILES.values(),
    ]

    for path in required_files:
        if not path.exists():
            raise FileNotFoundError(
                path
            )

    ENGINE_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    if args.reset:
        reset_outputs()

    provider = read_json(
        PROVIDER_FILE
    )

    timeout = (
        args.timeout
        or provider.get(
            "request_timeout_seconds",
            180,
        )
    )

    manifest = read_jsonl(
        MANIFEST_FILE
    )

    if len(manifest) != 697:
        raise RuntimeError(
            "Expected 697 dispatch records, "
            f"found {len(manifest)}"
        )

    router_records = (
        load_router_records()
    )

    completed = (
        load_completed()
    )

    pass_count = len(
        completed
    )

    fail_count = 0

    route_pass = Counter()
    route_fail = Counter()

    started_at = (
        datetime.now(
            timezone.utc
        )
    )

    print(
        "Hypothesis Engine v1.0"
    )
    print(
        "----------------------"
    )
    print(
        f"Model      : "
        f"{provider['inference_model']}"
    )
    print(
        f"Endpoint   : "
        f"{provider['base_url']}"
    )
    print(
        f"Inputs     : "
        f"{len(manifest)}"
    )
    print(
        f"Resume PASS: "
        f"{len(completed)}"
    )
    print()

    for position, item in enumerate(
        manifest,
        start=1,
    ):
        technique_id = (
            item[
                "technique_id"
            ]
        )

        if technique_id in completed:
            continue

        route = item[
            "route"
        ]

        record = (
            router_records[
                technique_id
            ]
        )

        base_messages = item[
            "messages"
        ]

        final_output = None
        final_validation = None
        final_raw = None
        final_usage = {}
        total_latency = 0.0
        attempt_used = 0
        last_error = None

        for attempt in range(
            1,
            args.max_retries + 2,
        ):
            attempt_used = attempt

            messages = list(
                base_messages
            )

            if (
                attempt > 1
                and last_error
            ):
                messages.append({
                    "role": "user",
                    "content": (
                        "The previous response "
                        "failed validation.\n"
                        "Validation errors:\n"
                        + "\n".join(
                            f"- {error}"
                            for error
                            in last_error
                        )
                        + "\nRegenerate the complete "
                        "answer as valid JSON only. "
                        "Do not add commentary."
                    ),
                })

            try:
                raw_content, latency, usage = (
                    call_model(
                        provider,
                        messages,
                        timeout,
                    )
                )

                total_latency += (
                    latency
                )

                final_raw = (
                    raw_content
                )

                parsed = (
                    parse_json_output(
                        raw_content
                    )
                )

                validation = (
                    validate_output(
                        record,
                        parsed,
                    )
                )

                if (
                    validation[
                        "schema_valid"
                    ]
                    and validation[
                        "grounding_valid"
                    ]
                ):
                    final_output = (
                        parsed
                    )

                    final_validation = (
                        validation
                    )

                    final_usage = (
                        usage
                    )

                    break

                last_error = (
                    validation[
                        "errors"
                    ]
                )

            except Exception as exc:
                last_error = [
                    f"{type(exc).__name__}:"
                    f"{exc}"
                ]

        if final_output is not None:
            envelope = {
                "engine_version": "1.0",

                "generated_at_utc":
                    datetime.now(
                        timezone.utc
                    ).isoformat(),

                "technique_id":
                    technique_id,

                "technique_name":
                    item.get(
                        "technique_name"
                    ),

                "route":
                    route,

                "task_mode":
                    item[
                        "task_mode"
                    ],

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
                    provider[
                        "inference_model"
                    ],

                "model_output":
                    final_output,

                "validation":
                    final_validation,

                "attempts":
                    attempt_used,

                "latency_seconds":
                    round(
                        total_latency,
                        3,
                    ),

                "usage":
                    final_usage,

                "status":
                    "PASS",
            }

            append_jsonl(
                OUTPUT_FILES[
                    route
                ],
                envelope,
            )

            append_jsonl(
                INDEX_OUTPUT,
                {
                    "technique_id":
                        technique_id,

                    "route":
                        route,

                    "task_mode":
                        item[
                            "task_mode"
                        ],

                    "router_queue_position":
                        item.get(
                            "router_queue_position"
                        ),

                    "runtime_hunt_rank":
                        item.get(
                            "runtime_hunt_rank"
                        ),

                    "attempts":
                        attempt_used,

                    "latency_seconds":
                        round(
                            total_latency,
                            3,
                        ),

                    "status":
                        "PASS",
                },
            )

            pass_count += 1

            route_pass[
                route
            ] += 1

            print(
                f"[{position:03d}/697] "
                f"PASS "
                f"{technique_id} "
                f"{route} "
                f"attempt={attempt_used} "
                f"{total_latency:.1f}s"
            )

        else:
            fail_count += 1

            route_fail[
                route
            ] += 1

            error_record = {
                "engine_version":
                    "1.0",

                "generated_at_utc":
                    datetime.now(
                        timezone.utc
                    ).isoformat(),

                "technique_id":
                    technique_id,

                "technique_name":
                    item.get(
                        "technique_name"
                    ),

                "route":
                    route,

                "task_mode":
                    item[
                        "task_mode"
                    ],

                "attempts":
                    attempt_used,

                "errors":
                    last_error or [
                        "unknown_generation_failure"
                    ],

                "raw_response":
                    final_raw,

                "status":
                    "FAIL",
            }

            append_jsonl(
                ERROR_OUTPUT,
                error_record,
            )

            append_jsonl(
                INDEX_OUTPUT,
                {
                    "technique_id":
                        technique_id,

                    "route":
                        route,

                    "task_mode":
                        item[
                            "task_mode"
                        ],

                    "router_queue_position":
                        item.get(
                            "router_queue_position"
                        ),

                    "runtime_hunt_rank":
                        item.get(
                            "runtime_hunt_rank"
                        ),

                    "attempts":
                        attempt_used,

                    "status":
                        "FAIL",
                },
            )

            print(
                f"[{position:03d}/697] "
                f"FAIL "
                f"{technique_id} "
                f"{route}"
            )

    finished_at = (
        datetime.now(
            timezone.utc
        )
    )

    current_index = (
        read_jsonl(
            INDEX_OUTPUT
        )
        if INDEX_OUTPUT.exists()
        else []
    )

    latest_status = {}

    for row in current_index:
        latest_status[
            row[
                "technique_id"
            ]
        ] = row

    final_pass = sum(
        1
        for row
        in latest_status.values()
        if row.get(
            "status"
        ) == "PASS"
    )

    final_fail = sum(
        1
        for row
        in latest_status.values()
        if row.get(
            "status"
        ) == "FAIL"
    )

    validation_status = (
        "PASS"
        if (
            final_pass == 697
            and final_fail == 0
        )
        else "FAIL"
    )

    report = {
        "component":
            "hypothesis_engine",

        "version":
            "1.0",

        "started_at_utc":
            started_at.isoformat(),

        "finished_at_utc":
            finished_at.isoformat(),

        "model":
            provider[
                "inference_model"
            ],

        "provider":
            provider[
                "provider"
            ],

        "input_records":
            697,

        "successful_records":
            final_pass,

        "failed_records":
            final_fail,

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

        "sigma_generation_allowed":
            False,

        "occurrence_claim_allowed":
            False,

        "status":
            validation_status,
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
        f"Successful : {final_pass}"
    )
    print(
        f"Failed     : {final_fail}"
    )
    print(
        f"Validation : "
        f"{validation_status}"
    )
    print()
    print(
        f"Index  : {INDEX_OUTPUT}"
    )
    print(
        f"Errors : {ERROR_OUTPUT}"
    )
    print(
        f"Report : {REPORT_OUTPUT}"
    )


if __name__ == "__main__":
    main()
