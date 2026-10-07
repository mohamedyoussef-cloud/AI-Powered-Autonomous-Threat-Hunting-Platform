#!/usr/bin/env python3
import argparse
import csv
import hashlib
import io
import json
import subprocess
import time
from collections import Counter
from pathlib import Path

ROOT = Path(r"D:\ThreatHunting\project")
QUEUE = ROOT / "data" / "processed" / "phase3" / "splunk_runtime" / "execution" / "runtime_execution_queue_v1.jsonl"
OUTDIR = ROOT / "data" / "processed" / "phase3" / "splunk_runtime" / "execution" / "runtime_results_v1"
RESULTS = OUTDIR / "runtime_execution_results_v1.jsonl"
ERRORS = OUTDIR / "runtime_execution_errors_v1.jsonl"
SUMMARY = OUTDIR / "summary_v1.json"
MANIFEST = OUTDIR / "manifest_v1.json"
SPLUNK = Path(r"D:\SPL\bin\splunk.exe")

def read_jsonl(path):
    rows = []
    with Path(path).open("r", encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception as e:
                raise RuntimeError(f"{path}:{n}: invalid JSON: {e}") from e
    return rows

def sha256(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def parse_match_count(stdout):
    text = stdout.strip()
    if not text:
        raise ValueError("empty stdout")
    rows = list(csv.DictReader(io.StringIO(text)))
    if not rows:
        raise ValueError(f"no CSV rows in stdout: {text[:300]!r}")
    if "match_count" not in rows[0]:
        raise ValueError(f"match_count column missing: {rows[0]}")
    return int(str(rows[0]["match_count"]).strip())

def append_jsonl(path, obj):
    with Path(path).open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")

def run_with_retry(cmd, timeout_seconds, retries=3, retry_delay=2.0):
    last_exc = None
    for attempt in range(1, retries + 1):
        try:
            return subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                encoding="utf-8",
                errors="replace",
            ), attempt
        except PermissionError as e:
            last_exc = e
            if attempt < retries:
                time.sleep(retry_delay * attempt)
                continue
            raise
        except OSError as e:
            if getattr(e, "winerror", None) == 5:
                last_exc = e
                if attempt < retries:
                    time.sleep(retry_delay * attempt)
                    continue
            raise
    raise last_exc

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--timeout-seconds", type=int, default=60)
    ap.add_argument("--limit", type=int, default=0, help="0 = all remaining")
    ap.add_argument("--spawn-retries", type=int, default=3)
    args = ap.parse_args()

    if not QUEUE.exists():
        raise RuntimeError(f"Missing queue: {QUEUE}")
    if not SPLUNK.exists():
        raise RuntimeError(f"Missing Splunk CLI: {SPLUNK}")

    OUTDIR.mkdir(parents=True, exist_ok=True)

    queue = read_jsonl(QUEUE)
    if len(queue) != 404:
        raise RuntimeError(f"Expected 404 queued searches, got {len(queue)}")

    existing = {}
    if RESULTS.exists():
        for r in read_jsonl(RESULTS):
            existing[r["path_id"]] = r

    remaining = [r for r in queue if r["path_id"] not in existing]
    if args.limit > 0:
        remaining = remaining[:args.limit]

    print("QUEUE_TOTAL", len(queue))
    print("ALREADY_COMPLETED", len(existing))
    print("TO_EXECUTE", len(remaining))
    print("TIMEOUT_SECONDS", args.timeout_seconds)
    print("SPAWN_RETRIES", args.spawn_retries)

    for pos, row in enumerate(remaining, 1):
        started = time.time()
        cmd = [
            str(SPLUNK),
            "search",
            row["execution_spl"],
            "-output", "csv",
            "-maxout", "10",
        ]

        status = None
        match_count = None
        error = None
        stderr_text = ""
        stdout_text = ""
        spawn_attempts = 0

        try:
            proc, spawn_attempts = run_with_retry(
                cmd,
                args.timeout_seconds,
                retries=args.spawn_retries,
            )
            elapsed = time.time() - started
            stdout_text = proc.stdout or ""
            stderr_text = proc.stderr or ""

            if proc.returncode != 0:
                status = "EXECUTION_ERROR"
                error = f"Splunk CLI return code {proc.returncode}"
            else:
                try:
                    match_count = parse_match_count(stdout_text)
                    status = (
                        "NONZERO_FINDING_CANDIDATE"
                        if match_count > 0
                        else "ZERO_INCONCLUSIVE_RUNTIME_VISIBILITY"
                    )
                except Exception as e:
                    status = "EXECUTION_ERROR"
                    error = f"Result parse failure: {e}"

        except subprocess.TimeoutExpired:
            elapsed = time.time() - started
            status = "TIMEOUT"
            error = f"Timed out after {args.timeout_seconds}s"

        except (PermissionError, OSError) as e:
            elapsed = time.time() - started
            status = "EXECUTION_ERROR"
            error = f"Process spawn failed after {args.spawn_retries} attempts: {type(e).__name__}: {e}"

        result = {
            "execution_result_version": "1.1",
            "path_id": row["path_id"],
            "generation_unit_id": row["generation_unit_id"],
            "rule_id": row["rule_id"],
            "rule_file": row["rule_file"],
            "technique_id": row["technique_id"],
            "technique_name": row["technique_name"],
            "analytic_id": row["analytic_id"],
            "classification": row["classification"],
            "keyword_mode": row["keyword_mode"],
            "confirmed_sourcetypes": row["confirmed_sourcetypes"],
            "logical_log_sources": row["logical_log_sources"],
            "grounded_event_ids": row["grounded_event_ids"],
            "execution_spl": row["execution_spl"],
            "execution_status": status,
            "match_count": match_count,
            "elapsed_seconds": round(elapsed, 3),
            "spawn_attempts": spawn_attempts,
            "error": error,
            "stderr": stderr_text.strip()[:2000],
            "zero_result_interpretation": (
                "INCONCLUSIVE_RUNTIME_VISIBILITY"
                if status == "ZERO_INCONCLUSIVE_RUNTIME_VISIBILITY"
                else None
            ),
        }
        append_jsonl(RESULTS, result)

        if status in {"EXECUTION_ERROR", "TIMEOUT"}:
            append_jsonl(ERRORS, result)

        print(
            f"[{len(existing)+pos}/{len(queue)}] "
            f"{row['path_id']} => {status} "
            f"count={match_count if match_count is not None else '-'} "
            f"spawn_attempts={spawn_attempts or '-'} "
            f"({elapsed:.1f}s)"
        )

    all_results = read_jsonl(RESULTS) if RESULTS.exists() else []
    latest = {}
    for r in all_results:
        latest[r["path_id"]] = r
    latest_results = list(latest.values())

    counts = Counter(r["execution_status"] for r in latest_results)
    total_nonzero_matches = sum(
        int(r["match_count"] or 0)
        for r in latest_results
        if r["execution_status"] == "NONZERO_FINDING_CANDIDATE"
    )

    summary = {
        "execution_result_version": "1.1",
        "queue_total": len(queue),
        "completed_unique_paths": len(latest_results),
        "remaining": len(queue) - len(latest_results),
        "status_counts": dict(sorted(counts.items())),
        "nonzero_finding_candidate_rows": counts.get("NONZERO_FINDING_CANDIDATE", 0),
        "total_nonzero_match_count": total_nonzero_matches,
        "zero_results_are_conclusive_negatives": False,
        "zero_result_interpretation": "INCONCLUSIVE_RUNTIME_VISIBILITY",
        "timeout_seconds": args.timeout_seconds,
        "spawn_retries": args.spawn_retries,
    }
    SUMMARY.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    manifest = {
        "inputs": {str(QUEUE): sha256(QUEUE)},
        "outputs": {
            str(RESULTS): sha256(RESULTS) if RESULTS.exists() else None,
            str(ERRORS): sha256(ERRORS) if ERRORS.exists() else None,
            str(SUMMARY): sha256(SUMMARY),
        },
    }
    MANIFEST.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    print("COMPLETED_RESULTS", len(latest_results))
    print("REMAINING", summary["remaining"])
    print("STATUS_COUNTS", summary["status_counts"])
    print("NONZERO_FINDING_CANDIDATES", summary["nonzero_finding_candidate_rows"])
    print("TOTAL_NONZERO_MATCH_COUNT", summary["total_nonzero_match_count"])
    print("RESULTS", RESULTS)
    print("SUMMARY", SUMMARY)
    print("MANIFEST", MANIFEST)

if __name__ == "__main__":
    main()
