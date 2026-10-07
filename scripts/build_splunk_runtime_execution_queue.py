#!/usr/bin/env python3
import json, hashlib
from pathlib import Path

ROOT = Path(r"D:\ThreatHunting\project")
PHASE3 = ROOT / "data" / "processed" / "phase3"
COMPILED = PHASE3 / "splunk_compilation" / "compiled_queries.jsonl"
RESOLUTION = PHASE3 / "splunk_runtime" / "evidence_gate" / "grounded_path_runtime_resolution_v1.jsonl"
OUT = PHASE3 / "splunk_runtime" / "execution"
QUEUE = OUT / "runtime_execution_queue_v1.jsonl"
DEFERRED = OUT / "runtime_execution_deferred_v1.jsonl"
SUMMARY = OUT / "summary_v1.json"
MANIFEST = OUT / "manifest_v1.json"

def read_jsonl(path):
    with Path(path).open("r", encoding="utf-8") as f:
        return [json.loads(x) for x in f if x.strip()]

def sha256(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def esc(s):
    return str(s).replace("\\", "\\\\").replace('"', '\\"')

def main():
    compiled = read_jsonl(COMPILED)
    paths = {r["path_id"]: r for r in read_jsonl(RESOLUTION)}

    if len(compiled) != 540:
        raise RuntimeError(f"Expected 540 compiled queries, got {len(compiled)}")
    if len(paths) != 540:
        raise RuntimeError(f"Expected 540 path-resolution rows, got {len(paths)}")

    runtime = [r for r in compiled if r.get("runtime_execution_candidate") is True]
    if len(runtime) != 418:
        raise RuntimeError(f"Expected 418 runtime candidates, got {len(runtime)}")

    queue = []
    deferred = []

    for r in runtime:
        p = paths.get(r["path_id"])
        if p is None:
            raise RuntimeError(f"Missing path resolution for {r['path_id']}")

        if p["source_coverage_state"] != "ALL_SOURCES_CONFIRMED":
            deferred.append({
                "path_id": r["path_id"],
                "technique_id": r["technique_id"],
                "analytic_id": r["analytic_id"],
                "classification": r["classification"],
                "source_coverage_state": p["source_coverage_state"],
                "confirmed_sourcetypes": p["confirmed_sourcetypes"],
                "unresolved_sources": p["unresolved_sources"],
                "defer_reason": "RUNTIME_SOURCE_MAPPING_NOT_FULLY_CONFIRMED",
            })
            continue

        sourcetypes = p["confirmed_sourcetypes"]
        if not sourcetypes:
            raise RuntimeError(f"{r['path_id']}: ALL_SOURCES_CONFIRMED but no sourcetypes")

        source_clause = " OR ".join(f'sourcetype="{esc(x)}"' for x in sourcetypes)
        core = r["spl"].strip()
        execution_spl = (
            f'search index=botsv3 earliest=0 ({source_clause}) ({core}) '
            f'| stats count as match_count'
        )

        queue.append({
            "execution_contract_version": "1.0",
            "path_id": r["path_id"],
            "generation_unit_id": r["generation_unit_id"],
            "rule_id": r["rule_id"],
            "rule_file": r["rule_file"],
            "technique_id": r["technique_id"],
            "technique_name": r["technique_name"],
            "analytic_id": r["analytic_id"],
            "classification": r["classification"],
            "keyword_mode": r["keyword_mode"],
            "confirmed_sourcetypes": sourcetypes,
            "logical_log_sources": p["logical_log_sources"],
            "grounded_event_ids": r["grounded_event_ids"],
            "spl": core,
            "execution_spl": execution_spl,
            "execution_result_status": "PENDING",
            "zero_result_interpretation": "INCONCLUSIVE_RUNTIME_VISIBILITY",
            "runtime_environment_note": (
                "BOTS v3 on Splunk 9.4.13 has incomplete raw-event search visibility; "
                "zero raw-search matches must not be interpreted as proof of no technique occurrence."
            ),
        })

    if len(queue) != 404:
        raise RuntimeError(f"Expected 404 execution-ready rows, got {len(queue)}")
    if len(deferred) != 14:
        raise RuntimeError(f"Expected 14 deferred rows, got {len(deferred)}")

    OUT.mkdir(parents=True, exist_ok=True)
    with QUEUE.open("w", encoding="utf-8") as f:
        for r in queue:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    with DEFERRED.open("w", encoding="utf-8") as f:
        for r in deferred:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    summary = {
        "execution_contract_version": "1.0",
        "compiled_population": len(compiled),
        "literal_runtime_candidates": len(runtime),
        "execution_ready_exact": len(queue),
        "deferred": len(deferred),
        "query_shape": "index+botsv3 + confirmed sourcetype scope + compiled Sigma SPL + stats count",
        "zero_result_interpretation": "INCONCLUSIVE_RUNTIME_VISIBILITY",
        "raw_runtime_limit": "legacy BOTS v3/current Splunk raw-event visibility is incomplete",
    }
    SUMMARY.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    manifest = {
        "inputs": {
            str(COMPILED): sha256(COMPILED),
            str(RESOLUTION): sha256(RESOLUTION),
        },
        "outputs": {
            str(QUEUE): sha256(QUEUE),
            str(DEFERRED): sha256(DEFERRED),
            str(SUMMARY): sha256(SUMMARY),
        },
    }
    MANIFEST.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    print("COMPILED_POPULATION", len(compiled))
    print("LITERAL_RUNTIME_CANDIDATES", len(runtime))
    print("EXECUTION_READY_EXACT", len(queue))
    print("DEFERRED", len(deferred))
    print("QUEUE", QUEUE)
    print("DEFERRED_OUTPUT", DEFERRED)
    print("SUMMARY", SUMMARY)
    print("MANIFEST", MANIFEST)
    print("FIRST_EXECUTION_SPL", queue[0]["execution_spl"])

if __name__ == "__main__":
    main()
