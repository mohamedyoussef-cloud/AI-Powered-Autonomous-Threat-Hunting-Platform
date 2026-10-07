#!/usr/bin/env python3
import argparse
import csv
import io
import json
import subprocess
import time
from collections import Counter
from pathlib import Path

ROOT = Path(r"D:\ThreatHunting\project")
PHASE3 = ROOT / "data" / "processed" / "phase3"
RESULTS = PHASE3 / "splunk_runtime" / "execution" / "runtime_results_v1" / "runtime_execution_results_v1.jsonl"
COMPILED = PHASE3 / "splunk_compilation" / "compiled_queries.jsonl"
OUTDIR = PHASE3 / "splunk_runtime" / "finding_validation"
OUT = OUTDIR / "keyword_contribution_v1.jsonl"
SUMMARY = OUTDIR / "keyword_contribution_summary_v1.json"
SPLUNK = Path(r"D:\SPL\bin\splunk.exe")

def read_jsonl(path):
    with Path(path).open("r", encoding="utf-8") as f:
        return [json.loads(x) for x in f if x.strip()]

def append_jsonl(path, obj):
    with Path(path).open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")

def parse_count(stdout):
    rows = list(csv.DictReader(io.StringIO(stdout.strip())))
    if not rows or "match_count" not in rows[0]:
        raise ValueError(f"unexpected CSV: {stdout[:300]!r}")
    return int(rows[0]["match_count"])

def esc(s):
    return str(s).replace("\\", "\\\\").replace('"', '\\"')

def run_count(spl, timeout, retries):
    cmd = [str(SPLUNK), "search", spl, "-output", "csv", "-maxout", "10"]
    last = None
    for attempt in range(1, retries + 1):
        try:
            p = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout,
                encoding="utf-8", errors="replace"
            )
            if p.returncode != 0:
                last = f"returncode={p.returncode}; stderr={p.stderr.strip()[:500]}"
            else:
                return parse_count(p.stdout), attempt, None
        except (PermissionError, OSError, subprocess.TimeoutExpired) as e:
            last = f"{type(e).__name__}: {e}"
        if attempt < retries:
            time.sleep(attempt * 2)
    return None, retries, last

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--timeout-seconds", type=int, default=60)
    ap.add_argument("--spawn-retries", type=int, default=3)
    args = ap.parse_args()

    OUTDIR.mkdir(parents=True, exist_ok=True)

    results = read_jsonl(RESULTS)
    compiled = {r["path_id"]: r for r in read_jsonl(COMPILED)}

    nonzero = [r for r in results if r.get("execution_status") == "NONZERO_FINDING_CANDIDATE"]
    if len(nonzero) != 22:
        raise RuntimeError(f"Expected 22 nonzero runtime candidates, got {len(nonzero)}")

    # cross-rule keyword frequency among the 22 candidates
    keyword_freq = Counter()
    for r in nonzero:
        c = compiled[r["path_id"]]
        for kw in set(c.get("keywords", [])):
            keyword_freq[kw] += 1

    existing = {}
    if OUT.exists():
        existing = {r["path_id"]: r for r in read_jsonl(OUT)}

    todo = [r for r in nonzero if r["path_id"] not in existing]

    print("NONZERO_CANDIDATES", len(nonzero))
    print("ALREADY_COMPLETED", len(existing))
    print("TO_ANALYZE", len(todo))

    for idx, r in enumerate(todo, 1):
        c = compiled[r["path_id"]]
        keywords = c.get("keywords", [])
        sourcetypes = r["confirmed_sourcetypes"]
        source_clause = " OR ".join(f'sourcetype="{esc(x)}"' for x in sourcetypes)

        contributions = []
        for kw in keywords:
            spl = (
                f'search index=botsv3 earliest=0 ({source_clause}) '
                f'"{esc(kw)}" | stats count as match_count'
            )
            count, attempts, error = run_count(
                spl, args.timeout_seconds, args.spawn_retries
            )
            contributions.append({
                "keyword": kw,
                "keyword_rule_frequency_within_22": keyword_freq[kw],
                "match_count": count,
                "spawn_attempts": attempts,
                "error": error,
            })

        ok = [x for x in contributions if x["match_count"] is not None]
        dominant = max(ok, key=lambda x: x["match_count"]) if ok else None
        full_count = int(r["match_count"])

        if dominant:
            dominant_ratio = (
                dominant["match_count"] / full_count if full_count > 0 else 0.0
            )
        else:
            dominant_ratio = None

        if (
            dominant
            and dominant["match_count"] == full_count
            and dominant["keyword_rule_frequency_within_22"] >= 2
        ):
            validation_state = "SHARED_KEYWORD_DOMINATED"
        elif dominant and dominant["match_count"] == full_count:
            validation_state = "SINGLE_KEYWORD_DOMINATED_NEEDS_REVIEW"
        elif dominant:
            validation_state = "MULTI_KEYWORD_SIGNAL_RETAIN"
        else:
            validation_state = "ANALYSIS_ERROR"

        record = {
            "finding_validation_version": "1.0",
            "path_id": r["path_id"],
            "technique_id": r["technique_id"],
            "analytic_id": r["analytic_id"],
            "runtime_match_count": full_count,
            "keywords": keywords,
            "keyword_contributions": contributions,
            "dominant_keyword": dominant["keyword"] if dominant else None,
            "dominant_keyword_count": dominant["match_count"] if dominant else None,
            "dominant_keyword_ratio": round(dominant_ratio, 6) if dominant_ratio is not None else None,
            "dominant_keyword_rule_frequency_within_22": (
                dominant["keyword_rule_frequency_within_22"] if dominant else None
            ),
            "validation_state": validation_state,
            "interpretation": (
                "This classifies whether the nonzero OR-query result is fully explained "
                "by one keyword. It does not claim attack occurrence or false-positive status."
            ),
        }
        append_jsonl(OUT, record)

        print(
            f"[{len(existing)+idx}/{len(nonzero)}] {r['path_id']} "
            f"=> {validation_state} "
            f"dominant={record['dominant_keyword']!r} "
            f"{record['dominant_keyword_count']}/{full_count}"
        )

    rows = read_jsonl(OUT)
    latest = {r["path_id"]: r for r in rows}
    states = Counter(r["validation_state"] for r in latest.values())

    summary = {
        "finding_validation_version": "1.0",
        "nonzero_runtime_candidates": len(nonzero),
        "completed_unique_paths": len(latest),
        "validation_state_counts": dict(sorted(states.items())),
        "policy": {
            "shared_keyword_dominated": (
                "one keyword alone reproduces the full runtime match count and the same "
                "keyword appears in at least two of the 22 nonzero candidate rules"
            ),
            "attack_occurrence_claim": False,
            "false_positive_claim": False,
        },
    }
    SUMMARY.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print("COMPLETED", len(latest))
    print("VALIDATION_STATE_COUNTS", dict(sorted(states.items())))
    print("OUTPUT", OUT)
    print("SUMMARY", SUMMARY)

if __name__ == "__main__":
    main()
