#!/usr/bin/env python3
import csv
import hashlib
import io
import json
import subprocess
from collections import Counter
from pathlib import Path

ROOT = Path(r"D:\ThreatHunting\project")
PHASE3 = ROOT / "data" / "processed" / "phase3"

RUNTIME_RESULTS = (
    PHASE3 / "splunk_runtime" / "execution" / "runtime_results_v1"
    / "runtime_execution_results_v1.jsonl"
)
COMPILED = PHASE3 / "splunk_compilation" / "compiled_queries.jsonl"
KEYWORD_VALIDATION = (
    PHASE3 / "splunk_runtime" / "finding_validation"
    / "keyword_contribution_v1.jsonl"
)

OUTDIR = PHASE3 / "splunk_runtime" / "hunt_findings"
DISPOSITIONS = OUTDIR / "runtime_candidate_dispositions_v1.jsonl"
FINDINGS = OUTDIR / "validated_hunt_findings_v1.jsonl"
SUMMARY = OUTDIR / "summary_v1.json"
MANIFEST = OUTDIR / "manifest_v1.json"

SPLUNK = Path(r"D:\SPL\bin\splunk.exe")

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

def parse_count(stdout):
    rows = list(csv.DictReader(io.StringIO(stdout.strip())))
    if not rows or "refined_match_count" not in rows[0]:
        raise RuntimeError(f"Unexpected Splunk CSV: {stdout[:300]!r}")
    return int(rows[0]["refined_match_count"])

def run_refined_query(sourcetypes, keywords):
    if not keywords:
        return None, None, "NO_REFINED_KEYWORDS"

    source_clause = " OR ".join(
        f'sourcetype="{esc(x)}"' for x in sourcetypes
    )
    keyword_clause = " OR ".join(f'"{esc(x)}"' for x in keywords)
    spl = (
        f'search index=botsv3 earliest=0 ({source_clause}) '
        f'({keyword_clause}) | stats count as refined_match_count'
    )

    proc = subprocess.run(
        [str(SPLUNK), "search", spl, "-output", "csv", "-maxout", "10"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
    )
    if proc.returncode != 0:
        return spl, None, f"SPLUNK_RETURN_CODE_{proc.returncode}: {proc.stderr.strip()[:500]}"

    try:
        return spl, parse_count(proc.stdout), None
    except Exception as e:
        return spl, None, f"PARSE_ERROR: {e}"

def main():
    required = [RUNTIME_RESULTS, COMPILED, KEYWORD_VALIDATION]
    missing = [str(p) for p in required if not p.exists()]
    if missing:
        raise RuntimeError("Missing required inputs:\n" + "\n".join(missing))
    if not SPLUNK.exists():
        raise RuntimeError(f"Missing Splunk CLI: {SPLUNK}")

    OUTDIR.mkdir(parents=True, exist_ok=True)

    runtime = {
        r["path_id"]: r
        for r in read_jsonl(RUNTIME_RESULTS)
        if r.get("execution_status") == "NONZERO_FINDING_CANDIDATE"
    }
    compiled = {r["path_id"]: r for r in read_jsonl(COMPILED)}
    validation = {r["path_id"]: r for r in read_jsonl(KEYWORD_VALIDATION)}

    if len(runtime) != 22:
        raise RuntimeError(f"Expected 22 nonzero runtime candidates, got {len(runtime)}")
    if len(validation) != 22:
        raise RuntimeError(f"Expected 22 keyword-validation rows, got {len(validation)}")

    dispositions = []
    findings = []

    for path_id in sorted(runtime):
        rr = runtime[path_id]
        kv = validation[path_id]
        cr = compiled[path_id]

        state = kv["validation_state"]
        disposition = None
        refined_spl = None
        refined_count = None
        validation_error = None

        if state == "SHARED_KEYWORD_DOMINATED":
            disposition = "REJECTED_BROAD_SHARED_KEYWORD_DOMINATED"

        elif state == "SINGLE_KEYWORD_DOMINATED_NEEDS_REVIEW":
            dominant = kv.get("dominant_keyword")
            refined_keywords = [
                x for x in cr.get("keywords", [])
                if x != dominant
            ]
            refined_spl, refined_count, validation_error = run_refined_query(
                rr["confirmed_sourcetypes"], refined_keywords
            )

            if validation_error is not None:
                disposition = "REVIEW_INCOMPLETE_EXECUTION_ERROR"
            elif refined_count == 0:
                disposition = "REJECTED_AFTER_DOMINANT_KEYWORD_REMOVAL"
            else:
                disposition = "VALIDATED_HUNT_FINDING_CANDIDATE"

        else:
            disposition = "REVIEW_INCOMPLETE_VALIDATION_STATE"

        record = {
            "hunt_finding_validation_version": "1.0",
            "path_id": path_id,
            "technique_id": rr["technique_id"],
            "technique_name": rr["technique_name"],
            "analytic_id": rr["analytic_id"],
            "runtime_match_count": rr["match_count"],
            "keyword_validation_state": state,
            "dominant_keyword": kv.get("dominant_keyword"),
            "dominant_keyword_count": kv.get("dominant_keyword_count"),
            "dominant_keyword_ratio": kv.get("dominant_keyword_ratio"),
            "disposition": disposition,
            "refined_spl": refined_spl,
            "refined_match_count": refined_count,
            "validation_error": validation_error,
            "attack_occurrence_claim": False,
        }
        dispositions.append(record)

        if disposition == "VALIDATED_HUNT_FINDING_CANDIDATE":
            findings.append({
                **record,
                "finding_status": "VALIDATED_RUNTIME_SIGNAL",
                "finding_interpretation": (
                    "A nonzero runtime signal survived dominant-keyword removal. "
                    "This is a hunt finding candidate, not proof of malicious activity."
                ),
            })

    with DISPOSITIONS.open("w", encoding="utf-8") as f:
        for r in dispositions:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    with FINDINGS.open("w", encoding="utf-8") as f:
        for r in findings:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    counts = Counter(r["disposition"] for r in dispositions)
    runtime_all = read_jsonl(RUNTIME_RESULTS)
    execution_counts = Counter(r["execution_status"] for r in runtime_all)

    summary = {
        "hunt_finding_validation_version": "1.0",
        "runtime_execution_population": len(runtime_all),
        "runtime_execution_status_counts": dict(sorted(execution_counts.items())),
        "raw_nonzero_candidates": len(runtime),
        "candidate_disposition_counts": dict(sorted(counts.items())),
        "validated_hunt_findings": len(findings),
        "validated_hunt_findings_are_attack_proof": False,
        "zero_runtime_results_are_conclusive_negatives": False,
        "runtime_visibility_limitation": (
            "Legacy BOTS v3 on current Splunk has incomplete raw-event visibility; "
            "zero runtime matches remain inconclusive."
        ),
    }
    SUMMARY.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    manifest = {
        "inputs": {str(p): sha256(p) for p in required},
        "outputs": {
            str(DISPOSITIONS): sha256(DISPOSITIONS),
            str(FINDINGS): sha256(FINDINGS),
            str(SUMMARY): sha256(SUMMARY),
        },
    }
    MANIFEST.write_text(
        json.dumps(manifest, indent=2),
        encoding="utf-8",
    )

    print("RAW_NONZERO_CANDIDATES", len(runtime))
    print("DISPOSITION_COUNTS", dict(sorted(counts.items())))
    print("VALIDATED_HUNT_FINDINGS", len(findings))
    print("DISPOSITIONS", DISPOSITIONS)
    print("FINDINGS", FINDINGS)
    print("SUMMARY", SUMMARY)
    print("MANIFEST", MANIFEST)

if __name__ == "__main__":
    main()
